#include "tracer.h"
#include "syscall.h"
#include "memory.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * Read the complete register state of the tracee.
 *
 * x86-64 Linux syscall ABI:
 *
 *   orig_rax -> syscall number
 *   rdi      -> argument 1
 *   rsi      -> argument 2
 *   rdx      -> argument 3
 *   r10      -> argument 4
 *   r8       -> argument 5
 *   r9       -> argument 6
 *
 * At syscall exit:
 *
 *   rax      -> return value
 */
static int get_registers(pid_t child,
                         struct user_regs_struct *regs)
{
    if (ptrace(PTRACE_GETREGS,
               child,
               NULL,
               regs) == -1) {

        perror("ptrace(PTRACE_GETREGS)");
        return -1;
    }

    return 0;
}

/*
 * Print the six x86-64 syscall argument registers.
 */
static void print_syscall_registers(
    const struct user_regs_struct *regs)
{
    printf("    args: "
           "rdi=0x%llx, "
           "rsi=0x%llx, "
           "rdx=0x%llx, "
           "r10=0x%llx, "
           "r8=0x%llx, "
           "r9=0x%llx\n",
           (unsigned long long)regs->rdi,
           (unsigned long long)regs->rsi,
           (unsigned long long)regs->rdx,
           (unsigned long long)regs->r10,
           (unsigned long long)regs->r8,
           (unsigned long long)regs->r9);
}

/*
 * Launch and trace a target program.
 */
int tracer_launch(char *const argv[])
{
    if (argv == NULL || argv[0] == NULL) {
        fprintf(stderr,
                "[Tracer] Invalid target command.\n");
        return -1;
    }

    /*
     * ============================================================
     * CHILD PROCESS
     * ============================================================
     */
    pid_t child = fork();

    if (child == -1) {
        perror("fork");
        return -1;
    }

    if (child == 0) {

        /*
         * Request tracing by the parent.
         */
        if (ptrace(PTRACE_TRACEME,
                   0,
                   NULL,
                   NULL) == -1) {

            perror("ptrace(PTRACE_TRACEME)");
            _exit(EXIT_FAILURE);
        }

        /*
         * Stop before exec().
         *
         * This gives the parent a chance to configure ptrace
         * options before the target starts running.
         */
        if (raise(SIGSTOP) == -1) {
            perror("raise(SIGSTOP)");
            _exit(EXIT_FAILURE);
        }

        /*
         * Replace the child with the target program.
         */
        execvp(argv[0], argv);

        /*
         * execvp() only returns if execution failed.
         */
        perror("execvp");
        _exit(127);
    }

    /*
     * ============================================================
     * PARENT / TRACER
     * ============================================================
     */

    int status = 0;

    /*
     * Wait for the child's initial SIGSTOP.
     */
    if (waitpid(child, &status, 0) == -1) {
        perror("waitpid");
        return -1;
    }

    if (WIFEXITED(status)) {
        fprintf(stderr,
                "[Tracer] Child exited before tracing began "
                "with status %d\n",
                WEXITSTATUS(status));
        return WEXITSTATUS(status);
    }

    if (WIFSIGNALED(status)) {
        fprintf(stderr,
                "[Tracer] Child terminated by signal %d\n",
                WTERMSIG(status));
        return -1;
    }

    if (!WIFSTOPPED(status)) {
        fprintf(stderr,
                "[Tracer] Unexpected initial child state.\n");
        return -1;
    }

    printf("[Tracer] Child %d stopped by signal %d\n",
           child,
           WSTOPSIG(status));

    /*
     * PTRACE_O_TRACESYSGOOD makes syscall stops distinguishable
     * from normal SIGTRAP events.
     *
     * Syscall stop:
     *
     *     SIGTRAP | 0x80
     */
    if (ptrace(PTRACE_SETOPTIONS,
               child,
               NULL,
               (void *)(long)PTRACE_O_TRACESYSGOOD) == -1) {

        perror("ptrace(PTRACE_SETOPTIONS)");
        return -1;
    }

    unsigned long syscall_count = 0;

    /*
     * 1 -> next stop is syscall entry
     * 0 -> next stop is syscall exit
     */
    int entering = 1;

    /*
     * ============================================================
     * MAIN TRACE LOOP
     * ============================================================
     */
    while (1) {

        /*
         * Resume the tracee until the next syscall boundary.
         */
        if (ptrace(PTRACE_SYSCALL,
                   child,
                   NULL,
                   NULL) == -1) {

            perror("ptrace(PTRACE_SYSCALL)");
            return -1;
        }

        /*
         * Wait for the next tracee event.
         */
        if (waitpid(child, &status, 0) == -1) {
            perror("waitpid");
            return -1;
        }

        /*
         * --------------------------------------------------------
         * NORMAL EXIT
         * --------------------------------------------------------
         */
        if (WIFEXITED(status)) {

            printf("[Tracer] Child exited with status %d\n",
                   WEXITSTATUS(status));

            break;
        }

        /*
         * --------------------------------------------------------
         * SIGNAL TERMINATION
         * --------------------------------------------------------
         */
        if (WIFSIGNALED(status)) {

            printf("[Tracer] Child terminated by signal %d\n",
                   WTERMSIG(status));

            break;
        }

        if (!WIFSTOPPED(status)) {

            fprintf(stderr,
                    "[Tracer] Unexpected child state.\n");

            break;
        }

        int stop_signal = WSTOPSIG(status);

        /*
         * ========================================================
         * SYSCALL STOP
         * ========================================================
         */
        if (stop_signal == (SIGTRAP | 0x80)) {

            struct user_regs_struct regs;

            if (get_registers(child, &regs) == -1) {
                return -1;
            }

            /*
             * ----------------------------------------------------
             * SYSCALL ENTRY
             * ----------------------------------------------------
             */
            if (entering) {

                long syscall_number =
                    (long)regs.orig_rax;

                /*
                 * Local buffer used when decoding pointer
                 * arguments from the tracee.
                 */
                char decoded_string[256] = {0};

                /*
                 * x86-64 Linux:
                 *
                 * execve = syscall number 59
                 *
                 * rdi contains the pointer to the pathname.
                 *
                 * We use PTRACE_PEEKDATA through
                 * tracee_read_string() to safely copy that
                 * pathname from the tracee's address space.
                 */
                if (syscall_number == 59) {

                    if (tracee_read_string(
                            child,
                            regs.rdi,
                            decoded_string,
                            sizeof(decoded_string)) == 0) {

                        printf("[Decoded] execve path: \"%s\"\n",
                               decoded_string);
                    }
                    else {

                        printf("[Decoded] execve path: "
                               "<unreadable at 0x%llx>\n",
                               (unsigned long long)regs.rdi);
                    }
                }

                printf("[Syscall Entry] #%lu  %ld (%s)\n",
                       syscall_count,
                       syscall_number,
                       syscall_name(syscall_number));

                print_syscall_registers(&regs);
            }

            /*
             * ----------------------------------------------------
             * SYSCALL EXIT
             * ----------------------------------------------------
             */
            else {

                long return_value =
                    (long)regs.rax;

                printf("[Syscall Exit ] #%lu  return=%ld",
                       syscall_count,
                       return_value);

                /*
                 * Linux syscall errors are represented as
                 * negative errno values.
                 *
                 * Example:
                 *
                 *     -2  -> ENOENT
                 *     -13 -> EACCES
                 */
                if (return_value < 0 &&
                    return_value >= -4095) {

                    printf(" (errno=%ld)",
                           -return_value);
                }

                printf("\n");

                syscall_count++;
            }

            /*
             * Toggle between syscall entry and syscall exit.
             */
            entering = !entering;

            continue;
        }

        /*
         * ========================================================
         * ORDINARY SIGTRAP
         * ========================================================
         *
         * This commonly occurs around exec().
         *
         * It is a tracing/debugging event and should NOT be
         * delivered back to the tracee.
         */
        if (stop_signal == SIGTRAP) {
            continue;
        }

        /*
         * ========================================================
         * OTHER SIGNAL
         * ========================================================
         *
         * Preserve signals such as SIGINT or SIGTERM.
         */
        printf("[Tracer] Child stopped by signal %d\n",
               stop_signal);

        if (ptrace(PTRACE_SYSCALL,
                   child,
                   NULL,
                   (void *)(long)stop_signal) == -1) {

            perror("ptrace(PTRACE_SYSCALL)");
            return -1;
        }

        if (waitpid(child, &status, 0) == -1) {
            perror("waitpid");
            return -1;
        }

        /*
         * Check whether signal delivery terminated the tracee.
         */
        if (WIFEXITED(status)) {

            printf("[Tracer] Child exited with status %d\n",
                   WEXITSTATUS(status));

            break;
        }

        if (WIFSIGNALED(status)) {

            printf("[Tracer] Child terminated by signal %d\n",
                   WTERMSIG(status));

            break;
        }
    }

    printf("[Tracer] Total syscall calls observed: %lu\n",
           syscall_count);

    return 0;
}
