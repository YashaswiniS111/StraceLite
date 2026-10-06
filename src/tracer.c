
#include "tracer.h"
#include "syscall.h"

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
static int get_registers(pid_t child, struct user_regs_struct *regs)
{
    if (ptrace(PTRACE_GETREGS, child, NULL, regs) == -1) {
        perror("ptrace(PTRACE_GETREGS)");
        return -1;
    }

    return 0;
}

/*
 * Print syscall argument registers.
 *
 * These registers will later be used to decode strings,
 * buffers, file descriptors, and other syscall arguments.
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
        fprintf(stderr, "[Tracer] Invalid target command.\n");
        return -1;
    }

    /*
     * Create the tracee.
     */
    pid_t child = fork();

    if (child == -1) {
        perror("fork");
        return -1;
    }

    /*
     * ============================================================
     * CHILD PROCESS
     * ============================================================
     */
    if (child == 0) {

        /*
         * Tell the kernel that this child wants to be traced
         * by its parent.
         */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            perror("ptrace(PTRACE_TRACEME)");
            _exit(EXIT_FAILURE);
        }

        /*
         * Stop before executing the target.
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
         * execvp() only returns when it fails.
         */
        perror("execvp");
        _exit(127);
    }

    /*
     * ============================================================
     * PARENT / TRACER PROCESS
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
     * PTRACE_O_TRACESYSGOOD changes syscall-stop SIGTRAP into:
     *
     *     SIGTRAP | 0x80
     *
     * This allows us to distinguish syscall stops from normal
     * SIGTRAP events.
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
     * 1 = syscall entry
     * 0 = syscall exit
     */
    int entering = 1;

    /*
     * ============================================================
     * TRACE LOOP
     * ============================================================
     */
    while (1) {

        /*
         * Continue until the next syscall boundary.
         */
        if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) == -1) {
            perror("ptrace(PTRACE_SYSCALL)");
            return -1;
        }

        /*
         * Wait for the tracee to stop.
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

                long syscall_number = (long)regs.orig_rax;

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

                long return_value = (long)regs.rax;

                printf("[Syscall Exit ] #%lu  return=%ld",
                       syscall_count,
                       return_value);

                /*
                 * Linux syscall errors are negative errno values.
                 *
                 * Example:
                 *
                 *   -2 -> ENOENT
                 *   -13 -> EACCES
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
             * Toggle entry <-> exit.
             */
            entering = !entering;

            continue;
        }

        /*
         * ========================================================
         * ORDINARY SIGTRAP
         * ========================================================
         *
         * This can happen around execve().
         *
         * IMPORTANT:
         *
         * We must NOT deliver this SIGTRAP back to the tracee.
         * It is a debugger/tracing event, not a signal that the
         * target program should receive.
         */
        if (stop_signal == SIGTRAP) {

            continue;
        }

        /*
         * ========================================================
         * OTHER SIGNAL
         * ========================================================
         *
         * For signals such as SIGINT, SIGTERM, etc., we preserve
         * the signal and deliver it to the tracee.
         *
         * More sophisticated signal handling will be introduced
         * in the later milestones.
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
         * If delivering the signal caused the process to exit,
         * handle it immediately.
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

