#define _GNU_SOURCE

#include "tracer.h"
#include "syscall.h"
#include "memory.h"
#include "stats.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * StraceLite tracer
 *
 * Milestone 5:
 *   - Launch tracee
 *   - Trace syscall entry/exit
 *   - Decode syscall numbers
 *   - Display registers
 *   - Display return values
 *   - Decode execve path from tracee memory
 *   - Collect syscall statistics
 */

/*
 * Print the six syscall argument registers used by
 * the x86-64 Linux syscall ABI.
 */
static void print_syscall_arguments(struct user_regs_struct *regs)
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
 * Print the return value of a syscall.
 *
 * Linux x86-64 returns the syscall result in RAX.
 * Negative values represent errors.
 */


/*
 * Start and trace a target process.
 */
int tracer_launch(char *const argv[])
{
    if (argv == NULL || argv[0] == NULL) {
        fprintf(stderr, "[Tracer] Invalid target arguments\n");
        return -1;
    }

    /*
     * Reset statistics before starting a new trace.
     */
    stats_reset();

    pid_t child = fork();

    if (child == -1) {
        perror("fork");
        return -1;
    }

    /*
     * Child process.
     */
    if (child == 0) {

        /*
         * Ask the parent to trace this process.
         */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            perror("ptrace(PTRACE_TRACEME)");
            _exit(1);
        }

        /*
         * Stop ourselves so the parent can take control
         * before execve().
         */
        if (raise(SIGSTOP) == -1) {
            perror("raise(SIGSTOP)");
            _exit(1);
        }

        /*
         * Replace this process with the target program.
         */
        execvp(argv[0], argv);

        /*
         * If execvp returns, it failed.
         */
        perror("execvp");
        _exit(127);
    }

    /*
     * Parent/tracer process.
     */
    printf("[StraceLite] Launching target: %s\n", argv[0]);

    int status = 0;

    /*
     * Wait for the child's initial SIGSTOP.
     */
    if (waitpid(child, &status, 0) == -1) {
        perror("waitpid");
        return -1;
    }

    if (WIFEXITED(status)) {
        printf("[Tracer] Child exited with status %d\n",
               WEXITSTATUS(status));
        return 0;
    }

    if (WIFSIGNALED(status)) {
        printf("[Tracer] Child terminated by signal %d\n",
               WTERMSIG(status));
        return 0;
    }

    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "[Tracer] Unexpected child state\n");
        return -1;
    }

    printf("[Tracer] Child %d stopped by signal %d\n",
           child,
           WSTOPSIG(status));

    /*
     * Tell ptrace to stop the child at every syscall entry
     * and syscall exit.
     */
    if (ptrace(PTRACE_SETOPTIONS,
               child,
               NULL,
               PTRACE_O_TRACESYSGOOD) == -1) {

        perror("ptrace(PTRACE_SETOPTIONS)");
        return -1;
    }

    /*
     * Start the first syscall-stop cycle.
     */
    if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) == -1) {
        perror("ptrace(PTRACE_SYSCALL)");
        return -1;
    }

    unsigned long syscall_count = 0;

    /*
     * Alternates between:
     *
     *   0 = syscall entry
     *   1 = syscall exit
     */
    int entering_syscall = 1;

    /*
     * Current syscall number.
     *
     * We save it during entry because the syscall return
     * value is only available during the exit stop.
     */
    long current_syscall = -1;

    while (1) {

        if (waitpid(child, &status, 0) == -1) {

            /*
             * The child can disappear after an exec failure or
             * other terminal condition.
             */
            if (errno == ECHILD) {
                break;
            }

            perror("waitpid");
            return -1;
        }

        /*
         * Child exited normally.
         */
        if (WIFEXITED(status)) {

            printf("[Tracer] Child exited with status %d\n",
                   WEXITSTATUS(status));

            break;
        }

        /*
         * Child was killed by a signal.
         */
        if (WIFSIGNALED(status)) {

            printf("[Tracer] Child terminated by signal %d\n",
                   WTERMSIG(status));

            break;
        }

        /*
         * We only want stopped states here.
         */
        if (!WIFSTOPPED(status)) {
            continue;
        }

        int signal_number = WSTOPSIG(status);

        /*
         * Syscall stops generated by
         * PTRACE_O_TRACESYSGOOD have bit 7 set.
         *
         * SIGTRAP | 0x80 = syscall-stop.
         */
        if (signal_number == (SIGTRAP | 0x80)) {

            struct user_regs_struct regs;

            if (ptrace(PTRACE_GETREGS,
                       child,
                       NULL,
                       &regs) == -1) {

                perror("ptrace(PTRACE_GETREGS)");
                return -1;
            }

            /*
             * SYSCALL number is stored in ORIG_RAX.
             */
            long syscall_number =
                (long)regs.orig_rax;

            /*
             * Syscall ENTRY.
             */
            if (entering_syscall) {

                current_syscall = syscall_number;

                const char *name =
                    syscall_name(syscall_number);

                printf("[Syscall Entry] #%lu  %ld (%s)\n",
                       syscall_count,
                       syscall_number,
                       name);

                /*
                 * Special decoding for execve.
                 *
                 * On x86-64:
                 *
                 *   rdi = pathname
                 *   rsi = argv
                 *   rdx = envp
                 */
                if (syscall_number == 59) {

                    char path[512];

                    if (tracee_read_string(
                            child,
                            (unsigned long)regs.rdi,
                            path,
                            sizeof(path)) == 0) {

                        printf("[Decoded] execve path: \"%s\"\n",
                               path);
                    }
                }

                print_syscall_arguments(&regs);

                entering_syscall = 0;

            } else {

                /*
                 * Syscall EXIT.
                 *
                 * RAX contains the return value.
                 */
                long long return_value =
                    (long long)regs.rax;

                /*
                 * Record statistics.
                 */
                stats_record(current_syscall,
                             (long)return_value);

                printf("[Syscall Exit ] #%lu  ",
                       syscall_count);

                if (return_value < 0) {

                    long error_number =
                        (long)(-return_value);

                    printf("return=%lld (errno=%ld)\n",
                           return_value,
                           error_number);

                } else {

                    printf("return=%lld\n",
                           return_value);
                }

                /*
                 * One complete syscall has now been observed.
                 */
                syscall_count++;

                entering_syscall = 1;
            }

        } else {

            /*
             * This is a normal signal stop rather than a
             * syscall boundary.
             */
            printf("[Tracer] Child stopped by signal %d\n",
                   signal_number);
        }

        /*
         * Continue to the next syscall boundary.
         */
        if (ptrace(PTRACE_SYSCALL,
                   child,
                   NULL,
                   NULL) == -1) {

            /*
             * If the child exited between waitpid() and
             * ptrace(), don't turn normal termination into
             * a confusing error.
             */
            if (errno == ESRCH) {
                break;
            }

            perror("ptrace(PTRACE_SYSCALL)");
            return -1;
        }
    }

    /*
     * Final count.
     */
    printf("[Tracer] Total syscall calls observed: %lu\n",
           syscall_count);

    /*
     * Print Milestone 5 statistics.
     */
    stats_print();

    return 0;
}
