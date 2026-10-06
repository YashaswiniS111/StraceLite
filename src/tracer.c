#define _GNU_SOURCE

#include "tracer.h"
#include "syscall.h"
#include "memory.h"
#include "stats.h"
#include "filter.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

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
         * Stop ourselves so the parent can configure ptrace.
         */
        if (raise(SIGSTOP) == -1) {
            perror("raise(SIGSTOP)");
            _exit(1);
        }

        /*
         * Replace child with target program.
         */
        execvp(argv[0], argv);

        /*
         * Only reached when execvp fails.
         */
        perror("execvp");
        _exit(127);
    }

    /*
     * Parent/tracer process.
     */
    int status;

    if (waitpid(child, &status, 0) == -1) {
        perror("waitpid");
        return -1;
    }

    if (WIFSTOPPED(status)) {

        printf("[Tracer] Child %d stopped by signal %d\n",
               child,
               WSTOPSIG(status));

    } else {

        fprintf(stderr,
                "[Tracer] Unexpected child state\n");

        return -1;
    }

    /*
     * Ask ptrace to mark syscall stops as:
     *
     *     SIGTRAP | 0x80
     *
     * This allows us to distinguish syscall stops from
     * ordinary SIGTRAP events.
     */
    if (ptrace(PTRACE_SETOPTIONS,
               child,
               NULL,
               PTRACE_O_TRACESYSGOOD) == -1) {

        perror("ptrace(PTRACE_SETOPTIONS)");
        return -1;
    }

    /*
     * Continue until the first syscall stop.
     */
    if (ptrace(PTRACE_SYSCALL,
               child,
               NULL,
               NULL) == -1) {

        perror("ptrace(PTRACE_SYSCALL)");
        return -1;
    }

    /*
     * 1 = syscall entry
     * 0 = syscall exit
     */
    int entering_syscall = 1;

    /*
     * Number of syscalls observed.
     */
    unsigned long syscall_count = 0;

    /*
     * Syscall currently being traced.
     */
    long current_syscall_number = -1;

    /*
     * Main tracing loop.
     */
    while (1) {

        if (waitpid(child, &status, 0) == -1) {

            if (errno == EINTR) {
                continue;
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
         * Child was terminated by a signal.
         */
        if (WIFSIGNALED(status)) {

            printf("[Tracer] Child terminated by signal %d\n",
                   WTERMSIG(status));

            break;
        }

        /*
         * We only process stopped children.
         */
        if (!WIFSTOPPED(status)) {

            if (ptrace(PTRACE_SYSCALL,
                       child,
                       NULL,
                       NULL) == -1) {

                perror("ptrace(PTRACE_SYSCALL)");
                return -1;
            }

            continue;
        }

        int signal_number = WSTOPSIG(status);

        /*
         * IMPORTANT:
         *
         * After execve(), Linux generates a plain SIGTRAP.
         *
         * This SIGTRAP belongs to ptrace and must NOT be
         * delivered to the tracee.
         *
         * If we deliver it, /bin/ls terminates with:
         *
         *     signal 5
         */
        if (signal_number == SIGTRAP) {

            if (ptrace(PTRACE_SYSCALL,
                       child,
                       NULL,
                       NULL) == -1) {

                perror("ptrace(PTRACE_SYSCALL)");
                return -1;
            }

            continue;
        }

        /*
         * With PTRACE_O_TRACESYSGOOD:
         *
         *     SIGTRAP | 0x80
         *
         * means syscall stop.
         *
         * Any other signal is a real signal received
         * by the tracee.
         */
        if (signal_number != (SIGTRAP | 0x80)) {

            /*
             * Do not re-deliver SIGSTOP.
             */
            int deliver_signal = signal_number;

            if (signal_number == SIGSTOP) {
                deliver_signal = 0;
            }

            if (ptrace(PTRACE_SYSCALL,
                       child,
                       NULL,
                       (void *)(long)deliver_signal) == -1) {

                perror("ptrace(PTRACE_SYSCALL)");
                return -1;
            }

            continue;
        }

        /*
         * Get CPU registers.
         */
        struct user_regs_struct regs;

        if (ptrace(PTRACE_GETREGS,
                   child,
                   NULL,
                   &regs) == -1) {

            perror("ptrace(PTRACE_GETREGS)");
            return -1;
        }

        /* =====================================================
         * SYSCALL ENTRY
         * ===================================================== */

        if (entering_syscall) {

            /*
             * x86-64 Linux:
             *
             * orig_rax = syscall number
             */
            long syscall_number = (long)regs.orig_rax;

            current_syscall_number = syscall_number;

            const char *name =
                syscall_name(syscall_number);

            /*
             * Count every syscall, even filtered ones.
             *
             * We record the final return value at syscall exit.
             */
            syscall_count++;

            /*
             * Special handling for execve.
             *
             * execve:
             *
             *   rdi = filename
             */
            if (syscall_number == 59) {

                char path[4096];

                if (tracee_read_string(child,
                                        (unsigned long)regs.rdi,
                                        path,
                                        sizeof(path)) == 0) {

                    printf("[Decoded] execve path: \"%s\"\n",
                           path);
                }
            }

            /*
             * Display syscall only if it passes the filter.
             */
            if (filter_allows(name)) {

                printf("[Syscall Entry] #%lu  %ld (%s)\n",
                       syscall_count - 1,
                       syscall_number,
                       name);

                print_syscall_arguments(&regs);
            }

            /*
             * Next syscall stop will be exit.
             */
            entering_syscall = 0;
        }

        /* =====================================================
         * SYSCALL EXIT
         * ===================================================== */

        else {

            /*
             * Return value is stored in RAX.
             */
            long return_value = (long)regs.rax;

            const char *name =
                syscall_name(current_syscall_number);

            /*
             * Record statistics for every syscall.
             */
            stats_record(current_syscall_number,
                         return_value);

            /*
             * Display exit only if syscall passes filter.
             */
            if (filter_allows(name)) {

                printf("[Syscall Exit ] #%lu  %ld (%s)",
                       syscall_count - 1,
                       current_syscall_number,
                       name);

                printf("     return=%ld",
                       return_value);

                /*
                 * Linux syscall errors are returned as
                 * negative errno values.
                 */
                if (return_value < 0 &&
                    return_value >= -4095) {

                    printf(" (errno=%ld)",
                           -return_value);
                }

                printf("\n");
            }

            /*
             * Next syscall stop will be entry.
             */
            entering_syscall = 1;
        }

        /*
         * Continue the tracee to the next syscall stop.
         */
        if (ptrace(PTRACE_SYSCALL,
                   child,
                   NULL,
                   NULL) == -1) {

            perror("ptrace(PTRACE_SYSCALL)");
            return -1;
        }
    }

    /*
     * Final trace statistics.
     */
    printf("[Tracer] Total syscall calls observed: %lu\n\n",
           syscall_count);

    stats_print();

    return 0;
}

