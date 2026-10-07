
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
 * ============================================================
 * StraceLite - System Call Tracer
 * ============================================================
 *
 * Features:
 *
 * 1. Launch a target program
 * 2. Trace system calls using ptrace()
 * 3. Decode syscall numbers into names
 * 4. Display syscall arguments
 * 5. Display syscall return values
 * 6. Detect Linux syscall errors
 * 7. Decode execve() path from tracee memory
 * 8. Collect syscall statistics
 * 9. Support syscall-name filtering
 * 10. Support syscall-category filtering
 *
 * Architecture:
 *
 *     Linux x86-64
 *
 * Syscall argument registers:
 *
 *     rdi
 *     rsi
 *     rdx
 *     r10
 *     r8
 *     r9
 *
 * Syscall number:
 *
 *     orig_rax
 *
 * Return value:
 *
 *     rax
 */


/* ============================================================
 * Print syscall arguments
 * ============================================================ */

static void print_syscall_arguments(
    struct user_regs_struct *regs)
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


/* ============================================================
 * Start and trace target process
 * ============================================================ */

int tracer_launch(char *const argv[])
{
    /*
     * Validate target arguments.
     */
    if (argv == NULL || argv[0] == NULL) {

        fprintf(stderr,
                "[Tracer] Invalid target arguments\n");

        return -1;
    }


    /*
     * Reset syscall statistics.
     */
    stats_reset();


    /* ========================================================
     * CREATE CHILD PROCESS
     * ======================================================== */

    pid_t child = fork();

    if (child == -1) {

        perror("fork");

        return -1;
    }


    /* ========================================================
     * CHILD PROCESS
     * ======================================================== */

    if (child == 0) {

        /*
         * Tell the kernel that the parent will trace us.
         */
        if (ptrace(PTRACE_TRACEME,
                   0,
                   NULL,
                   NULL) == -1) {

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
         * Replace this process with the target program.
         */
        execvp(argv[0], argv);


        /*
         * Only reached if execvp() fails.
         */
        perror("execvp");

        _exit(127);
    }


    /* ========================================================
     * PARENT / TRACER PROCESS
     * ======================================================== */

    int status;


    /*
     * Wait for the child's initial SIGSTOP.
     */
    if (waitpid(child,
                &status,
                0) == -1) {

        perror("waitpid");

        return -1;
    }


    /*
     * Verify that the child actually stopped.
     */
    if (!WIFSTOPPED(status)) {

        fprintf(stderr,
                "[Tracer] Unexpected child state\n");

        return -1;
    }


    printf("[Tracer] Child %d stopped by signal %d\n",
           child,
           WSTOPSIG(status));


    /*
     * Configure ptrace.
     *
     * PTRACE_O_TRACESYSGOOD causes syscall stops
     * to be reported as:
     *
     *     SIGTRAP | 0x80
     */
    if (ptrace(PTRACE_SETOPTIONS,
               child,
               NULL,
               PTRACE_O_TRACESYSGOOD) == -1) {

        perror("ptrace(PTRACE_SETOPTIONS)");

        return -1;
    }


    /*
     * Continue child until first syscall stop.
     */
    if (ptrace(PTRACE_SYSCALL,
               child,
               NULL,
               NULL) == -1) {

        perror("ptrace(PTRACE_SYSCALL)");

        return -1;
    }


    /*
     * Syscall stop state:
     *
     *     1 = syscall entry
     *     0 = syscall exit
     */
    int entering_syscall = 1;


    /*
     * Number of syscalls observed.
     */
    unsigned long syscall_count = 0;


    /*
     * Syscall number belonging to the current
     * entry/exit pair.
     */
    long current_syscall_number = -1;


    /* ========================================================
     * MAIN TRACING LOOP
     * ======================================================== */

    while (1) {

        /*
         * Wait for the next child event.
         */
        if (waitpid(child,
                    &status,
                    0) == -1) {

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
         * Ignore unexpected non-stopped states.
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


        /*
         * Get the signal that caused the stop.
         */
        int signal_number = WSTOPSIG(status);


        /* ====================================================
         * HANDLE PTRACE SIGTRAP
         * ==================================================== */

        /*
         * After execve(), Linux generates a plain SIGTRAP.
         *
         * This belongs to ptrace and should not be delivered
         * to the tracee.
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


        /* ====================================================
         * HANDLE REAL SIGNALS
         * ==================================================== */

        /*
         * A syscall stop is:
         *
         *     SIGTRAP | 0x80
         *
         * Any other signal is a real signal delivered to
         * the tracee.
         */
        if (signal_number != (SIGTRAP | 0x80)) {

            int deliver_signal = signal_number;


            /*
             * Do not re-deliver SIGSTOP.
             */
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


        /* ====================================================
         * GET TRACEe REGISTERS
         * ==================================================== */

        struct user_regs_struct regs;

        if (ptrace(PTRACE_GETREGS,
                   child,
                   NULL,
                   &regs) == -1) {

            perror("ptrace(PTRACE_GETREGS)");

            return -1;
        }


        /* ====================================================
         * SYSCALL ENTRY
         * ==================================================== */

        if (entering_syscall) {

            /*
             * On x86-64 Linux:
             *
             *     orig_rax = syscall number
             */
            long syscall_number =
                (long)regs.orig_rax;


            current_syscall_number =
                syscall_number;


            /*
             * Convert syscall number into name.
             */
            const char *name =
                syscall_name(syscall_number);


            /*
             * Count every syscall, even when filtered.
             */
            syscall_count++;


            /*
             * =================================================
             * EXECVE MEMORY DECODING
             * =================================================
             *
             * execve() has:
             *
             *     rdi = filename
             */
            if (syscall_number == 59) {

                char path[4096];

                if (tracee_read_string(
                        child,
                        (unsigned long)regs.rdi,
                        path,
                        sizeof(path)) == 0) {

                    printf("[Decoded] execve path: \"%s\"\n",
                           path);
                }
            }


            /*
             * =================================================
             * FILTERING
             * =================================================
             *
             * A syscall is displayed only when:
             *
             * 1. It passes the syscall-name filter
             * 2. It passes the category filter
             *
             * If either filter is disabled, that filter
             * automatically allows the syscall.
             */
            if (filter_allows(name) &&
                filter_category_allows(syscall_number)) {

                printf("[Syscall Entry] #%lu  %ld (%s)\n",
                       syscall_count - 1,
                       syscall_number,
                       name);

                print_syscall_arguments(&regs);
            }


            /*
             * Next syscall stop will be an exit stop.
             */
            entering_syscall = 0;
        }


        /* ====================================================
         * SYSCALL EXIT
         * ==================================================== */

        else {

            /*
             * Syscall return value is stored in RAX.
             */
            long return_value =
                (long)regs.rax;


            /*
             * Get syscall name.
             */
            const char *name =
                syscall_name(current_syscall_number);


            /*
             * Record statistics for every syscall.
             *
             * Statistics are NOT affected by filtering.
             */
            stats_record(current_syscall_number,
                         return_value);


            /*
             * Display exit only if both filters allow it.
             */
            if (filter_allows(name) &&
                filter_category_allows(
                    current_syscall_number)) {

                printf("[Syscall Exit ] #%lu  %ld (%s)",
                       syscall_count - 1,
                       current_syscall_number,
                       name);


                printf("     return=%ld",
                       return_value);


                /*
                 * Linux syscalls normally return negative
                 * errno values when an error occurs.
                 */
                if (return_value < 0 &&
                    return_value >= -4095) {

                    printf(" (errno=%ld)",
                           -return_value);
                }


                printf("\n");
            }


            /*
             * Next syscall stop will be an entry stop.
             */
            entering_syscall = 1;
        }


        /* ====================================================
         * CONTINUE TRACE
         * ==================================================== */

        if (ptrace(PTRACE_SYSCALL,
                   child,
                   NULL,
                   NULL) == -1) {

            perror("ptrace(PTRACE_SYSCALL)");

            return -1;
        }
    }


    /* ========================================================
     * FINAL STATISTICS
     * ======================================================== */

    printf("\n[Tracer] Total syscall calls observed: %lu\n\n",
           syscall_count);


    stats_print();


    return 0;
}
