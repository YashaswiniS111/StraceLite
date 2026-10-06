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
 * 9. Support syscall filtering
 *
 * Architecture:
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

/*
 * Print the six syscall argument registers used by
 * the x86-64 Linux syscall ABI.
 */
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
     *
     * This ensures every trace starts with
     * a clean statistics table.
     */
    stats_reset();


    /* ========================================================
     * CREATE CHILD
     * ======================================================== */

    pid_t child = fork();

    if (child == -1) {

        perror("fork");

        return -1;
    }


    /*
     * ========================================================
     * CHILD PROCESS
     * ========================================================
     */

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
         * Stop ourselves.
         *
         * This gives the parent a chance to configure
         * ptrace before execvp().
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
         * If execution reaches here, execvp() failed.
         */
        perror("execvp");

        _exit(127);
    }


    /*
     * ========================================================
     * PARENT / TRACER PROCESS
     * ========================================================
     */

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
     * Verify that the child really stopped.
     */
    if (WIFSTOPPED(status)) {

        printf("[Tracer] Child %d stopped by signal %d\n",
               child,
               WSTOPSIG(status));

    } else {

        fprintf(stderr,
                "[Tracer] Unexpected child state\n");

        return -1;
    }


    /* ========================================================
     * CONFIGURE PTRACE
     * ======================================================== */

    /*
     * PTRACE_O_TRACESYSGOOD causes syscall stops to appear as:
     *
     *     SIGTRAP | 0x80
     *
     * This allows us to distinguish syscall stops from
     * ordinary SIGTRAP signals.
     */
    if (ptrace(PTRACE_SETOPTIONS,
               child,
               NULL,
               PTRACE_O_TRACESYSGOOD) == -1) {

        perror("ptrace(PTRACE_SETOPTIONS)");

        return -1;
    }


    /*
     * Start the child.
     *
     * PTRACE_SYSCALL tells the kernel to stop the child
     * at the next syscall entry/exit.
     */
    if (ptrace(PTRACE_SYSCALL,
               child,
               NULL,
               NULL) == -1) {

        perror("ptrace(PTRACE_SYSCALL)");

        return -1;
    }


    /* ========================================================
     * TRACE STATE
     * ======================================================== */

    /*
     * 1 = next syscall stop is an entry
     * 0 = next syscall stop is an exit
     */
    int entering_syscall = 1;


    /*
     * Number of syscalls observed.
     */
    unsigned long syscall_count = 0;


    /*
     * Current syscall number.
     *
     * We save the syscall number at entry because the
     * return value is processed at the exit stop.
     */
    long current_syscall_number = -1;


    /* ========================================================
     * MAIN TRACE LOOP
     * ======================================================== */

    while (1) {

        /*
         * Wait until the tracee stops or exits.
         */
        if (waitpid(child,
                    &status,
                    0) == -1) {

            /*
             * Interrupted wait is not a fatal error.
             */
            if (errno == EINTR) {
                continue;
            }

            perror("waitpid");

            return -1;
        }


        /* ====================================================
         * NORMAL EXIT
         * ==================================================== */

        if (WIFEXITED(status)) {

            printf("[Tracer] Child exited with status %d\n",
                   WEXITSTATUS(status));

            break;
        }


        /* ====================================================
         * SIGNAL TERMINATION
         * ==================================================== */

        if (WIFSIGNALED(status)) {

            printf("[Tracer] Child terminated by signal %d\n",
                   WTERMSIG(status));

            break;
        }


        /* ====================================================
         * UNEXPECTED STATE
         * ==================================================== */

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
         * Get the signal responsible for the stop.
         */
        int signal_number = WSTOPSIG(status);


        /* ====================================================
         * EXECVE SIGTRAP
         * ==================================================== */

        /*
         * After execve(), Linux generates a plain SIGTRAP.
         *
         * This SIGTRAP is generated for the tracer and should
         * NOT be delivered back to the tracee.
         *
         * If we accidentally deliver it, programs such as
         * /bin/ls may terminate with signal 5.
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
         * NON-SYSCALL SIGNAL
         * ==================================================== */

        /*
         * With PTRACE_O_TRACESYSGOOD:
         *
         *     SIGTRAP | 0x80
         *
         * represents a syscall stop.
         *
         * Any other signal is a real signal received by
         * the tracee.
         */
        if (signal_number != (SIGTRAP | 0x80)) {

            int deliver_signal = signal_number;


            /*
             * Do not re-deliver the initial SIGSTOP.
             */
            if (signal_number == SIGSTOP) {

                deliver_signal = 0;
            }


            /*
             * Continue the tracee while optionally forwarding
             * the real signal.
             */
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
         * GET REGISTERS
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
             * x86-64 Linux stores the original syscall number
             * in orig_rax.
             */
            long syscall_number =
                (long)regs.orig_rax;


            /*
             * Save the syscall number so it can be used
             * during the exit stop.
             */
            current_syscall_number =
                syscall_number;


            /*
             * Convert syscall number to human-readable name.
             */
            const char *name =
                syscall_name(syscall_number);


            /*
             * Count every syscall.
             *
             * Filtering only affects display.
             * It does NOT affect statistics.
             */
            syscall_count++;


            /* =================================================
             * EXECVE PATH DECODING
             * ================================================= */

            /*
             * execve() syscall number on x86-64 Linux:
             *
             *     59
             *
             * Its first argument:
             *
             *     rdi = filename pointer
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


            /* =================================================
             * FILTERED DISPLAY
             * ================================================= */

            /*
             * Display only if the syscall passes the filter.
             *
             * If no filter is configured, filter_allows()
             * returns 1 for every syscall.
             */
            if (filter_allows(name)) {

                printf("[Syscall Entry] #%lu  %ld (%s)\n",
                       syscall_count - 1,
                       syscall_number,
                       name);


                print_syscall_arguments(&regs);
            }


            /*
             * The next syscall stop will be the exit.
             */
            entering_syscall = 0;
        }


        /* ====================================================
         * SYSCALL EXIT
         * ==================================================== */

        else {

            /*
             * Linux stores the syscall return value in rax.
             */
            long return_value =
                (long)regs.rax;


            /*
             * Get the syscall name using the number saved
             * during syscall entry.
             */
            const char *name =
                syscall_name(current_syscall_number);


            /* =================================================
             * RECORD STATISTICS
             * ================================================= */

            /*
             * Record every syscall, including filtered ones.
             */
            stats_record(current_syscall_number,
                         return_value);


            /* =================================================
             * DISPLAY RETURN VALUE
             * ================================================= */

            if (filter_allows(name)) {

                printf("[Syscall Exit ] #%lu  %ld (%s)",
                       syscall_count - 1,
                       current_syscall_number,
                       name);


                printf("     return=%ld",
                       return_value);


                /*
                 * Linux system calls normally indicate errors
                 * using negative errno values in the range:
                 *
                 *     -1 to -4095
                 */
                if (return_value < 0 &&
                    return_value >= -4095) {

                    printf(" (errno=%ld)",
                           -return_value);
                }


                printf("\n");
            }


            /*
             * The next syscall stop will be an entry.
             */
            entering_syscall = 1;
        }


        /* ====================================================
         * CONTINUE TO NEXT SYSCALL
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

    printf("[Tracer] Total syscall calls observed: %lu\n\n",
           syscall_count);


    /*
     * Print the complete syscall summary.
     */
    stats_print();


    return 0;
}
