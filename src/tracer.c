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
 * StraceLite - System Call Tracer
 *
 * Features implemented:
 *   - Launch tracee
 *   - ptrace syscall tracing
 *   - Decode syscall numbers
 *   - Decode syscall names
 *   - Display syscall registers
 *   - Display return values
 *   - Detect syscall errors
 *   - Decode execve path from tracee memory
 *   - Collect syscall statistics
 *
 * Milestone 6:
 *   - Statistics integration
 *   - Filtering infrastructure can be added without
 *     changing the core ptrace loop
 */


/* ============================================================
 * Print syscall arguments
 * ============================================================ */

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


/* ============================================================
 * Print syscall return value
 * ============================================================ */

static void print_syscall_return(long long return_value)
{
    if (return_value < 0 && return_value >= -4095) {

        long error_number = -return_value;

        printf("    return=%lld (errno=%ld)\n",
               return_value,
               error_number);

    } else {

        printf("    return=%lld\n",
               return_value);
    }
}


/* ============================================================
 * Start and trace target process
 * ============================================================ */

int tracer_launch(char *const argv[])
{
    if (argv == NULL || argv[0] == NULL) {

        fprintf(stderr,
                "[Tracer] Invalid target arguments\n");

        return -1;
    }


    /*
     * Reset statistics before every new trace.
     */
    stats_reset();


    /*
     * Create child process.
     */
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
         * Ask parent to trace this process.
         */
        if (ptrace(PTRACE_TRACEME,
                   0,
                   NULL,
                   NULL) == -1) {

            perror("ptrace(PTRACE_TRACEME)");

            _exit(1);
        }


        /*
         * Stop ourselves so the parent can configure tracing.
         */
        raise(SIGSTOP);


        /*
         * Replace child with target program.
         */
        execvp(argv[0], argv);


        /*
         * Only reached if execvp failed.
         */
        perror("execvp");

        _exit(127);
    }


    /* ========================================================
     * PARENT / TRACER PROCESS
     * ======================================================== */

    int status;

    if (waitpid(child, &status, 0) == -1) {

        perror("waitpid");

        return -1;
    }


    /*
     * The child should initially stop with SIGSTOP.
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


    /*
     * Configure ptrace to report syscall stops.
     */
    if (ptrace(PTRACE_SETOPTIONS,
               child,
               NULL,
               PTRACE_O_TRACESYSGOOD) == -1) {

        perror("ptrace(PTRACE_SETOPTIONS)");

        return -1;
    }


    /*
     * Tell child to continue until next syscall.
     */
    if (ptrace(PTRACE_SYSCALL,
               child,
               NULL,
               NULL) == -1) {

        perror("ptrace(PTRACE_SYSCALL)");

        return -1;
    }


    /*
     * First syscall stop is syscall entry.
     */
    int entering_syscall = 1;

    unsigned long syscall_count = 0;

    /*
     * Keep the syscall number between entry and exit.
     */
    long current_syscall_number = -1;


    /* ========================================================
     * MAIN TRACE LOOP
     * ======================================================== */

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
         * We only care about stopped children.
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
         * Get register state.
         */
        struct user_regs_struct regs;

        if (ptrace(PTRACE_GETREGS,
                   child,
                   NULL,
                   &regs) == -1) {

            perror("ptrace(PTRACE_GETREGS)");

            return -1;
        }


        /*
         * Ignore ordinary signals.

         * With PTRACE_O_TRACESYSGOOD,
         * syscall stops appear as SIGTRAP | 0x80.
         */
        int signal_number = WSTOPSIG(status);

        if (signal_number != (SIGTRAP | 0x80)) {

            /*
             * Forward the signal to the child unless it is SIGSTOP.
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


        /* ====================================================
         * SYSCALL ENTRY
         * ==================================================== */

        if (entering_syscall) {

            /*
             * On x86-64 Linux:
             *
             * orig_rax = syscall number
             */
            long syscall_number =
                (long)regs.orig_rax;


            current_syscall_number =
                syscall_number;


            const char *name =
                syscall_name(syscall_number);


            /*
             * Decode execve path.
             *
             * execve:
             *
             *   rdi = filename
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


            printf("[Syscall Entry] #%lu  %ld (%s)\n",
                   syscall_count,
                   syscall_number,
                   name);


            print_syscall_arguments(&regs);


            /*
             * Do NOT call stats_record() here.
             *
             * stats_record() expects:
             *
             *     syscall number
             *     return value
             *
             * The return value is only available on syscall exit.
             */


            entering_syscall = 0;
        }


        /* ====================================================
         * SYSCALL EXIT
         * ==================================================== */

        else {

            /*
             * On x86-64 Linux:
             *
             * rax = syscall return value
             */
            long return_value =
                (long)regs.rax;


            const char *name =
                syscall_name(current_syscall_number);


            printf("[Syscall Exit ] #%lu  ",
                   syscall_count);


            printf("%ld (%s) ",
                   current_syscall_number,
                   name);


            print_syscall_return(return_value);


            /*
             * Record complete syscall statistics.
             *
             * IMPORTANT:
             *
             * stats_record() expects:
             *
             *     stats_record(syscall_number,
             *                  return_value);
             */
            stats_record(current_syscall_number,
                         return_value);


            syscall_count++;


            entering_syscall = 1;
        }


        /*
         * Continue the tracee until the next syscall stop.
         */
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

    printf("[Tracer] Total syscall calls observed: %lu\n",
           syscall_count);


    printf("\n");


    /*
     * Print the statistics table.
     */
    stats_print();


    return 0;
}
