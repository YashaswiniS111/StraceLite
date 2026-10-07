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
 * 11. Follow fork()
 * 12. Follow vfork()
 * 13. Follow clone()
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
 * Maximum number of simultaneously traced processes
 * ============================================================ */

#define MAX_TRACEES 128


/* ============================================================
 * Per-process tracing state
 * ============================================================ */

typedef struct {
    pid_t pid;

    /*
     * 1 = next syscall stop is entry
     * 0 = next syscall stop is exit
     */
    int entering_syscall;

    /*
     * Syscall number belonging to the current
     * entry/exit pair.
     */
    long current_syscall_number;

    /*
     * Whether this slot is currently active.
     */
    int active;
} TraceeState;


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
 * Initialize tracee state
 * ============================================================ */

static void tracee_state_init(
    TraceeState *state,
    pid_t pid)
{
    state->pid = pid;
    state->entering_syscall = 1;
    state->current_syscall_number = -1;
    state->active = 1;
}


/* ============================================================
 * Find tracee state
 * ============================================================ */

static TraceeState *find_tracee(
    TraceeState *tracees,
    pid_t pid)
{
    for (int i = 0; i < MAX_TRACEES; i++) {

        if (tracees[i].active &&
            tracees[i].pid == pid) {

            return &tracees[i];
        }
    }

    return NULL;
}


/* ============================================================
 * Add new tracee
 * ============================================================ */

static TraceeState *add_tracee(
    TraceeState *tracees,
    pid_t pid)
{
    /*
     * Do not add the same PID twice.
     */
    TraceeState *existing =
        find_tracee(tracees, pid);

    if (existing != NULL) {
        return existing;
    }


    for (int i = 0; i < MAX_TRACEES; i++) {

        if (!tracees[i].active) {

            tracee_state_init(
                &tracees[i],
                pid);

            return &tracees[i];
        }
    }


    fprintf(stderr,
            "[Tracer] Maximum number of tracees reached\n");

    return NULL;
}


/* ============================================================
 * Remove tracee
 * ============================================================ */

static void remove_tracee(
    TraceeState *tracees,
    pid_t pid)
{
    TraceeState *state =
        find_tracee(tracees, pid);

    if (state != NULL) {
        state->active = 0;
    }
}


/* ============================================================
 * Count active tracees
 * ============================================================ */

static int active_tracee_count(
    TraceeState *tracees)
{
    int count = 0;

    for (int i = 0; i < MAX_TRACEES; i++) {

        if (tracees[i].active) {
            count++;
        }
    }

    return count;
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
     * TRACE PROCESS TABLE
     * ======================================================== */

    TraceeState tracees[MAX_TRACEES] = {0};


    /* ========================================================
     * CREATE INITIAL CHILD PROCESS
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
     * Wait for the initial SIGSTOP.
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
     * Add the initial tracee.
     */
    if (add_tracee(tracees, child) == NULL) {
        return -1;
    }


    /* ========================================================
     * CONFIGURE PTRACE
     * ======================================================== */

    /*
     * PTRACE_O_TRACESYSGOOD:
     *
     *     syscall stop = SIGTRAP | 0x80
     *
     * PTRACE_O_TRACEFORK:
     *
     *     report fork() events
     *
     * PTRACE_O_TRACEVFORK:
     *
     *     report vfork() events
     *
     * PTRACE_O_TRACECLONE:
     *
     *     report clone() events
     */
    long ptrace_options =
        PTRACE_O_TRACESYSGOOD |
        PTRACE_O_TRACEFORK |
        PTRACE_O_TRACEVFORK |
        PTRACE_O_TRACECLONE;


    if (ptrace(PTRACE_SETOPTIONS,
               child,
               NULL,
               (void *)ptrace_options) == -1) {

        perror("ptrace(PTRACE_SETOPTIONS)");

        return -1;
    }


    /*
     * Continue initial tracee.
     */
    if (ptrace(PTRACE_SYSCALL,
               child,
               NULL,
               NULL) == -1) {

        perror("ptrace(PTRACE_SYSCALL)");

        return -1;
    }


    /*
     * Global number of syscall entries observed.
     */
    unsigned long syscall_count = 0;


    /* ========================================================
     * MAIN MULTI-PROCESS TRACING LOOP
     * ======================================================== */

    while (active_tracee_count(tracees) > 0) {

        /*
         * Wait for ANY traced process.
         *
         * __WALL is important because it allows the tracer
         * to receive events from traced threads created by
         * clone().
         */
        pid_t pid = waitpid(
            -1,
            &status,
            __WALL);


        if (pid == -1) {

            if (errno == EINTR) {
                continue;
            }

            /*
             * No traced children remain.
             */
            if (errno == ECHILD) {
                break;
            }

            perror("waitpid");

            return -1;
        }


        /*
         * Find state belonging to this process.
         */
        TraceeState *state =
            find_tracee(tracees, pid);


        /*
         * A newly created tracee may appear before
         * its state has been explicitly registered.
         */
        if (state == NULL) {

            state = add_tracee(
                tracees,
                pid);

            if (state == NULL) {
                return -1;
            }
        }


        /* ====================================================
         * PROCESS EXIT
         * ==================================================== */

        if (WIFEXITED(status)) {

            printf("[Tracer] PID %d exited with status %d\n",
                   pid,
                   WEXITSTATUS(status));

            remove_tracee(tracees, pid);

            continue;
        }


        /* ====================================================
         * PROCESS TERMINATED BY SIGNAL
         * ==================================================== */

        if (WIFSIGNALED(status)) {

            printf("[Tracer] PID %d terminated by signal %d\n",
                   pid,
                   WTERMSIG(status));

            remove_tracee(tracees, pid);

            continue;
        }


        /*
         * Ignore unexpected states.
         */
        if (!WIFSTOPPED(status)) {
            continue;
        }


        int signal_number =
            WSTOPSIG(status);


        /* ====================================================
         * HANDLE PTRACE PROCESS EVENTS
         * ==================================================== */

        /*
         * ptrace event information is stored in:
         *
         *     status >> 16
         *
         * The signal itself is SIGTRAP.
         */
        unsigned int event =
            (unsigned int)status >> 16;


        if (signal_number == SIGTRAP &&
            event != 0) {

            unsigned long event_message = 0;


            /*
             * Obtain PID associated with the event.
             */
            if (ptrace(PTRACE_GETEVENTMSG,
                       pid,
                       NULL,
                       &event_message) == -1) {

                perror("ptrace(PTRACE_GETEVENTMSG)");

                return -1;
            }


            pid_t new_pid =
                (pid_t)event_message;


            /*
             * ------------------------------------------------
             * FORK
             * ------------------------------------------------
             */

            if (event == PTRACE_EVENT_FORK) {

                printf("[Tracer] PID %d created child PID %d "
                       "using fork()\n",
                       pid,
                       new_pid);
            }


            /*
             * ------------------------------------------------
             * VFORK
             * ------------------------------------------------
             */

            else if (event == PTRACE_EVENT_VFORK) {

                printf("[Tracer] PID %d created child PID %d "
                       "using vfork()\n",
                       pid,
                       new_pid);
            }


            /*
             * ------------------------------------------------
             * CLONE
             * ------------------------------------------------
             */

            else if (event == PTRACE_EVENT_CLONE) {

                printf("[Tracer] PID %d created child PID %d "
                       "using clone()\n",
                       pid,
                       new_pid);
            }


            /*
             * Register the new process/thread.
             *
             * The kernel has already attached it to the
             * tracer because the corresponding ptrace option
             * was enabled.
             */
            if (event == PTRACE_EVENT_FORK ||
                event == PTRACE_EVENT_VFORK ||
                event == PTRACE_EVENT_CLONE) {

                if (add_tracee(
                        tracees,
                        new_pid) == NULL) {

                    return -1;
                }
            }


            /*
             * Continue the process that generated the event.
             */
            if (ptrace(PTRACE_SYSCALL,
                       pid,
                       NULL,
                       NULL) == -1) {

                /*
                 * The process may have exited between the
                 * event and this call.
                 */
                if (errno != ESRCH) {

                    perror("ptrace(PTRACE_SYSCALL)");

                    return -1;
                }
            }


            continue;
        }


        /* ====================================================
         * HANDLE PLAIN SIGTRAP
         * ==================================================== */

        /*
         * A plain SIGTRAP can occur after execve().
         *
         * It is generated by ptrace and should not be
         * delivered to the tracee.
         */
        if (signal_number == SIGTRAP) {

            if (ptrace(PTRACE_SYSCALL,
                       pid,
                       NULL,
                       NULL) == -1) {

                if (errno != ESRCH) {

                    perror("ptrace(PTRACE_SYSCALL)");

                    return -1;
                }
            }

            continue;
        }


        /* ====================================================
         * HANDLE REAL SIGNALS
         * ==================================================== */

        /*
         * Syscall stops are:
         *
         *     SIGTRAP | 0x80
         *
         * Everything else is a real signal.
         */
        if (signal_number !=
            (SIGTRAP | 0x80)) {

            int deliver_signal =
                signal_number;


            /*
             * Do not re-deliver SIGSTOP.
             */
            if (signal_number == SIGSTOP) {
                deliver_signal = 0;
            }


            if (ptrace(
                    PTRACE_SYSCALL,
                    pid,
                    NULL,
                    (void *)(long)deliver_signal) == -1) {

                if (errno != ESRCH) {

                    perror("ptrace(PTRACE_SYSCALL)");

                    return -1;
                }
            }

            continue;
        }


        /* ====================================================
         * GET TRACEe REGISTERS
         * ==================================================== */

        struct user_regs_struct regs;


        if (ptrace(PTRACE_GETREGS,
                   pid,
                   NULL,
                   &regs) == -1) {

            if (errno == ESRCH) {
                continue;
            }

            perror("ptrace(PTRACE_GETREGS)");

            return -1;
        }


        /* ====================================================
         * SYSCALL ENTRY
         * ==================================================== */

        if (state->entering_syscall) {

            /*
             * On x86-64 Linux:
             *
             *     orig_rax = syscall number
             */
            long syscall_number =
                (long)regs.orig_rax;


            state->current_syscall_number =
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
             * execve():
             *
             *     rdi = filename
             */
            if (syscall_number == 59) {

                char path[4096];


                if (tracee_read_string(
                        pid,
                        (unsigned long)regs.rdi,
                        path,
                        sizeof(path)) == 0) {

                    printf("[Decoded] PID %d execve path: "
                           "\"%s\"\n",
                           pid,
                           path);
                }
            }


            /*
             * =================================================
             * FILTERING
             * =================================================
             */
            if (filter_allows(name) &&
                filter_category_allows(
                    syscall_number)) {

                printf("[Syscall Entry] "
                       "PID %d  #%lu  %ld (%s)\n",
                       pid,
                       syscall_count - 1,
                       syscall_number,
                       name);

                print_syscall_arguments(&regs);
            }


            /*
             * Next syscall stop is exit.
             */
            state->entering_syscall = 0;
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
                syscall_name(
                    state->current_syscall_number);


            /*
             * Record statistics for every syscall.
             */
            stats_record(
                state->current_syscall_number,
                return_value);


            /*
             * Display exit only when filters allow it.
             */
            if (filter_allows(name) &&
                filter_category_allows(
                    state->current_syscall_number)) {

                printf("[Syscall Exit ] "
                       "PID %d  #%lu  %ld (%s)",
                       pid,
                       syscall_count - 1,
                       state->current_syscall_number,
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
             * Next syscall stop is entry.
             */
            state->entering_syscall = 1;
        }


        /* ====================================================
         * CONTINUE TRACE
         * ==================================================== */

        if (ptrace(PTRACE_SYSCALL,
                   pid,
                   NULL,
                   NULL) == -1) {

            if (errno != ESRCH) {

                perror("ptrace(PTRACE_SYSCALL)");

                return -1;
            }
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
