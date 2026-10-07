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
#include <string.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <unistd.h>

#define MAX_TRACEES 128

typedef struct
{
    pid_t pid;
    int entering_syscall;
    long current_syscall_number;
    int active;
} TraceeState;


/* ---------------------------------------------------------
 * Tracee state helpers
 * --------------------------------------------------------- */

static void tracee_state_init(TraceeState *state, pid_t pid)
{
    state->pid = pid;
    state->entering_syscall = 1;
    state->current_syscall_number = -1;
    state->active = 1;
}

static TraceeState *find_tracee(TraceeState *states, pid_t pid)
{
    for (int i = 0; i < MAX_TRACEES; i++)
    {
        if (states[i].active && states[i].pid == pid)
        {
            return &states[i];
        }
    }

    return NULL;
}

static TraceeState *add_tracee(TraceeState *states, pid_t pid)
{
    for (int i = 0; i < MAX_TRACEES; i++)
    {
        if (!states[i].active)
        {
            tracee_state_init(&states[i], pid);
            return &states[i];
        }
    }

    return NULL;
}

static void remove_tracee(TraceeState *state)
{
    if (state != NULL)
    {
        state->active = 0;
    }
}

static int active_tracee_count(TraceeState *states)
{
    int count = 0;

    for (int i = 0; i < MAX_TRACEES; i++)
    {
        if (states[i].active)
        {
            count++;
        }
    }

    return count;
}


/* ---------------------------------------------------------
 * Signal name helper
 * --------------------------------------------------------- */

static const char *signal_name(int signal_number)
{
    const char *name = strsignal(signal_number);

    if (name == NULL)
    {
        return "Unknown signal";
    }

    return name;
}


/* ---------------------------------------------------------
 * Main tracer
 * --------------------------------------------------------- */

int tracer_launch(char *const argv[])
{
    /*
     * Print BEFORE fork().
     *
     * If this is printed after fork(), both parent and child
     * can execute the printf() and the line may appear twice.
     */
    printf("[StraceLite] Launching target: %s\n", argv[0]);
    fflush(stdout);

    pid_t child_pid = fork();

    if (child_pid == -1)
    {
        perror("fork");
        return -1;
    }

    /*
     * ---------------------------------------------------------
     * Child process
     * ---------------------------------------------------------
     */
    if (child_pid == 0)
    {
        /*
         * Tell the kernel that this process will be traced by
         * its parent.
         */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1)
        {
            perror("ptrace(PTRACE_TRACEME)");
            _exit(EXIT_FAILURE);
        }

        /*
         * Stop ourselves so the parent can configure ptrace
         * before allowing the target to run.
         */
        raise(SIGSTOP);

        /*
         * Replace this process with the target program.
         */
        execvp(argv[0], argv);

        perror("execvp");
        _exit(EXIT_FAILURE);
    }

    /*
     * ---------------------------------------------------------
     * Parent / tracer process
     * ---------------------------------------------------------
     */

    TraceeState states[MAX_TRACEES] = {0};

    TraceeState *initial_state =
        add_tracee(states, child_pid);

    if (initial_state == NULL)
    {
        fprintf(stderr, "[Tracer] Too many tracees\n");
        return -1;
    }

    /*
     * Total completed syscall count.
     *
     * stats.c maintains the detailed per-syscall statistics.
     * This local variable is used for the numbered tracer output.
     */
    unsigned long total_syscall_calls = 0;

    /*
     * ---------------------------------------------------------
     * Wait for initial SIGSTOP
     * ---------------------------------------------------------
     */

    int status;

    if (waitpid(child_pid, &status, 0) == -1)
    {
        perror("waitpid");
        return -1;
    }

    if (WIFSTOPPED(status))
    {
        printf("[Tracer] Child %d stopped by signal %d\n",
               child_pid,
               WSTOPSIG(status));
    }

    /*
     * ---------------------------------------------------------
     * Configure ptrace
     * ---------------------------------------------------------
     */

    long options =
        PTRACE_O_TRACESYSGOOD |
        PTRACE_O_TRACEFORK |
        PTRACE_O_TRACEVFORK |
        PTRACE_O_TRACECLONE;

    if (ptrace(PTRACE_SETOPTIONS,
               child_pid,
               NULL,
               (void *)options) == -1)
    {
        perror("ptrace(PTRACE_SETOPTIONS)");
        return -1;
    }

    /*
     * Start syscall tracing.
     */
    if (ptrace(PTRACE_SYSCALL,
               child_pid,
               NULL,
               NULL) == -1)
    {
        perror("ptrace(PTRACE_SYSCALL)");
        return -1;
    }

    /*
     * ---------------------------------------------------------
     * Main tracing loop
     * ---------------------------------------------------------
     */

    while (active_tracee_count(states) > 0)
    {
        pid_t pid = waitpid(-1, &status, __WALL);

        if (pid == -1)
        {
            if (errno == EINTR)
            {
                continue;
            }

            if (errno == ECHILD)
            {
                break;
            }

            perror("waitpid");
            break;
        }

        TraceeState *state =
            find_tracee(states, pid);

        /*
         * -----------------------------------------------------
         * Normal process exit
         * -----------------------------------------------------
         */

        if (WIFEXITED(status))
        {
            printf("[Tracer] PID %d exited with status %d\n",
                   pid,
                   WEXITSTATUS(status));

            if (state != NULL)
            {
                remove_tracee(state);
            }

            continue;
        }

        /*
         * -----------------------------------------------------
         * Process terminated by a signal
         * -----------------------------------------------------
         */

        if (WIFSIGNALED(status))
        {
            int signal_number = WTERMSIG(status);

            printf("[Tracer] PID %d terminated by signal %d (%s)\n",
                   pid,
                   signal_number,
                   signal_name(signal_number));

            if (state != NULL)
            {
                remove_tracee(state);
            }

            continue;
        }

        /*
         * -----------------------------------------------------
         * Process stopped
         * -----------------------------------------------------
         */

        if (!WIFSTOPPED(status))
        {
            continue;
        }

        int stop_signal = WSTOPSIG(status);

        /*
         * With PTRACE_O_TRACESYSGOOD:
         *
         * SIGTRAP | 0x80 means syscall-stop.
         */
        int is_syscall_stop =
            (stop_signal == (SIGTRAP | 0x80));

        /*
         * Ptrace event is stored in the upper 16 bits.
         */
        unsigned int event =
            (unsigned int)(status >> 16);

        /*
         * -----------------------------------------------------
         * fork / vfork / clone event
         * -----------------------------------------------------
         */

        if (stop_signal == SIGTRAP && event != 0)
        {
            unsigned long new_pid = 0;

            if (ptrace(PTRACE_GETEVENTMSG,
                       pid,
                       NULL,
                       &new_pid) == -1)
            {
                perror("ptrace(PTRACE_GETEVENTMSG)");
            }
            else
            {
                TraceeState *new_state =
                    add_tracee(states, (pid_t)new_pid);

                if (new_state == NULL)
                {
                    fprintf(stderr,
                            "[Tracer] Too many tracees\n");
                }
                else
                {
                    const char *event_name = "process";

                    if (event == PTRACE_EVENT_FORK)
                    {
                        event_name = "fork()";
                    }
                    else if (event == PTRACE_EVENT_VFORK)
                    {
                        event_name = "vfork()";
                    }
                    else if (event == PTRACE_EVENT_CLONE)
                    {
                        event_name = "clone()";
                    }

                    printf(
                        "[Tracer] PID %d created child PID %lu using %s\n",
                        pid,
                        new_pid,
                        event_name);
                }
            }

            /*
             * Continue the parent tracee.
             */
            if (ptrace(PTRACE_SYSCALL,
                       pid,
                       NULL,
                       NULL) == -1)
            {
                if (errno != ESRCH)
                {
                    perror("ptrace(PTRACE_SYSCALL)");
                }
            }

            continue;
        }

        /*
         * -----------------------------------------------------
         * Real signal stop
         * -----------------------------------------------------
         *
         * Syscall stops are SIGTRAP | 0x80 and therefore must
         * not be treated as normal signals.
         *
         * SIGSTOP is the initial tracing stop and is ignored.
         */

        if (!is_syscall_stop &&
            stop_signal != SIGSTOP &&
            stop_signal != SIGTRAP)
        {
            printf(
                "[Signal] PID %d stopped by signal %d (%s)\n",
                pid,
                stop_signal,
                signal_name(stop_signal));

            /*
             * Deliver the real signal to the tracee.
             */
            if (ptrace(PTRACE_SYSCALL,
                       pid,
                       NULL,
                       (void *)(long)stop_signal) == -1)
            {
                if (errno != ESRCH)
                {
                    perror("ptrace(PTRACE_SYSCALL)");
                }
            }

            continue;
        }

        /*
         * -----------------------------------------------------
         * Plain SIGTRAP
         * -----------------------------------------------------
         *
         * This is a ptrace-related trap, not a normal signal
         * that should be reported as an application signal.
         */

        if (stop_signal == SIGTRAP &&
            !is_syscall_stop)
        {
            if (ptrace(PTRACE_SYSCALL,
                       pid,
                       NULL,
                       NULL) == -1)
            {
                if (errno != ESRCH)
                {
                    perror("ptrace(PTRACE_SYSCALL)");
                }
            }

            continue;
        }

        /*
         * -----------------------------------------------------
         * Unexpected non-syscall stop
         * -----------------------------------------------------
         */

        if (!is_syscall_stop)
        {
            if (ptrace(PTRACE_SYSCALL,
                       pid,
                       NULL,
                       NULL) == -1)
            {
                if (errno != ESRCH)
                {
                    perror("ptrace(PTRACE_SYSCALL)");
                }
            }

            continue;
        }

        /*
         * We should have a TraceeState for every syscall stop.
         */
        if (state == NULL)
        {
            if (ptrace(PTRACE_SYSCALL,
                       pid,
                       NULL,
                       NULL) == -1)
            {
                if (errno != ESRCH)
                {
                    perror("ptrace(PTRACE_SYSCALL)");
                }
            }

            continue;
        }

        /*
         * -----------------------------------------------------
         * Read registers
         * -----------------------------------------------------
         */

        struct user_regs_struct regs;

        if (ptrace(PTRACE_GETREGS,
                   pid,
                   NULL,
                   &regs) == -1)
        {
            if (errno != ESRCH)
            {
                perror("ptrace(PTRACE_GETREGS)");
            }

            continue;
        }

        /*
         * x86-64 Linux:
         *
         * orig_rax = syscall number
         */
        long syscall_number =
            (long)regs.orig_rax;

        /*
         * -----------------------------------------------------
         * Syscall entry
         * -----------------------------------------------------
         */

        if (state->entering_syscall)
        {
            state->current_syscall_number =
                syscall_number;

            const char *name =
                syscall_name(syscall_number);

            printf(
                "[Syscall Entry] PID %d #%lu %ld (%s)\n",
                pid,
                total_syscall_calls + 1,
                syscall_number,
                name);

            /*
             * execve syscall number on x86-64 Linux = 59.
             *
             * rdi contains the filename pointer.
             */
            if (syscall_number == 59)
            {
                char path[256];

                if (tracee_read_string(
                        pid,
                        (unsigned long)regs.rdi,
                        path,
                        sizeof(path)) == 0)
                {
                    printf(
                        "[Decoded] PID %d execve path: \"%s\"\n",
                        pid,
                        path);
                }
            }

            state->entering_syscall = 0;
        }
        else
        {
            /*
             * -------------------------------------------------
             * Syscall exit
             * -------------------------------------------------
             */

            long return_value =
                (long)regs.rax;

            long number =
                state->current_syscall_number;

            const char *name =
                syscall_name(number);

            printf(
                "[Syscall Exit ] PID %d #%lu %ld (%s) return=%ld",
                pid,
                total_syscall_calls + 1,
                number,
                name,
                return_value);

            /*
             * Linux syscall errors are represented by negative
             * values from -1 through -4095.
             */
            if (return_value < 0 &&
                return_value >= -4095)
            {
                printf(
                    " errno=%ld (%s)",
                    -return_value,
                    strerror((int)-return_value));
            }

            printf("\n");

            /*
             * Record detailed syscall statistics.
             */
            stats_record(number, return_value);

            /*
             * Count completed syscall.
             */
            total_syscall_calls++;

            /*
             * Keep the filtering subsystem active.
             *
             * Statistics are recorded regardless of filters.
             */
            (void)filter_allows(name);
            (void)filter_category_allows(number);

            state->entering_syscall = 1;
            state->current_syscall_number = -1;
        }

        /*
         * Continue until the next syscall stop.
         */
        if (ptrace(PTRACE_SYSCALL,
                   pid,
                   NULL,
                   NULL) == -1)
        {
            if (errno != ESRCH)
            {
                perror("ptrace(PTRACE_SYSCALL)");
            }
        }
    }

    /*
     * ---------------------------------------------------------
     * Final statistics
     * ---------------------------------------------------------
     */

    printf(
        "\n[Tracer] Total syscall calls observed: %lu\n",
        total_syscall_calls);

    stats_print();

    return 0;
}
