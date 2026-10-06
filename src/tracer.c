#include "tracer.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int wait_for_syscall(pid_t child)
{
    int status;

    if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) == -1) {
        perror("ptrace(PTRACE_SYSCALL)");
        return -1;
    }

    if (waitpid(child, &status, 0) == -1) {
        perror("waitpid");
        return -1;
    }

    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        return 1;
    }

    if (WIFSTOPPED(status)) {
        return 0;
    }

    return -1;
}

int tracer_launch(char *const argv[])
{
    pid_t child = fork();

    if (child == -1) {
        perror("fork");
        return -1;
    }

    if (child == 0) {
        /*
         * The child declares that its parent will trace it.
         */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            perror("ptrace(PTRACE_TRACEME)");
            _exit(EXIT_FAILURE);
        }

        /*
         * Replace the child process image with the target.
         */
        execvp(argv[0], argv);

        /*
         * execvp() returns only if an error occurs.
         */
        perror("execvp");
        _exit(127);
    }

    /*
     * Parent becomes the tracer.
     */
    int status;

    if (waitpid(child, &status, 0) == -1) {
        perror("waitpid");
        return -1;
    }

    if (!WIFSTOPPED(status)) {
        fprintf(stderr,
                "[Tracer] Expected initial trace stop\n");
        return -1;
    }

    printf("[Tracer] Child %d stopped by signal %d\n",
           child,
           WSTOPSIG(status));

    /*
     * Each PTRACE_SYSCALL resumes the tracee until
     * the next syscall boundary.
     *
     * The first stop is syscall entry, the next is
     * syscall exit, then entry again, and so on.
     */
    int entering = 1;
    unsigned long syscall_count = 0;

    while (1) {
        int result = wait_for_syscall(child);

        if (result == -1) {
            return -1;
        }

        if (result == 1) {
            break;
        }

        if (entering) {
            printf("[Syscall Entry] #%lu\n", syscall_count);
        } else {
            printf("[Syscall Exit ] #%lu\n", syscall_count);
            syscall_count++;
        }

        entering = !entering;
    }

    if (WIFEXITED(status)) {
        printf("[Tracer] Child exited with status %d\n",
               WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        printf("[Tracer] Child terminated by signal %d\n",
               WTERMSIG(status));
    }

    printf("[Tracer] Total syscall boundaries observed: %lu\n",
           syscall_count);

    return 0;
}
