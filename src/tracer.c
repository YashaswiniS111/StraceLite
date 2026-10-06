#include "tracer.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

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
         * Replace the child process image with the target program.
         */
        execvp(argv[0], argv);

        /*
         * execvp() only returns when an error occurs.
         */
        perror("execvp");
        _exit(EXIT_FAILURE);
    }

    /*
     * Parent becomes the tracer.
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
     * Continue the tracee.
     */
    if (ptrace(PTRACE_CONT, child, NULL, NULL) == -1) {
        perror("ptrace(PTRACE_CONT)");
        return -1;
    }

    /*
     * Wait for the tracee to finish.
     */
    if (waitpid(child, &status, 0) == -1) {
        perror("waitpid");
        return -1;
    }

    if (WIFEXITED(status)) {
        printf("[Tracer] Child exited with status %d\n",
               WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        printf("[Tracer] Child terminated by signal %d\n",
               WTERMSIG(status));
    }

    return 0;
}
