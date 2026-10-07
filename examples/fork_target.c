#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

int main(void)
{
    pid_t pid = fork();

    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        printf("Child process running\n");
        return 0;
    }

    printf("Parent process running\n");
    waitpid(pid, NULL, 0);

    return 0;
}
