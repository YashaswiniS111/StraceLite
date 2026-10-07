#include <signal.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    printf("Signal target running\n");
    fflush(stdout);
    raise(SIGTERM);
    return 0;
}
