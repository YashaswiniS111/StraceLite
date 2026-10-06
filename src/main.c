#include "tracer.h"

#include <stdio.h>

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program> [args...]\n", argv[0]);
        return 1;
    }

    printf("[StraceLite] Launching target: %s\n", argv[1]);

    return tracer_launch(&argv[1]);
}
