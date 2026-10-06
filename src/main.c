#include "tracer.h"
#include "filter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Parse a comma-separated syscall filter list.
 *
 * Example:
 *
 *     openat,read,write
 */
static int parse_filter_list(const char *list)
{
    if (list == NULL || list[0] == '\0') {
        return -1;
    }

    char *copy = malloc(strlen(list) + 1);

    if (copy == NULL) {
        return -1;
    }

    strcpy(copy, list);

    char *token = strtok(copy, ",");

    while (token != NULL) {

        if (filter_add(token) == -1) {

            fprintf(stderr,
                    "[StraceLite] Unknown or invalid syscall: %s\n",
                    token);

            free(copy);
            return -1;
        }

        token = strtok(NULL, ",");
    }

    free(copy);

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {

        fprintf(stderr,
                "Usage: %s [--filter syscall1,syscall2,...] "
                "<program> [args...]\n",
                argv[0]);

        return 1;
    }

    /*
     * Initialize filtering.
     */
    filter_init();

    int target_index = 1;

    /*
     * Optional syscall filter.
     */
    if (strcmp(argv[1], "--filter") == 0) {

        if (argc < 4) {

            fprintf(stderr,
                    "Usage: %s --filter syscall1,syscall2,... "
                    "<program> [args...]\n",
                    argv[0]);

            return 1;
        }

        if (parse_filter_list(argv[2]) == -1) {

            fprintf(stderr,
                    "[StraceLite] Failed to configure syscall filter\n");

            return 1;
        }

        target_index = 3;

        printf("[StraceLite] Syscall filter: %s\n",
               argv[2]);
    }

    printf("[StraceLite] Launching target: %s\n",
           argv[target_index]);

    return tracer_launch(&argv[target_index]);
}
