#include "tracer.h"
#include "filter.h"
#include "syscall.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/*
 * ============================================================
 * Parse comma-separated syscall filter
 * ============================================================
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


/*
 * ============================================================
 * Print command usage
 * ============================================================
 */
static void print_usage(const char *program)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s [options] <program> [args...]\n\n"
            "Options:\n"
            "  --filter syscall1,syscall2,...\n"
            "      Display only selected syscalls.\n\n"
            "  --category CATEGORY\n"
            "      Display only syscalls from a category.\n\n"
            "Categories:\n"
            "  FILE_IO\n"
            "  MEMORY\n"
            "  PROCESS\n"
            "  NETWORK\n"
            "  SYSTEM\n\n"
            "Examples:\n"
            "  %s --filter read,write /bin/ls\n"
            "  %s --category MEMORY /bin/ls\n"
            "  %s --category FILE_IO /bin/ls\n"
            "  %s --category FILE_IO --filter openat,close /bin/ls\n",
            program,
            program,
            program,
            program,
            program);
}


/*
 * ============================================================
 * Main
 * ============================================================
 */
int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    /*
     * Initialize all filters.
     */
    filter_init();

    int target_index = 1;

    /*
     * Parse command-line options.
     */
    while (target_index < argc) {

        /*
         * Syscall-name filter.
         */
        if (strcmp(argv[target_index], "--filter") == 0) {

            if (target_index + 1 >= argc) {

                fprintf(stderr,
                        "[StraceLite] Missing syscall filter list\n");

                print_usage(argv[0]);

                return 1;
            }

            if (parse_filter_list(
                    argv[target_index + 1]) == -1) {

                fprintf(stderr,
                        "[StraceLite] Failed to configure syscall filter\n");

                return 1;
            }

            printf("[StraceLite] Syscall filter: %s\n",
                   argv[target_index + 1]);

            target_index += 2;

            continue;
        }


        /*
         * Category filter.
         */
        if (strcmp(argv[target_index], "--category") == 0) {

            if (target_index + 1 >= argc) {

                fprintf(stderr,
                        "[StraceLite] Missing category name\n");

                print_usage(argv[0]);

                return 1;
            }

            if (filter_set_category(
                    argv[target_index + 1]) == -1) {

                fprintf(stderr,
                        "[StraceLite] Unknown category: %s\n",
                        argv[target_index + 1]);

                fprintf(stderr,
                        "[StraceLite] Valid categories: "
                        "FILE_IO, MEMORY, PROCESS, NETWORK, SYSTEM\n");

                return 1;
            }

            printf("[StraceLite] Category filter: %s\n",
                   argv[target_index + 1]);

            target_index += 2;

            continue;
        }


        /*
         * First non-option argument is the target program.
         */
        break;
    }


    /*
     * No target program.
     */
    if (target_index >= argc) {

        fprintf(stderr,
                "[StraceLite] No target program specified\n");

        print_usage(argv[0]);

        return 1;
    }


    /*
     * Launch target.
     */
    printf("[StraceLite] Launching target: %s\n",
           argv[target_index]);

    return tracer_launch(&argv[target_index]);
}
