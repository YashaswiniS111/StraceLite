#include "tracer.h"
#include "filter.h"

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
        fprintf(stderr,
                "[StraceLite] Memory allocation failed\n");
        return -1;
    }

    strcpy(copy, list);

    char *token = strtok(copy, ",");

    if (token == NULL) {
        free(copy);
        return -1;
    }

    while (token != NULL) {

        if (token[0] == '\0') {
            fprintf(stderr,
                    "[StraceLite] Empty syscall name in filter\n");

            free(copy);
            return -1;
        }

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
    printf(
        "StraceLite - Mini Linux Syscall Tracer\n"
        "\n"
        "Usage:\n"
        "  %s [options] <program> [args...]\n"
        "\n"
        "Options:\n"
        "  --help\n"
        "      Display this help message.\n"
        "\n"
        "  --filter syscall1,syscall2,...\n"
        "      Display only selected syscalls.\n"
        "\n"
        "  --category CATEGORY\n"
        "      Display only syscalls from a category.\n"
        "\n"
        "Categories:\n"
        "  FILE_IO\n"
        "  MEMORY\n"
        "  PROCESS\n"
        "  NETWORK\n"
        "  SYSTEM\n"
        "\n"
        "Examples:\n"
        "  %s /bin/ls\n"
        "  %s --filter read,write /bin/ls\n"
        "  %s --category MEMORY /bin/ls\n"
        "  %s --category FILE_IO /bin/ls\n"
        "  %s --category FILE_IO --filter openat,close /bin/ls\n"
        "\n",
        program,
        program,
        program,
        program,
        program,
        program
    );
}


/*
 * ============================================================
 * Print version information
 * ============================================================
 */
static void print_version(void)
{
    printf("StraceLite version 1.0\n");
    printf("Mini Linux syscall tracer using ptrace\n");
}


/*
 * ============================================================
 * Main
 * ============================================================
 */
int main(int argc, char *argv[])
{
    /*
     * No arguments.
     */
    if (argc < 2) {
        fprintf(stderr,
                "[StraceLite] No target program specified\n\n");

        print_usage(argv[0]);

        return 1;
    }


    /*
     * Initialize filters.
     */
    filter_init();

    int target_index = 1;


    /*
     * Parse command-line options.
     */
    while (target_index < argc) {

        /*
         * Help.
         */
        if (strcmp(argv[target_index], "--help") == 0 ||
            strcmp(argv[target_index], "-h") == 0) {

            print_usage(argv[0]);

            return 0;
        }


        /*
         * Version.
         */
        if (strcmp(argv[target_index], "--version") == 0 ||
            strcmp(argv[target_index], "-v") == 0) {

            print_version();

            return 0;
        }


        /*
         * Syscall-name filter.
         */
        if (strcmp(argv[target_index], "--filter") == 0) {

            if (target_index + 1 >= argc) {

                fprintf(stderr,
                        "[StraceLite] Missing syscall filter list\n\n");

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
                        "[StraceLite] Missing category name\n\n");

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
         * Unknown option.
         *
         * A target program beginning with '-' can still be
         * executed by placing "--" before it.
         */
        if (argv[target_index][0] == '-' &&
            strcmp(argv[target_index], "--") != 0) {

            fprintf(stderr,
                    "[StraceLite] Unknown option: %s\n\n",
                    argv[target_index]);

            print_usage(argv[0]);

            return 1;
        }


        /*
         * Explicit end of options.
         */
        if (strcmp(argv[target_index], "--") == 0) {

            target_index++;

            break;
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
                "[StraceLite] No target program specified\n\n");

        print_usage(argv[0]);

        return 1;
    }


    /*
     * Launch target.
     *
     * The actual launch message is printed inside tracer.c.
     * This prevents duplicate output after fork().
     */
    return tracer_launch(&argv[target_index]);
}
