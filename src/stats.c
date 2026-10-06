#include "stats.h"
#include "syscall.h"

#include <stdio.h>

/*
 * Global syscall statistics table.
 *
 * Index:
 *     syscall number
 *
 * Value:
 *     number of calls and errors
 */
static SyscallStats syscall_stats[MAX_SYSCALLS];

/*
 * Reset all statistics.
 */
void stats_reset(void)
{
    for (int i = 0; i < MAX_SYSCALLS; i++) {
        syscall_stats[i].calls = 0;
        syscall_stats[i].errors = 0;
    }
}

/*
 * Record a syscall.
 */
void stats_record(long syscall_number, long return_value)
{
    /*
     * Ignore invalid syscall numbers.
     */
    if (syscall_number < 0 ||
        syscall_number >= MAX_SYSCALLS) {
        return;
    }

    syscall_stats[syscall_number].calls++;

    /*
     * Linux system calls return negative values when an error
     * occurs.
     */
    if (return_value < 0) {
        syscall_stats[syscall_number].errors++;
    }
}

/*
 * Print statistics.
 */
void stats_print(void)
{
    unsigned long total_calls = 0;
    unsigned long total_errors = 0;

    printf("\n");
    printf("========== Syscall Summary ==========\n\n");

    printf("%-18s %8s %8s\n",
           "Syscall",
           "Calls",
           "Errors");

    printf("--------------------------------------\n");

    for (int i = 0; i < MAX_SYSCALLS; i++) {

        if (syscall_stats[i].calls == 0) {
            continue;
        }

        const char *name = syscall_name(i);

        printf("%-18s %8lu %8lu\n",
               name,
               syscall_stats[i].calls,
               syscall_stats[i].errors);

        total_calls += syscall_stats[i].calls;
        total_errors += syscall_stats[i].errors;
    }

    printf("--------------------------------------\n");

    printf("%-18s %8lu %8lu\n",
           "Total",
           total_calls,
           total_errors);

    printf("======================================\n");
}
