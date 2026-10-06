#ifndef STRACELITE_STATS_H
#define STRACELITE_STATS_H

#include <stddef.h>

/*
 * Maximum number of Linux syscall numbers we track.
 *
 * x86-64 Linux currently uses syscall numbers well below this
 * range, but keeping some extra space makes the tracer safer.
 */
#define MAX_SYSCALLS 512

/*
 * Statistics for one syscall.
 */
typedef struct {
    unsigned long calls;
    unsigned long errors;
} SyscallStats;

/*
 * Reset all syscall statistics.
 */
void stats_reset(void);

/*
 * Record one syscall.
 *
 * syscall_number:
 *     Linux syscall number.
 *
 * return_value:
 *     Return value from the syscall.
 *
 * Negative return values represent errors on Linux.
 */
void stats_record(long syscall_number, long return_value);

/*
 * Print the final syscall statistics table.
 */
void stats_print(void);

#endif
