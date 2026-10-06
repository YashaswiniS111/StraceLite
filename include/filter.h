#ifndef STRACELITE_FILTER_H
#define STRACELITE_FILTER_H

#include <stddef.h>

/*
 * Initialize the syscall filter.
 *
 * If no filter is configured, all syscalls are allowed.
 */
void filter_init(void);

/*
 * Add a syscall name to the filter.
 *
 * Returns:
 *   0  -> success
 *  -1  -> failure
 */
int filter_add(const char *name);

/*
 * Check whether a syscall should be displayed.
 *
 * Returns:
 *   1 -> allowed
 *   0 -> filtered
 */
int filter_allows(const char *name);

/*
 * Check whether filtering is currently enabled.
 */
int filter_enabled(void);

#endif
