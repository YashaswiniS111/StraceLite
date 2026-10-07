#ifndef STRACELITE_FILTER_H
#define STRACELITE_FILTER_H

#include <stddef.h>

#define MAX_FILTERS 64
#define MAX_NAME_LENGTH 64

/*
 * Initialize the syscall filter.
 *
 * If no filter is configured,
 * all syscalls are allowed.
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
 * Check whether filtering is enabled.
 */
int filter_enabled(void);

/*
 * Configure filtering by syscall category.
 *
 * Returns:
 *   0  -> success
 *  -1  -> invalid category
 */
int filter_set_category(const char *category);

/*
 * Check whether a syscall belongs to
 * the currently selected category.
 *
 * Returns:
 *   1 -> allowed
 *   0 -> filtered
 */
int filter_category_allows(long syscall_number);

#endif
