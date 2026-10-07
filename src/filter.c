#include "filter.h"
#include "syscall.h"

#include <string.h>

#define MAX_FILTERS 64
#define MAX_NAME_LENGTH 64

static char filters[MAX_FILTERS][MAX_NAME_LENGTH];
static size_t filter_count = 0;

/*
 * Category filter.
 *
 * UNKNOWN means that no category filter
 * has been configured.
 */
static SyscallCategory selected_category =
    SYSCALL_CATEGORY_UNKNOWN;


/*
 * ============================================================
 * Initialize filters
 * ============================================================
 */
void filter_init(void)
{
    filter_count = 0;

    selected_category = SYSCALL_CATEGORY_UNKNOWN;

    memset(filters, 0, sizeof(filters));
}


/*
 * ============================================================
 * Add syscall-name filter
 * ============================================================
 */
int filter_add(const char *name)
{
    if (name == NULL || name[0] == '\0') {
        return -1;
    }

    /*
     * Verify that the syscall exists.
     */
    int valid = 0;

    for (long number = 0; number < 512; number++) {

        const char *known_name =
            syscall_name(number);

        if (strcmp(known_name, name) == 0) {
            valid = 1;
            break;
        }
    }

    if (!valid) {
        return -1;
    }

    /*
     * Prevent duplicate entries.
     */
    for (size_t i = 0; i < filter_count; i++) {

        if (strcmp(filters[i], name) == 0) {
            return 0;
        }
    }

    if (filter_count >= MAX_FILTERS) {
        return -1;
    }

    strncpy(filters[filter_count],
            name,
            MAX_NAME_LENGTH - 1);

    filters[filter_count][MAX_NAME_LENGTH - 1] = '\0';

    filter_count++;

    return 0;
}


/*
 * ============================================================
 * Check syscall-name filter
 * ============================================================
 */
int filter_allows(const char *name)
{
    if (name == NULL) {
        return 0;
    }

    /*
     * No syscall-name filter means
     * every syscall passes this filter.
     */
    if (filter_count == 0) {
        return 1;
    }

    for (size_t i = 0; i < filter_count; i++) {

        if (strcmp(filters[i], name) == 0) {
            return 1;
        }
    }

    return 0;
}


/*
 * ============================================================
 * Check whether syscall-name filtering is enabled
 * ============================================================
 */
int filter_enabled(void)
{
    return filter_count > 0;
}


/*
 * ============================================================
 * Set category filter
 * ============================================================
 */
int filter_set_category(const char *category_name)
{
    if (category_name == NULL ||
        category_name[0] == '\0') {

        return -1;
    }

    /*
     * Match category names exactly.
     */
    if (strcmp(category_name, "FILE_IO") == 0) {

        selected_category =
            SYSCALL_CATEGORY_FILE_IO;

    } else if (strcmp(category_name, "MEMORY") == 0) {

        selected_category =
            SYSCALL_CATEGORY_MEMORY;

    } else if (strcmp(category_name, "PROCESS") == 0) {

        selected_category =
            SYSCALL_CATEGORY_PROCESS;

    } else if (strcmp(category_name, "NETWORK") == 0) {

        selected_category =
            SYSCALL_CATEGORY_NETWORK;

    } else if (strcmp(category_name, "SYSTEM") == 0) {

        selected_category =
            SYSCALL_CATEGORY_SYSTEM;

    } else {

        return -1;
    }

    return 0;
}


/*
 * ============================================================
 * Check whether category filtering is enabled
 * ============================================================
 */
int category_filter_enabled(void)
{
    return selected_category !=
           SYSCALL_CATEGORY_UNKNOWN;
}


/*
 * ============================================================
 * Check syscall against category filter
 * ============================================================
 */
int filter_category_allows(long syscall_number)
{
    /*
     * No category filter means everything passes.
     */
    if (!category_filter_enabled()) {
        return 1;
    }

    return syscall_category(syscall_number) ==
           selected_category;
}
