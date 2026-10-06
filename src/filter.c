#include "filter.h"
#include "syscall.h"

#include <string.h>

#define MAX_FILTERS 64
#define MAX_NAME_LENGTH 64

static char filters[MAX_FILTERS][MAX_NAME_LENGTH];
static size_t filter_count = 0;

void filter_init(void)
{
    filter_count = 0;

    memset(filters, 0, sizeof(filters));
}

int filter_add(const char *name)
{
    if (name == NULL || name[0] == '\0') {
        return -1;
    }

    /*
     * Verify that the syscall name actually exists.
     *
     * This prevents commands such as:
     *
     *     --filter hello,world
     *
     * from silently producing no output.
     */
    int valid = 0;

    for (long number = 0; number < 512; number++) {

        const char *known_name = syscall_name(number);

        if (strcmp(known_name, name) == 0) {
            valid = 1;
            break;
        }
    }

    if (!valid) {
        return -1;
    }

    /*
     * Prevent the same syscall from being added twice.
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

int filter_allows(const char *name)
{
    if (name == NULL) {
        return 0;
    }

    /*
     * No filters means everything is allowed.
     */
    if (filter_count == 0) {
        return 1;
    }

    /*
     * When filters are configured,
     * only explicitly selected syscalls are shown.
     */
    for (size_t i = 0; i < filter_count; i++) {

        if (strcmp(filters[i], name) == 0) {
            return 1;
        }
    }

    return 0;
}

int filter_enabled(void)
{
    return filter_count > 0;
}
