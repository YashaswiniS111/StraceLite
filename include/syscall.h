#ifndef STRACELITE_SYSCALL_H
#define STRACELITE_SYSCALL_H

/*
 * Return the name of a Linux x86-64 syscall.
 */
const char *syscall_name(long syscall_number);

/*
 * Categories used by StraceLite.
 */
typedef enum {
    SYSCALL_CATEGORY_UNKNOWN = 0,
    SYSCALL_CATEGORY_FILE_IO,
    SYSCALL_CATEGORY_MEMORY,
    SYSCALL_CATEGORY_PROCESS,
    SYSCALL_CATEGORY_NETWORK,
    SYSCALL_CATEGORY_SYSTEM
} SyscallCategory;

/*
 * Return the category of a syscall.
 */
SyscallCategory syscall_category(long syscall_number);

/*
 * Return a printable category name.
 */
const char *syscall_category_name(SyscallCategory category);

#endif
