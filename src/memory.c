#include "memory.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>

/*
 * Read one machine word from the tracee.
 *
 * PTRACE_PEEKDATA returns the word directly.
 * However, -1 is ambiguous because -1 can technically be
 * valid data. Therefore errno must be cleared before calling
 * ptrace() and checked afterward.
 */
int tracee_read_word(pid_t pid,
                     unsigned long address,
                     unsigned long *value)
{
    if (value == NULL) {
        errno = EINVAL;
        return -1;
    }

    errno = 0;

    long data = ptrace(PTRACE_PEEKDATA,
                       pid,
                       (void *)address,
                       NULL);

    if (data == -1 && errno != 0) {
        return -1;
    }

    *value = (unsigned long)data;

    return 0;
}

/*
 * Read a null-terminated string from the tracee.
 *
 * We read machine-word-sized chunks instead of attempting to
 * dereference the tracee's pointer directly. The tracer and
 * tracee are separate processes, so direct dereferencing would
 * be invalid.
 */
int tracee_read_string(pid_t pid,
                       unsigned long address,
                       char *buffer,
                       size_t max_length)
{
    if (buffer == NULL || max_length == 0) {
        errno = EINVAL;
        return -1;
    }

    size_t bytes_read = 0;

    /*
     * A Linux x86-64 machine word is 8 bytes.
     */
    const size_t word_size = sizeof(unsigned long);

    while (bytes_read < max_length - 1) {

        unsigned long word = 0;

        /*
         * Read the next word from the tracee.
         */
        if (tracee_read_word(pid,
                             address + bytes_read,
                             &word) == -1) {

            /*
             * Don't leave an unterminated string behind.
             */
            buffer[bytes_read] = '\0';
            return -1;
        }

        /*
         * Copy the bytes from the machine word into our
         * local buffer.
         */
        size_t remaining = max_length - 1 - bytes_read;

        size_t copy_size = word_size;

        if (copy_size > remaining) {
            copy_size = remaining;
        }

        memcpy(buffer + bytes_read,
               &word,
               copy_size);

        /*
         * Search the bytes we just copied for '\0'.
         */
        for (size_t i = 0; i < copy_size; i++) {

            if (buffer[bytes_read + i] == '\0') {
                return 0;
            }
        }

        bytes_read += copy_size;
    }

    /*
     * Always terminate our local buffer.
     */
    buffer[bytes_read] = '\0';

    /*
     * Reaching the limit is not a fatal ptrace error.
     * The string was simply truncated.
     */
    return 0;
}
