#ifndef STRACELITE_MEMORY_H
#define STRACELITE_MEMORY_H

#include <stddef.h>
#include <sys/types.h>

/*
 * Read one machine word from the tracee's address space.
 *
 * Returns:
 *   0  -> success
 *  -1  -> failure
 */
int tracee_read_word(pid_t pid, unsigned long address,
                     unsigned long *value);

/*
 * Read a null-terminated string from the tracee.
 *
 * The result is stored in buffer.
 *
 * max_length prevents the tracer from reading indefinitely if
 * the tracee memory does not contain a terminating '\0'.
 *
 * Returns:
 *   0  -> success
 *  -1  -> failure
 */
int tracee_read_string(pid_t pid,
                       unsigned long address,
                       char *buffer,
                       size_t max_length);

#endif
