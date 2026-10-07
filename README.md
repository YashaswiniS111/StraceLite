# StraceLite

A lightweight Linux system-call tracer written in C using the `ptrace` API.

StraceLite is a mini `strace`-like debugging and tracing tool designed to observe system calls made by Linux processes, decode syscall information, trace child processes, monitor signals, collect statistics, and filter syscall output.

---

## Features

### System Call Tracing
- Traces system calls using `ptrace`.
- Detects syscall entry and exit boundaries.
- Displays syscall numbers and names.
- Displays syscall return values.
- Displays `errno` information for failed system calls.

### Syscall Decoding
- Decodes Linux x86-64 syscall numbers.
- Displays syscall names.
- Displays syscall register information.
- Decodes selected syscall arguments.
- Decodes the executable path passed to `execve`.

### Tracee Memory Decoding
- Reads memory from the traced process.
- Supports reading machine words.
- Supports reading strings from tracee memory.
- Used for decoding syscall arguments such as paths.

### Statistics
- Counts observed system calls.
- Tracks syscall errors.
- Generates a syscall summary table after tracing.

### Syscall Filtering
Filter tracing output by syscall name.

Example:

```bash
./build/stracelite --filter read,write /bin/echo hello
