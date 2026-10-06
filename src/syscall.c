#include "syscall.h"

#include <stddef.h>

typedef struct {
    long number;
    const char *name;
} syscall_entry_t;

/*
 * Linux x86-64 syscall numbers.
 *
 * This table contains the commonly encountered syscalls
 * needed by StraceLite's initial decoder.
 */
static const syscall_entry_t syscall_table[] = {
    {0,   "read"},
    {1,   "write"},
    {2,   "open"},
    {3,   "close"},
    {4,   "stat"},
    {5,   "fstat"},
    {6,   "lstat"},
    {7,   "poll"},
    {8,   "lseek"},
    {9,   "mmap"},
    {10,  "mprotect"},
    {11,  "munmap"},
    {12,  "brk"},
    {13,  "rt_sigaction"},
    {14,  "rt_sigprocmask"},
    {15,  "rt_sigreturn"},
    {16,  "ioctl"},
    {17,  "pread64"},
    {18,  "pwrite64"},
    {19,  "readv"},
    {20,  "writev"},
    {21,  "access"},
    {22,  "pipe"},
    {23,  "select"},
    {24,  "sched_yield"},
    {25,  "mremap"},
    {26,  "msync"},
    {27,  "mincore"},
    {28,  "madvise"},
    {29,  "shmget"},
    {30,  "shmat"},
    {31,  "shmctl"},
    {32,  "dup"},
    {33,  "dup2"},
    {34,  "pause"},
    {35,  "nanosleep"},
    {36,  "getitimer"},
    {37,  "alarm"},
    {38,  "setitimer"},
    {39,  "getpid"},
    {40,  "sendfile"},
    {41,  "socket"},
    {42,  "connect"},
    {43,  "accept"},
    {44,  "sendto"},
    {45,  "recvfrom"},
    {46,  "sendmsg"},
    {47,  "recvmsg"},
    {48,  "shutdown"},
    {49,  "bind"},
    {50,  "listen"},
    {51,  "getsockname"},
    {52,  "getpeername"},
    {53,  "socketpair"},
    {54,  "setsockopt"},
    {55,  "getsockopt"},
    {56,  "clone"},
    {57,  "fork"},
    {58,  "vfork"},
    {59,  "execve"},
    {60,  "exit"},
    {61,  "wait4"},
    {62,  "kill"},
    {63,  "uname"},
    {64,  "semget"},
    {65,  "semop"},
    {66,  "semctl"},
    {67,  "shmdt"},
    {68,  "msgget"},
    {69,  "msgsnd"},
    {70,  "msgrcv"},
    {71,  "msgctl"},
    {72,  "fcntl"},
    {73,  "flock"},
    {74,  "fsync"},
    {75,  "fdatasync"},
    {76,  "truncate"},
    {77,  "ftruncate"},
    {78,  "getdents"},
    {79,  "getcwd"},
    {80,  "chdir"},
    {81,  "fchdir"},
    {82,  "rename"},
    {83,  "mkdir"},
    {84,  "rmdir"},
    {85,  "creat"},
    {86,  "link"},
    {87,  "unlink"},
    {88,  "symlink"},
    {89,  "readlink"},
    {90,  "chmod"},
    {91,  "fchmod"},
    {92,  "chown"},
    {93,  "fchown"},
    {94,  "lchown"},
    {95,  "umask"},
    {96,  "gettimeofday"},
    {97,  "getrlimit"},
    {98,  "getrusage"},
    {99,  "sysinfo"},
    {100, "times"},
    {101, "ptrace"},
    {102, "getuid"},
    {103, "syslog"},
    {104, "getgid"},
    {105, "setuid"},
    {106, "setgid"},
    {107, "geteuid"},
    {108, "getegid"},
    {109, "setpgid"},
    {110, "getppid"},
    {111, "getpgrp"},
    {112, "setsid"},
    {113, "setreuid"},
    {114, "setregid"},
    {115, "getgroups"},
    {116, "setgroups"},
    {117, "setresuid"},
    {118, "getresuid"},
    {119, "setresgid"},
    {120, "getresgid"},
    {121, "getpgid"},
    {122, "setfsuid"},
    {123, "setfsgid"},
    {124, "getsid"},
    {125, "capget"},
    {126, "capset"},
    {127, "rt_sigpending"},
    {128, "rt_sigtimedwait"},
    {129, "rt_sigqueueinfo"},
    {130, "rt_sigsuspend"},
    {131, "sigaltstack"},
    {132, "utime"},
    {133, "mknod"},
    {134, "uselib"},
    {135, "personality"},
    {136, "ustat"},
    {137, "statfs"},
    {138, "fstatfs"},
    {139, "sysfs"},
    {140, "getpriority"},
    {141, "setpriority"},
    {142, "sched_setparam"},
    {143, "sched_getparam"},
    {144, "sched_setscheduler"},
    {145, "sched_getscheduler"},
    {146, "sched_get_priority_max"},
    {147, "sched_get_priority_min"},
    {148, "sched_rr_get_interval"},
    {149, "mlock"},
    {150, "munlock"},
    {151, "mlockall"},
    {152, "munlockall"},
    {153, "vhangup"},
    {154, "modify_ldt"},
    {155, "pivot_root"},
    {156, "_sysctl"},
    {157, "prctl"},
    {158, "arch_prctl"},
    {159, "adjtimex"},
    {160, "setrlimit"},
    {161, "chroot"},
    {162, "sync"},
    {163, "acct"},
    {164, "settimeofday"},
    {165, "mount"},
    {166, "umount2"},
    {167, "swapon"},
    {168, "swapoff"},
    {169, "reboot"},
    {170, "sethostname"},
    {171, "setdomainname"},
    {172, "iopl"},
    {173, "ioperm"},
    {174, "create_module"},
    {175, "init_module"},
    {176, "delete_module"},
    {177, "get_kernel_syms"},
    {178, "query_module"},
    {179, "quotactl"},
    {180, "nfsservctl"},
    {181, "getpmsg"},
    {182, "putpmsg"},
    {183, "afs_syscall"},
    {184, "tuxcall"},
    {185, "security"},
    {186, "gettid"},
    {187, "readahead"},
    {188, "setxattr"},
    {189, "lsetxattr"},
    {190, "fsetxattr"},
    {191, "getxattr"},
    {192, "lgetxattr"},
    {193, "fgetxattr"},
    {194, "listxattr"},
    {195, "llistxattr"},
    {196, "flistxattr"},
    {197, "removexattr"},
    {198, "lremovexattr"},
    {199, "fremovexattr"},
    {200, "tkill"},
    {201, "time"},
    {202, "futex"},
    {203, "sched_setaffinity"},
    {204, "sched_getaffinity"},
    {205, "set_thread_area"},
    {206, "io_setup"},
    {207, "io_destroy"},
    {208, "io_getevents"},
    {209, "io_submit"},
    {210, "io_cancel"},
    {211, "get_thread_area"},
    {212, "lookup_dcookie"},
    {213, "epoll_create"},
    {214, "epoll_ctl_old"},
    {215, "epoll_wait_old"},
    {216, "remap_file_pages"},
    {217, "getdents64"},
    {218, "set_tid_address"},
    {219, "restart_syscall"},
    {220, "semtimedop"},
    {221, "fadvise64"},
    {222, "timer_create"},
    {223, "timer_settime"},
    {224, "timer_gettime"},
    {225, "timer_getoverrun"},
    {226, "timer_delete"},
    {227, "clock_settime"},
    {228, "clock_gettime"},
    {229, "clock_getres"},
    {230, "clock_nanosleep"},
    {231, "exit_group"},
    {232, "epoll_wait"},
    {233, "epoll_ctl"},
    {234, "tgkill"},
    {235, "utimes"},
    {236, "vserver"},
    {237, "mbind"},
    {238, "set_mempolicy"},
    {239, "get_mempolicy"},
    {240, "mq_open"},
    {241, "mq_unlink"},
    {242, "mq_timedsend"},
    {243, "mq_timedreceive"},
    {244, "mq_notify"},
    {245, "mq_getsetattr"},
    {246, "kexec_load"},
    {247, "waitid"},
    {248, "add_key"},
    {249, "request_key"},
    {250, "keyctl"},
    {251, "ioprio_set"},
    {252, "ioprio_get"},
    {253, "inotify_init"},
    {254, "inotify_add_watch"},
    {255, "inotify_rm_watch"},
    {256, "migrate_pages"},
    {257, "openat"},
    {258, "mkdirat"},
    {259, "mknodat"},
    {260, "fchownat"},
    {261, "futimesat"},
    {262, "newfstatat"},
    {263, "unlinkat"},
    {264, "renameat"},
    {265, "linkat"},
    {266, "symlinkat"},
    {267, "readlinkat"},
    {268, "fchmodat"},
    {269, "faccessat"},
    {270, "pselect6"},
    {271, "ppoll"},
    {272, "unshare"},
    {273, "set_robust_list"},
    {274, "get_robust_list"},
    {275, "splice"},
    {276, "tee"},
    {277, "sync_file_range"},
    {278, "vmsplice"},
    {279, "move_pages"},
    {280, "utimensat"},
    {281, "epoll_pwait"},
    {282, "signalfd"},
    {283, "timerfd_create"},
    {284, "eventfd"},
    {285, "fallocate"},
    {286, "timerfd_settime"},
    {287, "timerfd_gettime"},
    {288, "accept4"},
    {289, "signalfd4"},
    {290, "eventfd2"},
    {291, "epoll_create1"},
    {292, "dup3"},
    {293, "pipe2"},
    {294, "inotify_init1"},
    {295, "preadv"},
    {296, "pwritev"},
    {297, "rt_tgsigqueueinfo"},
    {298, "perf_event_open"},
    {299, "recvmmsg"},
    {300, "fanotify_init"},
    {301, "fanotify_mark"},
    {302, "prlimit64"},
    {303, "name_to_handle_at"},
    {304, "open_by_handle_at"},
    {305, "clock_adjtime"},
    {306, "syncfs"},
    {307, "sendmmsg"},
    {308, "setns"},
    {309, "getcpu"},
    {310, "process_vm_readv"},
    {311, "process_vm_writev"},
    {312, "kcmp"},
    {313, "finit_module"},
    {314, "sched_setattr"},
    {315, "sched_getattr"},
    {316, "renameat2"},
    {317, "seccomp"},
    {318, "getrandom"},
    {319, "memfd_create"},
    {320, "kexec_file_load"},
    {321, "bpf"},
    {322, "execveat"},
    {323, "socket"},
    {324, "socketpair"},
    {325, "setsockopt"},
    {326, "getsockopt"},
    {327, "io_setup"},
    {328, "io_destroy"},
    {329, "io_submit"},
    {330, "io_cancel"},
    {331, "io_getevents"},
    {332, "mincore"},
    {333, "madvise"},
    {334, "remap_file_pages"},
    {335, "mbind"},
    {336, "get_mempolicy"},
    {337, "set_mempolicy"},
    {338, "migrate_pages"},
    {339, "move_pages"},
    {340, "rt_tgsigqueueinfo"},
    {341, "perf_event_open"},
    {342, "accept4"},
    {343, "recvmmsg"},
    {344, "arch_prctl"},
    {345, "clock_gettime"},
    {346, "clock_getres"},
    {347, "clock_nanosleep"},
    {348, "exit_group"},
    {349, "epoll_wait"},
    {350, "epoll_ctl"},
    {351, "epoll_create1"},
    {352, "dup3"},
    {353, "pipe2"},
    {354, "inotify_init1"},
    {355, "preadv2"},
    {356, "pwritev2"},
    {357, "pkey_mprotect"},
    {358, "pkey_alloc"},
    {359, "pkey_free"},
    {360, "statx"},
    {361, "io_pgetevents"},
    {362, "rseq"},
    {363, "u2022"},
    {364, "pidfd_send_signal"},
    {365, "io_uring_setup"},
    {366, "io_uring_enter"},
    {367, "io_uring_register"},
    {368, "open_tree"},
    {369, "move_mount"},
    {370, "fsopen"},
    {371, "fsconfig"},
    {372, "fsmount"},
    {373, "fspick"},
    {374, "pidfd_open"},
    {375, "clone3"},
    {376, "close_range"},
    {377, "openat2"},
    {378, "pidfd_getfd"},
    {379, "faccessat2"},
    {380, "process_madvise"},
    {381, "epoll_pwait2"},
    {382, "mount_setattr"},
    {383, "quotactl_fd"},
    {384, "landlock_create_ruleset"},
    {385, "landlock_add_rule"},
    {386, "landlock_restrict_self"},
    {387, "memfd_secret"},
    {388, "process_mrelease"},
    {389, "futex_waitv"},
    {390, "set_mempolicy_home_node"},
    {391, "cachestat"},
    {392, "fchmodat2"},
    {393, "map_shadow_stack"},
    {394, "futex_wake"},
    {395, "futex_wait"},
    {396, "futex_requeue"},
    {397, "statmount"},
    {398, "listmount"},
    {399, "lsm_get_self_attr"},
    {400, "lsm_set_self_attr"},
    {401, "lsm_list_modules"}
};

const char *syscall_name(long syscall_number)
{
    size_t count = sizeof(syscall_table) / sizeof(syscall_table[0]);

    for (size_t i = 0; i < count; i++) {
        if (syscall_table[i].number == syscall_number) {
            return syscall_table[i].name;
        }
    }

    return "unknown";
}
/*
 * Classify commonly encountered syscalls.
 */
SyscallCategory syscall_category(long syscall_number)
{
    switch (syscall_number) {

        /*
         * File I/O
         */
        case 0:    /* read */
        case 1:    /* write */
        case 2:    /* open */
        case 3:    /* close */
        case 4:    /* stat */
        case 5:    /* fstat */
        case 6:    /* lstat */
        case 17:   /* pread64 */
        case 18:   /* pwrite64 */
        case 19:   /* readv */
        case 20:   /* writev */
        case 21:   /* access */
        case 72:   /* fcntl */
        case 73:   /* flock */
        case 74:   /* fsync */
        case 75:   /* fdatasync */
        case 78:   /* getdents */
        case 79:   /* getcwd */
        case 80:   /* chdir */
        case 81:   /* fchdir */
        case 87:   /* unlink */
        case 89:   /* readlink */
        case 257:  /* openat */
        case 262:  /* newfstatat */
        case 263:  /* unlinkat */
        case 267:  /* readlinkat */
        case 217:  /* getdents64 */
            return SYSCALL_CATEGORY_FILE_IO;

        /*
         * Memory management.
         */
        case 9:    /* mmap */
        case 10:   /* mprotect */
        case 11:   /* munmap */
        case 12:   /* brk */
        case 25:   /* mremap */
        case 26:   /* msync */
        case 27:   /* mincore */
        case 28:   /* madvise */
        case 149:  /* mlock */
        case 150:  /* munlock */
        case 151:  /* mlockall */
        case 152:  /* munlockall */
        case 216:  /* remap_file_pages */
            return SYSCALL_CATEGORY_MEMORY;

        /*
         * Process/thread management.
         */
        case 39:   /* getpid */
        case 56:   /* clone */
        case 57:   /* fork */
        case 58:   /* vfork */
        case 59:   /* execve */
        case 60:   /* exit */
        case 61:   /* wait4 */
        case 62:   /* kill */
        case 110:  /* getppid */
        case 186:  /* gettid */
        case 231:  /* exit_group */
        case 234:  /* tgkill */
        case 273:  /* set_robust_list */
        case 274:  /* get_robust_list */
        case 435:  /* clone3 */
            return SYSCALL_CATEGORY_PROCESS;

        /*
         * Networking.
         */
        case 41:   /* socket */
        case 42:   /* connect */
        case 43:   /* accept */
        case 44:   /* sendto */
        case 45:   /* recvfrom */
        case 46:   /* sendmsg */
        case 47:   /* recvmsg */
        case 48:   /* shutdown */
        case 49:   /* bind */
        case 50:   /* listen */
        case 51:   /* getsockname */
        case 52:   /* getpeername */
        case 53:   /* socketpair */
        case 54:   /* setsockopt */
        case 55:   /* getsockopt */
        case 288:  /* accept4 */
        case 299:  /* recvmmsg */
        case 307:  /* sendmmsg */
            return SYSCALL_CATEGORY_NETWORK;

        /*
         * General system operations.
         */
        case 13:   /* rt_sigaction */
        case 14:   /* rt_sigprocmask */
        case 16:   /* ioctl */
        case 96:   /* gettimeofday */
        case 97:   /* getrlimit */
        case 98:   /* getrusage */
        case 99:   /* sysinfo */
        case 158:  /* arch_prctl */
        case 202:  /* futex */
        case 218:  /* set_tid_address */
        case 302:  /* prlimit64 */
        case 318:  /* getrandom */
            return SYSCALL_CATEGORY_SYSTEM;

        default:
            return SYSCALL_CATEGORY_UNKNOWN;
    }
}

/*
 * Convert category enum into printable text.
 */
const char *syscall_category_name(SyscallCategory category)
{
    switch (category) {

        case SYSCALL_CATEGORY_FILE_IO:
            return "FILE_IO";

        case SYSCALL_CATEGORY_MEMORY:
            return "MEMORY";

        case SYSCALL_CATEGORY_PROCESS:
            return "PROCESS";

        case SYSCALL_CATEGORY_NETWORK:
            return "NETWORK";

        case SYSCALL_CATEGORY_SYSTEM:
            return "SYSTEM";

        default:
            return "UNKNOWN";
    }
}
