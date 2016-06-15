#ifndef __SYSCALL_H__
#define __SYSCALL_H__
/* 
 * Taken from /inux/x86_64/syscallent.h in strace: 
 *  http://strace.git.sourceforge.net 
 */

typedef struct 
{
    int num_params;
    char *name_syscall;
    char *name_libc;
} syscallent;


syscallent syscall_table[] = 
{
    { 3, "sys_read",               "read"          },  /* 0 */
    { 3, "sys_write",              "write"         },  /* 1 */
    { 3, "sys_open",               "open"          },  /* 2 */
    { 1, "sys_close",              "close"         },  /* 3 */
    { 2, "sys_stat",               "stat"          },  /* 4 */
    { 2, "sys_fstat",              "fstat"         },  /* 5 */
    { 2, "sys_lstat",              "lstat"         },  /* 6 */
    { 3, "sys_poll",               "poll"          },  /* 7 */
    { 3, "sys_lseek",              "lseek"         },  /* 8 */
    { 6, "sys_mmap",               "mmap"          },  /* 9 */
    { 3, "sys_mprotect",           "mprotect"      },  /* 10 */
    { 2, "sys_munmap",             "munmap"        },  /* 11 */
    { 1, "sys_brk",                "brk"           },  /* 12 */
    { 4, "sys_rt_sigaction",       "rt_sigaction"  },  /* 13 */
    { 4, "sys_rt_sigprocmask",     "rt_sigprocmask"},  /* 14 */
    { 0, "sys_rt_sigreturn",       "rt_sigreturn"  },  /* 15 */
    { 3, "sys_ioctl",              "ioctl"         },  /* 16 */
    { 4, "sys_pread",              "pread"         },  /* 17 */
    { 4, "sys_pwrite",             "pwrite"        },  /* 18 */
    { 3, "sys_readv",              "readv"         },  /* 19 */
    { 3, "sys_writev",             "writev"        },  /* 20 */
    { 2, "sys_access",             "access"        },  /* 21 */
    { 1, "sys_pipe",               "pipe"          },  /* 22 */
    { 5, "sys_select",             "select"        },  /* 23 */
    { 0, "sys_sched_yield",        "sched_yield"   },  /* 24 */
    { 5, "sys_mremap",             "mremap"        },  /* 25 */
    { 3, "sys_msync",              "msync"         },  /* 26 */
    { 3, "sys_mincore",            "mincore"       },  /* 27 */
    { 3, "sys_madvise",            "madvise"       },  /* 28 */
    { 4, "sys_shmget",             "shmget"        },  /* 29 */
    { 4, "sys_shmat",              "shmat"         },  /* 30 */
    { 4, "sys_shmctl",             "shmctl"        },  /* 31 */
    { 1, "sys_dup",                "dup"           },  /* 32 */
    { 2, "sys_dup2",               "dup2"          },  /* 33 */
    { 0, "sys_pause",              "pause"         },  /* 34 */
    { 2, "sys_nanosleep",          "nanosleep"     },  /* 35 */
    { 2, "sys_getitimer",          "getitimer"     },  /* 36 */
    { 1, "sys_alarm",              "alarm"         },  /* 37 */
    { 3, "sys_setitimer",          "setitimer"     },  /* 38 */
    { 0, "sys_getpid",             "getpid"        },  /* 39 */
    { 4, "sys_sendfile64",         "sendfile"      },  /* 40 */
    { 3, "sys_socket",             "socket"        },  /* 41 */
    { 3, "sys_connect",            "connect"       },  /* 42 */
    { 3, "sys_accept",             "accept"        },  /* 43 */
    { 6, "sys_sendto",             "sendto"        },  /* 44 */
    { 6, "sys_recvfrom",           "recvfrom"      },  /* 45 */
    { 3, "sys_sendmsg",            "sendmsg"       },  /* 46 */
    { 3, "sys_recvmsg",            "recvmsg"       },  /* 47 */
    { 2, "sys_shutdown",           "shutdown"      },  /* 48 */
    { 3, "sys_bind",               "bind"          },  /* 49 */
    { 2, "sys_listen",             "listen"        },  /* 50 */
    { 3, "sys_getsockname",        "getsockname"   },  /* 51 */
    { 3, "sys_getpeername",        "getpeername"   },  /* 52 */
    { 4, "sys_socketpair",         "socketpair"    },  /* 53 */
    { 5, "sys_setsockopt",         "setsockopt"    },  /* 54 */
    { 5, "sys_getsockopt",         "getsockopt"    },  /* 55 */
    { 5, "sys_clone",              "clone"         },  /* 56 */
    { 0, "sys_fork",               "fork"          },  /* 57 */
    { 0, "sys_vfork",              "vfork"         },  /* 58 */
    { 3, "sys_execve",             "execve"        },  /* 59 */
    { 1, "sys_exit",               "_exit"         },  /* 60 */
    { 4, "sys_wait4",              "wait4"         },  /* 61 */
    { 2, "sys_kill",               "kill"          },  /* 62 */
    { 1, "sys_uname",              "uname"         },  /* 63 */
    { 4, "sys_semget",             "semget"        },  /* 64 */
    { 4, "sys_semop",              "semop"         },  /* 65 */
    { 4, "sys_semctl",             "semctl"        },  /* 66 */
    { 4, "sys_shmdt",              "shmdt"         },  /* 67 */
    { 4, "sys_msgget",             "msgget"        },  /* 68 */
    { 4, "sys_msgsnd",             "msgsnd"        },  /* 69 */
    { 5, "sys_msgrcv",             "msgrcv"        },  /* 70 */
    { 3, "sys_msgctl",             "msgctl"        },  /* 71 */
    { 3, "sys_fcntl",              "fcntl"         },  /* 72 */
    { 2, "sys_flock",              "flock"         },  /* 73 */
    { 1, "sys_fsync",              "fsync"         },  /* 74 */
    { 1, "sys_fdatasync",          "fdatasync"     },  /* 75 */
    { 2, "sys_truncate",           "truncate"      },  /* 76 */
    { 2, "sys_ftruncate",          "ftruncate"     },  /* 77 */
    { 3, "sys_getdents",           "getdents"      },  /* 78 */
    { 2, "sys_getcwd",             "getcwd"        },  /* 79 */
    { 1, "sys_chdir",              "chdir"         },  /* 80 */
    { 1, "sys_fchdir",             "fchdir"        },  /* 81 */
    { 2, "sys_rename",             "rename"        },  /* 82 */
    { 2, "sys_mkdir",              "mkdir"         },  /* 83 */
    { 1, "sys_rmdir",              "rmdir"         },  /* 84 */
    { 2, "sys_creat",              "creat"         },  /* 85 */
    { 2, "sys_link",               "link"          },  /* 86 */
    { 1, "sys_unlink",             "unlink"        },  /* 87 */
    { 2, "sys_symlink",            "symlink"       },  /* 88 */
    { 3, "sys_readlink",           "readlink"      },  /* 89 */
    { 2, "sys_chmod",              "chmod"         },  /* 90 */
    { 2, "sys_fchmod",             "fchmod"        },  /* 91 */
    { 3, "sys_chown",              "chown"         },  /* 92 */
    { 3, "sys_fchown",             "fchown"        },  /* 93 */
    { 3, "sys_chown",              "lchown"        },  /* 94 */
    { 1, "sys_umask",              "umask"         },  /* 95 */
    { 2, "sys_gettimeofday",       "gettimeofday"  },  /* 96 */
    { 2, "sys_getrlimit",          "getrlimit"     },  /* 97 */
    { 2, "sys_getrusage",          "getrusage"     },  /* 98 */
    { 1, "sys_sysinfo",            "sysinfo"       },  /* 99 */
    { 1, "sys_times",              "times"         },  /* 100 */
    { 4, "sys_ptrace",             "ptrace"        },  /* 101 */
    { 0, "sys_getuid",             "getuid"        },  /* 102 */
    { 3, "sys_syslog",             "syslog"        },  /* 103 */
    { 0, "sys_getgid",             "getgid"        },  /* 104 */
    { 1, "sys_setuid",             "setuid"        },  /* 105 */
    { 1, "sys_setgid",             "setgid"        },  /* 106 */
    { 0, "sys_geteuid",            "geteuid"       },  /* 107 */
    { 0, "sys_getegid",            "getegid"       },  /* 108 */
    { 2, "sys_setpgid",            "setpgid"       },  /* 109 */
    { 0, "sys_getppid",            "getppid"       },  /* 110 */
    { 0, "sys_getpgrp",            "getpgrp"       },  /* 111 */
    { 0, "sys_setsid",             "setsid"        },  /* 112 */
    { 2, "sys_setreuid",           "setreuid"      },  /* 113 */
    { 2, "sys_setregid",           "setregid"      },  /* 114 */
    { 2, "sys_getgroups",          "getgroups"     },  /* 115 */
    { 2, "sys_setgroups",          "setgroups"     },  /* 116 */
    { 3, "sys_setresuid",          "setresuid"     },  /* 117 */
    { 3, "sys_getresuid",          "getresuid"     },  /* 118 */
    { 3, "sys_setresgid",          "setresgid"     },  /* 119 */
    { 3, "sys_getresgid",          "getresgid"     },  /* 120 */
    { 1, "sys_getpgid",            "getpgid"       },  /* 121 */
    { 1, "sys_setfsuid",           "setfsuid"      },  /* 122 */
    { 1, "sys_setfsgid",           "setfsgid"      },  /* 123 */
    { 1, "sys_getsid",             "getsid"        },  /* 124 */
    { 2, "sys_capget",             "capget"        },  /* 125 */
    { 2, "sys_capset",             "capset"        },  /* 126 */
    { 2, "sys_rt_sigpending",      "rt_sigpending" },  /* 127 */
    { 4, "sys_rt_sigtimedwait",    "rt_sigtimedwait"       },  /* 128 */
    { 3, "sys_rt_sigqueueinfo",    "rt_sigqueueinfo"       },  /* 129 */
    { 2, "sys_rt_sigsuspend",      "rt_sigsuspend" },  /* 130 */
    { 2, "sys_sigaltstack",        "sigaltstack"   },  /* 131 */
    { 2, "sys_utime",              "utime"         },  /* 132 */
    { 3, "sys_mknod",              "mknod"         },  /* 133 */
    { 1, "sys_uselib",             "uselib"        },  /* 134 */
    { 1, "sys_personality",        "personality"   },  /* 135 */
    { 2, "sys_ustat",              "ustat"         },  /* 136 */
    { 2, "sys_statfs",             "statfs"        },  /* 137 */
    { 2, "sys_fstatfs",            "fstatfs"       },  /* 138 */
    { 3, "sys_sysfs",              "sysfs"         },  /* 139 */
    { 2, "sys_getpriority",        "getpriority"   },  /* 140 */
    { 3, "sys_setpriority",        "setpriority"   },  /* 141 */
    { 0, "sys_sched_setparam",     "sched_setparam"        },  /* 142 */
    { 2, "sys_sched_getparam",     "sched_getparam"        },  /* 143 */
    { 3, "sys_sched_setscheduler", "sched_setscheduler"    },  /* 144 */
    { 1, "sys_sched_getscheduler", "sched_getscheduler"    },  /* 145 */
    { 1, "sys_sched_get_priority_max",     "sched_get_priority_max"        },  /* 146 */
    { 1, "sys_sched_get_priority_min",     "sched_get_priority_min"        },  /* 147 */
    { 2, "sys_sched_rr_get_interval",      "sched_rr_get_interval" },  /* 148 */
    { 2, "sys_mlock",              "mlock"         },  /* 149 */
    { 2, "sys_munlock",            "munlock"       },  /* 150 */
    { 1, "sys_mlockall",           "mlockall"      },  /* 151 */
    { 0, "sys_munlockall",         "munlockall"    },  /* 152 */
    { 0, "sys_vhangup",            "vhangup"       },  /* 153 */
    { 3, "sys_modify_ldt",         "modify_ldt"    },  /* 154 */
    { 2, "sys_pivotroot",          "pivot_root"    },  /* 155 */
    { 1, "sys_sysctl",             "_sysctl"       },  /* 156 */
    { 5, "sys_prctl",              "prctl"         },  /* 157 */
    { 2, "sys_arch_prctl",         "arch_prctl"    },  /* 158 */
    { 1, "sys_adjtimex",           "adjtimex"      },  /* 159 */
    { 2, "sys_setrlimit",          "setrlimit"     },  /* 160 */
    { 1, "sys_chroot",             "chroot"        },  /* 161 */
    { 0, "sys_sync",               "sync"          },  /* 162 */
    { 1, "sys_acct",               "acct"          },  /* 163 */
    { 2, "sys_settimeofday",       "settimeofday"  },  /* 164 */
    { 5, "sys_mount",              "mount"         },  /* 165 */
    { 2, "sys_umount2",            "umount"        }, /* 166 */
    { 2, "sys_swapon",             "swapon"        },  /* 167 */
    { 1, "sys_swapoff",            "swapoff"       },  /* 168 */
    { 4, "sys_reboot",             "reboot"        },  /* 169 */
    { 2, "sys_sethostname",        "sethostname"   },  /* 170 */
    { 2, "sys_setdomainname",      "setdomainname" },  /* 171 */
    { 1, "sys_iopl",               "iopl"          },  /* 172 */
    { 3, "sys_ioperm",             "ioperm"        },  /* 173 */
    { 2, "sys_create_module",      "create_module" },  /* 174 */
    { 3, "sys_init_module",        "init_module"   },  /* 175 */
    { 2, "sys_delete_module",      "delete_module" },  /* 176 */
    { 1, "sys_get_kernel_syms",    "get_kernel_syms"},  /* 177 */
    { 5, "sys_query_module",       "query_module"  },  /* 178 */
    { 4, "sys_quotactl",           "quotactl"      },  /* 179 */
    { 3, "sys_nfsservctl",         "nfsservctl"    },  /* 180 */
    { 5, "sys_getpmsg",            "getpmsg"       }, /* 181 */
    { 5, "sys_putpmsg",            "putpmsg"       }, /* 182 */
    { 5, "sys_afs_syscall",        "afs_syscall"   },  /* 183 */
    { 3, "sys_tuxcall",            "tuxcall"       }, /* 184 */
    { 3, "sys_security",           "security"      }, /* 185 */
    { 0, "sys_gettid",             "gettid"        }, /* 186 */
    { 3, "sys_readahead",          "readahead"     }, /* 187 */
    { 5, "sys_setxattr",           "setxattr"      }, /* 188 */
    { 5, "sys_setxattr",           "lsetxattr"     }, /* 189 */
    { 5, "sys_fsetxattr",          "fsetxattr"     }, /* 190 */
    { 4, "sys_getxattr",           "getxattr"      }, /* 191 */
    { 4, "sys_getxattr",           "lgetxattr"     }, /* 192 */
    { 4, "sys_fgetxattr",          "fgetxattr"     }, /* 193 */
    { 3, "sys_listxattr",          "listxattr"     }, /* 194 */
    { 3, "sys_listxattr",          "llistxattr"    }, /* 195 */
    { 3, "sys_flistxattr",         "flistxattr"    }, /* 196 */
    { 2, "sys_removexattr",        "removexattr"   }, /* 197 */
    { 2, "sys_removexattr",        "lremovexattr"  }, /* 198 */
    { 2, "sys_fremovexattr",       "fremovexattr"  }, /* 199 */
    { 2, "sys_kill",               "tkill"         }, /* 200 */
    { 1, "sys_time",               "time"          },  /* 201 */
    { 6, "sys_futex",              "futex"         }, /* 202 */
    { 3, "sys_sched_setaffinity",  "sched_setaffinity" },/* 203 */
    { 3, "sys_sched_getaffinity",  "sched_getaffinity" },/* 204 */
    { 1, "sys_set_thread_area",    "set_thread_area" }, /* 205 */
    { 2, "sys_io_setup",           "io_setup"      }, /* 206 */
    { 1, "sys_io_destroy",         "io_destroy"    }, /* 207 */
    { 5, "sys_io_getevents",       "io_getevents"  }, /* 208 */
    { 3, "sys_io_submit",          "io_submit"     }, /* 209 */
    { 3, "sys_io_cancel",          "io_cancel"     }, /* 210 */
    { 1, "sys_get_thread_area",    "get_thread_area" }, /* 211 */
    { 3, "sys_lookup_dcookie",     "lookup_dcookie"}, /* 212 */
    { 1, "sys_epoll_create",       "epoll_create"  }, /* 213 */
    { 4, "printargs",              "epoll_ctl_old" }, /* 214 */
    { 4, "printargs",              "epoll_wait_old"}, /* 215 */
    { 5, "sys_remap_file_pages",   "remap_file_pages"}, /* 216 */
    { 3, "sys_getdents64",         "getdents64"    }, /* 217 */
    { 1, "sys_set_tid_address",    "set_tid_address"}, /* 218 */
    { 0, "sys_restart_syscall",    "restart_syscall"}, /* 219 */
    { 5, "sys_semtimedop",         "semtimedop"    }, /* 220 */
    { 4, "sys_fadvise64",          "fadvise64"     }, /* 221 */
    { 3, "sys_timer_create",       "timer_create"  }, /* 222 */
    { 4, "sys_timer_settime",      "timer_settime" }, /* 223 */
    { 2, "sys_timer_gettime",      "timer_gettime" }, /* 224 */
    { 1, "sys_timer_getoverrun",   "timer_getoverrun"}, /* 225 */
    { 1, "sys_timer_delete",       "timer_delete"  }, /* 226 */
    { 2, "sys_clock_settime",      "clock_settime" }, /* 227 */
    { 2, "sys_clock_gettime",      "clock_gettime" }, /* 228 */
    { 2, "sys_clock_getres",       "clock_getres"  }, /* 229 */
    { 4, "sys_clock_nanosleep",    "clock_nanosleep"}, /* 230 */
    { 1, "sys_exit",               "exit_group"    }, /* 231 */
    { 4, "sys_epoll_wait",         "epoll_wait"    }, /* 232 */
    { 4, "sys_epoll_ctl",          "epoll_ctl"     }, /* 233 */
    { 3, "sys_tgkill",             "tgkill"        }, /* 234 */
    { 2, "sys_utimes",             "utimes"        }, /* 235 */
    { 5, "sys_vserver",            "vserver"       }, /* 236 */
    { 6, "sys_mbind",              "mbind"         }, /* 237 */
    { 3, "sys_set_mempolicy",      "set_mempolicy" }, /* 238 */
    { 5, "sys_get_mempolicy",      "get_mempolicy" }, /* 239 */
    { 4, "sys_mq_open",            "mq_open"       }, /* 240 */
    { 1, "sys_mq_unlink",          "mq_unlink"     }, /* 241 */
    { 5, "sys_mq_timedsend",       "mq_timedsend"  }, /* 242 */
    { 5, "sys_mq_timedreceive",    "mq_timedreceive" }, /* 243 */
    { 2, "sys_mq_notify",          "mq_notify"     }, /* 244 */
    { 3, "sys_mq_getsetattr",      "mq_getsetattr" }, /* 245 */
    { 4, "sys_kexec_load",         "kexec_load"    }, /* 246 */
    { 5, "sys_waitid",             "waitid"        }, /* 247 */
    { 5, "sys_add_key",            "add_key"       }, /* 248 */
    { 4, "sys_request_key",        "request_key"   }, /* 249 */
    { 5, "sys_keyctl",             "keyctl"        }, /* 250 */
    { 3, "sys_ioprio_set",         "ioprio_set"    }, /* 251 */
    { 2, "sys_ioprio_get",         "ioprio_get"    }, /* 252 */
    { 0, "sys_inotify_init",       "inotify_init"  }, /* 253 */
    { 3, "sys_inotify_add_watch",  "inotify_add_watch" }, /* 254 */
    { 2, "sys_inotify_rm_watch",   "inotify_rm_watch" }, /* 255 */
    { 4, "sys_migrate_pages",      "migrate_pages" }, /* 256 */
    { 4, "sys_openat",             "openat"        }, /* 257 */
    { 3, "sys_mkdirat",            "mkdirat"       }, /* 258 */
    { 4, "sys_mknodat",            "mknodat"       }, /* 259 */
    { 5, "sys_fchownat",           "fchownat"      }, /* 260 */
    { 3, "sys_futimesat",          "futimesat"     }, /* 261 */
    { 4, "sys_newfstatat",         "newfstatat"    }, /* 262 */
    { 3, "sys_unlinkat",           "unlinkat"      }, /* 263 */
    { 4, "sys_renameat",           "renameat"      }, /* 264 */
    { 5, "sys_linkat",             "linkat"        }, /* 265 */
    { 3, "sys_symlinkat",          "symlinkat"     }, /* 266 */
    { 4, "sys_readlinkat",         "readlinkat"    }, /* 267 */
    { 3, "sys_fchmodat",           "fchmodat"      }, /* 268 */
    { 3, "sys_faccessat",          "faccessat"     }, /* 269 */
    { 6, "sys_pselect6",           "pselect6"      }, /* 270 */
    { 5, "sys_ppoll",              "ppoll"         }, /* 271 */
    { 1, "sys_unshare",            "unshare"       }, /* 272 */
    { 2, "sys_set_robust_list",    "set_robust_list" }, /* 273 */
    { 3, "sys_get_robust_list",    "get_robust_list" }, /* 274 */
    { 6, "sys_splice",             "splice"        }, /* 275 */
    { 4, "sys_tee",                "tee"           }, /* 276 */
    { 4, "sys_sync_file_range",    "sync_file_range" }, /* 277 */
    { 4, "sys_vmsplice",           "vmsplice"      }, /* 278 */
    { 6, "sys_move_pages",         "move_pages"    }, /* 279 */
    { 4, "sys_utimensat",          "utimensat"     }, /* 280 */
    { 6, "sys_epoll_pwait",        "epoll_pwait"   }, /* 281 */
    { 3, "sys_signalfd",           "signalfd"      }, /* 282 */
    { 2, "sys_timerfd_create",     "timerfd_create"}, /* 283 */
    { 1, "sys_eventfd",            "eventfd"       }, /* 284 */
    { 4, "sys_fallocate",          "fallocate"     }, /* 285 */
    { 4, "sys_timerfd_settime",    "timerfd_settime"}, /* 286 */
    { 2, "sys_timerfd_gettime",    "timerfd_gettime"}, /* 287 */
    { 4, "sys_accept4",            "accept4"       }, /* 288 */
    { 4, "sys_signalfd4",          "signalfd4"     }, /* 289 */
    { 2, "sys_eventfd2",           "eventfd2"      }, /* 290 */
    { 1, "sys_epoll_create1",      "epoll_create1" }, /* 291 */
    { 3, "sys_dup3",               "dup3"          }, /* 292 */
    { 2, "sys_pipe2",              "pipe2"         }, /* 293 */
    { 1, "sys_inotify_init1",      "inotify_init1" }, /* 294 */
    { 4, "sys_preadv",             "preadv"        }, /* 295 */
    { 4, "sys_pwritev",            "pwritev"       }, /* 296 */
    { 4, "sys_rt_tgsigqueueinfo",  "rt_tgsigqueueinfo"}, /* 297 */
    { 5, "sys_perf_event_open",    "perf_event_open"}, /* 298 */
    { 5, "sys_recvmmsg",           "recvmmsg"      }, /* 299 */
    { 2, "sys_fanotify_init",      "fanotify_init" }, /* 300 */
    { 5, "sys_fanotify_mark",      "fanotify_mark" }, /* 301 */
    { 4, "sys_prlimit64",          "prlimit64"     }, /* 302 */
    { 5, "sys_name_to_handle_at",  "name_to_handle_at"}, /* 303 */
    { 3, "sys_open_by_handle_at",  "open_by_handle_at"}, /* 304 */
    { 2, "sys_clock_adjtime",      "clock_adjtime" }, /* 305 */
    { 1, "sys_syncfs",             "syncfs"        }, /* 306 */
    { 4, "sys_sendmmsg",           "sendmmsg"      }, /* 307 */
    { 2, "sys_setns",              "setns"         }, /* 308 */
    { 3, "sys_getcpu",             "getcpu"        }, /* 309 */
    { 6, "sys_process_vm_readv",   "process_vm_readv"      }, /* 310 */
    { 6, "sys_process_vm_writev",  "process_vm_writev"     }, /* 311 */
    { 5, "sys_kcmp",               "kcmp"          }, /* 312 */
    { 3, "sys_finit_module",       "finit_module"  }, /* 313 */
};

#endif
