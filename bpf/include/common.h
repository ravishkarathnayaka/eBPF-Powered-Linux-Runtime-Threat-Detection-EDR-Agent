/*
 * eBPF-Powered Linux Runtime Threat Detection & EDR Agent
 * common.h - Shared data structures between kernel and user-space
 *
 * Copyright (c) 2026 EDR Sensor Contributors
 * SPDX-License-Identifier: MIT
 */

#ifndef __EDR_COMMON_H__
#define __EDR_COMMON_H__

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

/* Constants */
#define TASK_COMM_LEN       16
#define MAX_FILENAME_LEN    256
#define MAX_ARGS_LEN        512
#define MAX_PATH_LEN        256

/* Event Type Identifiers */
enum event_type {
    EVENT_TYPE_UNKNOWN   = 0,
    EVENT_TYPE_EXECVE    = 1,
    EVENT_TYPE_CONNECT   = 2,
    EVENT_TYPE_PTRACE    = 3,
    EVENT_TYPE_OPENAT    = 4
};

/* PTRACE Request Constants (mirrored from <sys/ptrace.h>) */
#define EDR_PTRACE_TRACEME         0
#define EDR_PTRACE_PEEKTEXT        1
#define EDR_PTRACE_PEEKDATA        2
#define EDR_PTRACE_PEEKUSER        3
#define EDR_PTRACE_POKETEXT        4
#define EDR_PTRACE_POKEDATA        5
#define EDR_PTRACE_POKEUSER        6
#define EDR_PTRACE_CONT            7
#define EDR_PTRACE_KILL            8
#define EDR_PTRACE_SINGLESTEP      9
#define EDR_PTRACE_ATTACH          16
#define EDR_PTRACE_DETACH          17
#define EDR_PTRACE_GETREGS         12
#define EDR_PTRACE_SETREGS         13
#define EDR_PTRACE_SEIZE           0x4206

/* Unified EDR Event Structure sent through BPF perf ring buffer */
struct edr_event_t {
    /* Event Header */
    uint64_t timestamp_ns;
    uint32_t event_type;       /* enum event_type */
    uint32_t pid;              /* Process ID */
    uint32_t tgid;             /* Thread Group ID */
    uint32_t ppid;             /* Parent Process ID */
    uint32_t uid;              /* User ID */
    uint32_t gid;              /* Group ID */
    char comm[TASK_COMM_LEN];  /* Process name */

    /* Union for event-specific payloads */
    union {
        /* Execve Payload */
        struct {
            char filename[MAX_FILENAME_LEN];
            char args[MAX_ARGS_LEN];
            int32_t retval;
        } exec;

        /* Network Connect Payload */
        struct {
            uint16_t family;      /* AF_INET = 2, AF_INET6 = 10 */
            uint16_t dport;       /* Destination Port (Host Byte Order) */
            uint16_t sport;       /* Source Port (Host Byte Order) */
            uint16_t protocol;    /* IPPROTO_TCP = 6, IPPROTO_UDP = 17 */
            uint32_t daddr_v4;    /* Destination IPv4 (Network Byte Order) */
            uint32_t saddr_v4;    /* Source IPv4 (Network Byte Order) */
            uint8_t daddr_v6[16]; /* Destination IPv6 */
            uint8_t saddr_v6[16]; /* Source IPv6 */
            int32_t sock_fd;
        } net;

        /* Ptrace Payload */
        struct {
            int64_t request;      /* PTRACE_ATTACH, PTRACE_POKETEXT, etc. */
            uint32_t target_pid;  /* Target Process ID */
            uint64_t addr;        /* Memory address */
            uint64_t data;        /* Data value */
        } ptrace;

        /* Openat Payload */
        struct {
            char filepath[MAX_PATH_LEN];
            int32_t flags;        /* O_RDONLY, O_WRONLY, O_RDWR, etc. */
            int32_t dfd;          /* Directory file descriptor */
            int32_t retval;
        } openat;
    } payload;
};

#endif /* __EDR_COMMON_H__ */
