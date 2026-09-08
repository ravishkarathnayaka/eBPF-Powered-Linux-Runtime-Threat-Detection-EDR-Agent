/*
 * eBPF-Powered Linux Runtime Threat Detection & EDR Agent
 * network_monitor.bpf.c - Tracepoint probe for sys_enter_connect
 *
 * Intercepts outbound socket connection attempts to capture
 * destination IP address (IPv4/IPv6), destination port, PID, UID, and process.
 *
 * Uses BPF_PERCPU_ARRAY to safely handle event memory without
 * exceeding the strict 512-byte eBPF stack limit.
 *
 * Copyright (c) 2026 EDR Sensor Contributors
 * SPDX-License-Identifier: MIT
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include "include/common.h"

/* BPF Perf Ring Buffer map for streaming events to user-space */
BPF_PERF_OUTPUT(events);

/* Per-CPU heap array to bypass the 512-byte BPF stack limit */
BPF_PERCPU_ARRAY(event_buffer_heap, struct edr_event_t, 1);

/**
 * Tracepoint handler for sys_enter_connect.
 * Captures outbound TCP/UDP socket connections.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    if (!args->uservaddr)
        return 0;

    u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &args->uservaddr->sa_family);
    if (family != AF_INET && family != AF_INET6)
        return 0;

    u32 zero = 0;
    struct edr_event_t *event = event_buffer_heap.lookup(&zero);
    if (!event)
        return 0;

    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_CONNECT;

    /* PID & TGID */
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->tgid = (u32)pid_tgid;

    /* UID & GID */
    u64 uid_gid = bpf_get_current_uid_gid();
    event->uid = (u32)uid_gid;
    event->gid = uid_gid >> 32;

    /* Parent PID */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent = NULL;
        bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
        if (parent) {
            bpf_probe_read_kernel(&event->ppid, sizeof(event->ppid), &parent->tgid);
        }
    }

    /* Process Comm */
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    event->payload.net.family = family;
    event->payload.net.sock_fd = args->fd;
    event->payload.net.protocol = IPPROTO_TCP;

    if (family == AF_INET) {
        struct sockaddr_in sin = {};
        bpf_probe_read_user(&sin, sizeof(sin), args->uservaddr);
        u16 raw_port = sin.sin_port;
        event->payload.net.dport = ((raw_port >> 8) & 0x00FF) | ((raw_port & 0x00FF) << 8);
        event->payload.net.daddr_v4 = sin.sin_addr.s_addr;
    } else if (family == AF_INET6) {
        struct sockaddr_in6 sin6 = {};
        bpf_probe_read_user(&sin6, sizeof(sin6), args->uservaddr);
        u16 raw_port = sin6.sin6_port;
        event->payload.net.dport = ((raw_port >> 8) & 0x00FF) | ((raw_port & 0x00FF) << 8);
        bpf_probe_read_kernel(&event->payload.net.daddr_v6, sizeof(event->payload.net.daddr_v6), &sin6.sin6_addr.in6_u.u6_addr8);
    }

    /* Submit event to perf ring buffer */
    events.perf_submit(args, event, sizeof(*event));
    return 0;
}
