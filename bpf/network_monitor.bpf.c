/*
 * eBPF-Powered Linux Runtime Threat Detection & EDR Agent
 * network_monitor.bpf.c - Tracepoint probe for sys_enter_connect
 *
 * Intercepts outbound socket connection attempts to capture
 * destination IP address (IPv4/IPv6), destination port, PID, UID, and process.
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

/**
 * Tracepoint handler for sys_enter_connect.
 * Captures outbound TCP/UDP socket connections.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct edr_event_t event = {};
    struct sockaddr_in sin = {};
    struct sockaddr_in6 sin6 = {};
    u16 family = 0;

    if (!args->uservaddr)
        return 0;

    /* Read address family */
    bpf_probe_read_user(&family, sizeof(family), &args->uservaddr->sa_family);

    /* Only handle AF_INET (IPv4 = 2) and AF_INET6 (IPv6 = 10) */
    if (family != AF_INET && family != AF_INET6)
        return 0;

    event.timestamp_ns = bpf_ktime_get_ns();
    event.event_type = EVENT_TYPE_CONNECT;

    /* PID & TGID */
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.tgid = (u32)pid_tgid;

    /* UID & GID */
    u64 uid_gid = bpf_get_current_uid_gid();
    event.uid = (u32)uid_gid;
    event.gid = uid_gid >> 32;

    /* Parent PID */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        struct task_struct *parent = NULL;
        bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
        if (parent) {
            bpf_probe_read_kernel(&event.ppid, sizeof(event.ppid), &parent->tgid);
        }
    }

    /* Process Comm */
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    event.payload.net.family = family;
    event.payload.net.sock_fd = args->fd;
    event.payload.net.protocol = IPPROTO_TCP;

    if (family == AF_INET) {
        bpf_probe_read_user(&sin, sizeof(sin), args->uservaddr);
        /* Convert port from network byte order (big-endian) to host byte order */
        u16 raw_port = sin.sin_port;
        event.payload.net.dport = ((raw_port >> 8) & 0x00FF) | ((raw_port & 0x00FF) << 8);
        event.payload.net.daddr_v4 = sin.sin_addr.s_addr;
    } else if (family == AF_INET6) {
        bpf_probe_read_user(&sin6, sizeof(sin6), args->uservaddr);
        u16 raw_port = sin6.sin6_port;
        event.payload.net.dport = ((raw_port >> 8) & 0x00FF) | ((raw_port & 0x00FF) << 8);
        bpf_probe_read_kernel(&event.payload.net.daddr_v6, sizeof(event.payload.net.daddr_v6), &sin6.sin6_addr.in6_u.u6_addr8);
    }

    /* Submit event to perf ring buffer */
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
