/*
 * eBPF-Powered Linux Runtime Threat Detection & EDR Agent
 * openat_monitor.bpf.c - Tracepoint probe for sys_enter_openat
 *
 * Intercepts file open and creation operations to detect unauthorized access
 * to sensitive system files (e.g., /etc/shadow, /root/.ssh, /etc/sudoers).
 *
 * Uses BPF_PERCPU_ARRAY to safely handle event memory without
 * exceeding the strict 512-byte eBPF stack limit.
 *
 * Copyright (c) 2026 EDR Sensor Contributors
 * SPDX-License-Identifier: MIT
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include "include/common.h"

/* BPF Perf Ring Buffer map for streaming events to user-space */
BPF_PERF_OUTPUT(events);

/* Per-CPU heap array to bypass the 512-byte BPF stack limit */
BPF_PERCPU_ARRAY(event_buffer_heap, struct edr_event_t, 1);

/**
 * Tracepoint handler for sys_enter_openat.
 * Captures file open operations and flags.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    if (!args->filename)
        return 0;

    u32 zero = 0;
    struct edr_event_t *event = event_buffer_heap.lookup(&zero);
    if (!event)
        return 0;

    __builtin_memset(event, 0, sizeof(*event));

    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_OPENAT;

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

    /* Openat fields */
    event->payload.openat.dfd = (int32_t)args->dfd;
    event->payload.openat.flags = (int32_t)args->flags;
    event->payload.openat.retval = 0;

    bpf_probe_read_user_str(&event->payload.openat.filepath, sizeof(event->payload.openat.filepath), args->filename);

    /* Submit event to perf ring buffer */
    events.perf_submit(args, event, sizeof(*event));
    return 0;
}
