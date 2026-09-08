/*
 * eBPF-Powered Linux Runtime Threat Detection & EDR Agent
 * execve_monitor.bpf.c - Tracepoint probe for sys_enter_execve
 *
 * Intercepts process execution to capture PID, PPID, UID, GID,
 * executable filename, and command-line arguments.
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
 * Tracepoint handler for sys_enter_execve.
 * Captures process executions, parent lineage, and arguments.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    u32 zero = 0;
    struct edr_event_t *event = event_buffer_heap.lookup(&zero);
    if (!event)
        return 0;

    __builtin_memset(event, 0, sizeof(*event));
    struct task_struct *task;
    struct task_struct *parent;

    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = EVENT_TYPE_EXECVE;

    /* PID & TGID */
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    event->tgid = (u32)pid_tgid;

    /* UID & GID */
    u64 uid_gid = bpf_get_current_uid_gid();
    event->uid = (u32)uid_gid;
    event->gid = uid_gid >> 32;

    /* Process Comm (name) */
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    /* Extract Parent PID safely from task_struct */
    task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
        if (parent) {
            bpf_probe_read_kernel(&event->ppid, sizeof(event->ppid), &parent->tgid);
        }
    }

    /* Capture Executable Filename */
    if (args->filename) {
        bpf_probe_read_user_str(&event->payload.exec.filename, sizeof(event->payload.exec.filename), args->filename);
    }

    /* Capture Command-Line Arguments from argv */
    const char __user *const __user *argv = (const char __user *const __user *)args->argv;
    if (argv) {
        const char __user *arg0 = NULL;
        bpf_probe_read_user(&arg0, sizeof(arg0), &argv[0]);
        if (arg0) {
            bpf_probe_read_user_str(event->payload.exec.args, 256, arg0);
        }

        const char __user *arg1 = NULL;
        bpf_probe_read_user(&arg1, sizeof(arg1), &argv[1]);
        if (arg1) {
            #pragma unroll
            for (int i = 0; i < 250; i++) {
                if (event->payload.exec.args[i] == '\0') {
                    event->payload.exec.args[i] = ' ';
                    bpf_probe_read_user_str(&event->payload.exec.args[i + 1], 250, arg1);
                    break;
                }
            }
        }
    }

    event->payload.exec.retval = 0;

    /* Submit event to perf ring buffer */
    events.perf_submit(args, event, sizeof(*event));
    return 0;
}
