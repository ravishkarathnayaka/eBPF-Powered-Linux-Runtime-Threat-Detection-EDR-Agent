/*
 * eBPF-Powered Linux Runtime Threat Detection & EDR Agent
 * execve_monitor.bpf.c - Tracepoint probe for sys_enter_execve
 *
 * Intercepts process execution to capture PID, PPID, UID, GID,
 * executable filename, and command-line arguments.
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

/**
 * Tracepoint handler for sys_enter_execve.
 * Captures process executions, parent lineage, and arguments.
 */
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct edr_event_t event = {};
    struct task_struct *task;
    struct task_struct *parent;

    event.timestamp_ns = bpf_ktime_get_ns();
    event.event_type = EVENT_TYPE_EXECVE;

    /* PID & TGID */
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.tgid = (u32)pid_tgid;

    /* UID & GID */
    u64 uid_gid = bpf_get_current_uid_gid();
    event.uid = (u32)uid_gid;
    event.gid = uid_gid >> 32;

    /* Process Comm (name) */
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    /* Extract Parent PID safely from task_struct */
    task = (struct task_struct *)bpf_get_current_task();
    if (task) {
        bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
        if (parent) {
            bpf_probe_read_kernel(&event.ppid, sizeof(event.ppid), &parent->tgid);
        }
    }

    /* Capture Executable Filename */
    if (args->filename) {
        bpf_probe_read_user_str(&event.payload.exec.filename, sizeof(event.payload.exec.filename), args->filename);
    }

    /* Capture First Command-Line Arguments from argv */
    const char __user *const __user *argv = (const char __user *const __user *)args->argv;
    if (argv) {
        const char __user *argp = NULL;
        /* Read argv[0] */
        bpf_probe_read_user(&argp, sizeof(argp), &argv[0]);
        if (argp) {
            bpf_probe_read_user_str(&event.payload.exec.args, sizeof(event.payload.exec.args), argp);
        }
        
        /* Read argv[1] and append if space allows */
        const char __user *arg1 = NULL;
        bpf_probe_read_user(&arg1, sizeof(arg1), &argv[1]);
        if (arg1) {
            char arg1_buf[128] = {};
            bpf_probe_read_user_str(arg1_buf, sizeof(arg1_buf), arg1);
            
            /* Simple delimiter append in string buffer if space exists */
            #pragma unroll
            for (int i = 0; i < MAX_ARGS_LEN - 130; i++) {
                if (event.payload.exec.args[i] == '\0') {
                    event.payload.exec.args[i] = ' ';
                    #pragma unroll
                    for (int j = 0; j < 127; j++) {
                        if (arg1_buf[j] == '\0') {
                            event.payload.exec.args[i + 1 + j] = '\0';
                            break;
                        }
                        event.payload.exec.args[i + 1 + j] = arg1_buf[j];
                    }
                    break;
                }
            }
        }
    }

    event.payload.exec.retval = 0;

    /* Submit event to perf ring buffer */
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
