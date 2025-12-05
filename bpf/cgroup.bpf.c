// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
// Copyright (C) 2025 Meta Platforms, Inc. and affiliates. All rights reserved.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// The underlying cgroup name is from kernfs name [1] The name is dynamic allocated so we
// just take the first 25 bytes. This is because memflow/orchestrator only cares about
// cgroupv2 hierarchies. Which are always in the format: "uid_{uid}/pid_{pid}" [2].
// So we can calculate the max string length of these hierarchies.
//  * Max PID: 32768
//  * Max UID: 4294967294
//  * Max Path: strlen("/uid_4294967294/pid_32768\0"): 26
//
// [1]: https://elixir.bootlin.com/linux/v5.5.19/source/include/linux/kernfs.h#L129
// [2]: https://fburl.com/code/bhn3pxar
#define CG_NAME_LEN   26

#define EVENT_CGROUP_MKDIR 1
#define EVENT_CGROUP_ATTACH 2
#define EVENT_CGROUP_RMDIR 3
#define EVENT_SCHED_EXEC 4
#define EVENT_SCHED_EXIT 5

// cgroupv2 hierarchies are in the format "/uid_{uid}/pid_{pid}" [1]. We
// can use this to filter out cgroupv1 hierarchies, therefore reducing
// the number of event we submit to the ring buffer and therefore the
// chance of overruning the ring buffer.
//
// [1]: https://fburl.com/code/bhn3pxar
static const char CGROUPV2_PREFIX[] = "/uid_";

static __inline int strncmp(const char *s1, const char *s2, u32 n) {
    for (u32 i = 0; i < n; i++) {
        const unsigned char c1 = (unsigned char) s1[i];
        const unsigned char c2 = (unsigned char) s2[i];

        if (c1 != c2) {
            return c1 - c2;
        }

        if (c1 == '\0') {
            break;
        }
    }

    return 0;
}

// Check if the path is a cgroupv2 hierarchy
static __inline bool is_cgroupv2_path(const char *path) {
    char path_local[CG_NAME_LEN];
    bpf_probe_read_kernel_str(path_local , sizeof(path_local), path);
    return strncmp(path_local, CGROUPV2_PREFIX, sizeof(CGROUPV2_PREFIX) - 1) == 0;
}

struct event {
    // Used to identify the union below
    u8 event_id;
    union {
        // EVENT_CGROUP_MKDIR
        //
        // This event tracks when a new directory is created within
        // a cgroup. This is important because on Android, we create a new
        // cgroupv2 hierarchy for each process in the format "uid_{uid}/pid_{pid}" [1].
        //
        // Note: This event is fired for both cgroupv1 and cgroupv2 directories. The hierarchy
        // of cgroupv1 controllers is relatively static however we still need to filter them
        // out in userspace.
        //
        // [1]: https://fburl.com/code/bhn3pxar
        struct {
            char path[CG_NAME_LEN];
        } cgroup_mkdir;

        // EVENT_CGROUP_ATTACH
        //
        // This event tracks when a process is "attached" or "enrolled" in a cgroup.
        // This fires for both cgroupv1 and cgroupv2. We can cross reference the inode
        // published in EVENT_CGROUP_MKDIR with the one in this event to determine if the
        // attach event is for a cgroupv1 or cgroupv2 hierarchy.
        //
        // For cgroupv2 hierarchies, both services and Android applications will have uid = 0 when 
        // attach is issued. For Android applications, this is a quirk since when the cgroup is 
        // created in zygote running as uid = 0, it also writes the pid to the cgroup [1]. For services, 
        // they are launched from init and will attach to the cgroup with uid = 0 before calling 
        // setuid. We have to wait for the execv syscall [2] since the last thing the init process 
        // will do is call SetProcessAttributesAndCaps, which sets the uid and then calls exec.
        //
        // [1]: https://fburl.com/code/l3uljg3r
        // [2]: https://fburl.com/code/gtybugxt
        struct {
            char path[CG_NAME_LEN];
            u32 pid;
        } cgroup_attach;

        // EVENT_CGROUP_RMDIR
        //
        // This event tracks when a directory is destroyed within a cgroup. Just like with
        // EVENT_CGROUP_MKDIR, Android will remove a cgroupv2 hierarchy when the process
        // exits. Once reclaimed, the inode can be used again so it is important to process
        // these events in-order to maintain consistency.
        //
        // [1]: https://fburl.com/code/venf5w7i
        struct {
            char path[CG_NAME_LEN];
        } cgroup_rmdir;

        // EVENT_SCHED_EXEC
        //
        // This event tracks when the execv and company syscall are called. This should only
        // be called for services and Android Core OS components (zygote, system_service, etc).
        // When this is called, the uid, exe, and other attributes of the process should be fully
        // populated.
        struct {
            u32 uid;
            u32 pid;
        } sched_exec;

        // EVENT_SCHED_EXIT
        //
        // This event tracks when a process exits. This applies to both Android applications and
        // services and should be received prior to the EVENT_CGROUP_RMDIR. There are cases where
        // libprocessgroup will fail to remove the cgroupv2 directory so this is a better way of tracking
        // when a process is dead and should no longer be enrolled in any policy.
        struct {
            u32 uid;
            u32 pid;
        } sched_exit;
    };
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16384 /* four pages */);
} events SEC(".maps");

SEC("raw_tracepoint/cgroup_mkdir")
int BPF_PROG(cgroup_mkdir, struct cgroup *cgrp, const char *path)
{
    // Filter out cgroupv1 hierarchies
    if (!is_cgroupv2_path(path)) {
        return 0;
    }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->event_id = EVENT_CGROUP_MKDIR;
    bpf_probe_read_kernel_str(&e->cgroup_mkdir.path , sizeof(e->cgroup_mkdir.path), path);
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("raw_tracepoint/cgroup_attach_task")
int BPF_PROG(cgroup_attach_task, struct cgroup *dst_cgroup, const char *path,
             struct task_struct *leader, bool threadgroup)
{
    const pid_t pid = BPF_CORE_READ(leader, pid);
    const pid_t tgid = BPF_CORE_READ(leader, tgid);

    // Only care about threadgroup leaders (processes not threads)
    if (tgid != pid || !threadgroup)
        return 0;

    // Filter out cgroupv1 hierarchies
    if (!is_cgroupv2_path(path)) {
        return 0;
    }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->event_id = EVENT_CGROUP_ATTACH;
    bpf_probe_read_kernel_str(&e->cgroup_attach.path , sizeof(e->cgroup_attach.path), path);
    e->cgroup_attach.pid = tgid;
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("raw_tracepoint/cgroup_rmdir")
int BPF_PROG(cgroup_rmdir, struct cgroup *cgrp, const char *path)
{
    // Filter out cgroupv1 hierarchies
    if (!is_cgroupv2_path(path)) {
        return 0;
    }

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->event_id = EVENT_CGROUP_RMDIR;
    bpf_probe_read_kernel_str(&e->cgroup_rmdir.path , sizeof(e->cgroup_rmdir.path), path);
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("raw_tracepoint/sched_process_exec")
int BPF_PROG(sched_process_exec, struct task_struct *task, pid_t old_pid,
            struct linux_binprm *bprm)
{
    const pid_t pid = BPF_CORE_READ(task, pid);
    const pid_t tgid = BPF_CORE_READ(task, tgid);
    const uid_t uid = BPF_CORE_READ(task, real_cred, uid).val;

    // Only care about threadgroup leaders (processes not threads)
    if (tgid != pid)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->event_id = EVENT_SCHED_EXEC;
    e->sched_exec.uid = uid;
    e->sched_exec.pid = tgid;
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("raw_tracepoint/sched_process_exit")
int BPF_PROG(sched_process_exit, struct task_struct *task)
{
    pid_t tgid = BPF_CORE_READ(task, group_leader, pid);
    const uid_t uid = BPF_CORE_READ(task, real_cred, uid).val;
    const atomic_t live = BPF_CORE_READ(task, signal, live);

    // Only care when the last thread exits
    if (live.counter != 0)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->event_id = EVENT_SCHED_EXIT;
    e->sched_exit.uid = uid;
    e->sched_exit.pid = tgid;
    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
