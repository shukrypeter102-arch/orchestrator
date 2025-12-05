// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
// Copyright (C) 2025 Meta Platforms, Inc. and affiliates. All rights reserved.
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Per-CPU context data type
struct per_cpu_ctx {
    // The time when the current task started running on this CPU.
    __u64 start_time;
    // The current pid running on this CPU.
    __u32 cur_pid;
    // The current frequency of the CPU.
    __u32 cur_freq;
};

// Global per-CPU per-pid busy time
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 16); // max CPUs
    __type(key, u32); // PID
    __array(
        values,
        struct {
            __uint(type, BPF_MAP_TYPE_ARRAY);
            __uint(max_entries, 32768); // max pid /proc/sys/kernel/pid_max
            __type(key, __u32); // pid
            __type(value, __u64); // execution time
    });
} time_maps SEC(".maps");

// Global per-CPU per-pid raw credit (busy time * frequency)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 16); // max CPUs
    __type(key, u32); // PID
    __array(
        values,
        struct {
            __uint(type, BPF_MAP_TYPE_ARRAY);
            __uint(max_entries, 32768); // max pid /proc/sys/kernel/pid_max
            __type(key, __u32); // pid
            __type(value, __u64); // raw credit
    });
} credit_maps SEC(".maps");

// Global per-CPU context data. Note that it's not stored as a per-CPU map since the value type is not primitive
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16); // max CPUs
    __type(key, u32); // CPU
    __type(value, struct per_cpu_ctx);
} per_cpu_ctxs SEC(".maps");

static inline void* get_local_time_map(int cpu) {
    return bpf_map_lookup_elem(&time_maps, &cpu);
}

static inline void* get_local_credit_map(int cpu) {
    return bpf_map_lookup_elem(&credit_maps, &cpu);
}

static inline struct per_cpu_ctx* get_local_cpu_ctx(int cpu) {
    return bpf_map_lookup_elem(&per_cpu_ctxs, &cpu);
}

// Take a snapshot of the current per-CPU context
static inline void update_per_cpu_ctx(struct per_cpu_ctx* ctx, u64 timestamp, u32 pid, u32 freq) {
    if (timestamp) ctx->start_time = timestamp;
    ctx->cur_pid = pid; // 0 is a valid pid and we always update the current pid
    if (freq) ctx->cur_freq = freq;
}

SEC("raw_tp/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct* prev, struct task_struct* next) {
    int cpu = bpf_get_smp_processor_id();
    u64 now = bpf_ktime_get_boot_ns();
    u32 prev_pid = 0, next_pid = 0;

    void* time_map = get_local_time_map(cpu);
    void* credit_map = get_local_credit_map(cpu);
    if (!time_map || !credit_map) {
        bpf_printk("sched_switch: time_map %llu or credit_map %llu is null", time_map, credit_map);
        return 0;
    }

    struct per_cpu_ctx* cpu_ctx = get_local_cpu_ctx(cpu);
    if (!cpu_ctx) {
        bpf_printk("sched_switch: cpu_ctx is null");
        return 0;
    }

    prev_pid = BPF_CORE_READ(prev, pid);
    if (cpu_ctx->cur_pid && prev_pid != cpu_ctx->cur_pid) {
        // If it's not the first event, we should have a consistently tracked pid
        bpf_printk("sched_switch %d: prev_pid %d != cur_pid %d", cpu, prev_pid, cpu_ctx->cur_pid);
    }
    next_pid = BPF_CORE_READ(next, pid);

    if (!prev_pid) {
        // We're coming out of idle state -- just record the start time and return
        goto sched_switch_exit;
    }

    if (!cpu_ctx->start_time) {
        // BPF just started without seeing any event. Record the start time and return
        goto sched_switch_exit;
    }

    u64 runtime = now - cpu_ctx->start_time;

    u64* curr_time_ptr = bpf_map_lookup_elem(time_map, &prev_pid);
    u64 curr_time = (curr_time_ptr ? *curr_time_ptr : 0);
    u64 new_time = curr_time + runtime;
    bpf_map_update_elem(time_map, &prev_pid, &new_time, BPF_ANY);

    if (!cpu_ctx->cur_freq) {
        // We don't have a frequency yet, so we can't calculate the credit.
        goto sched_switch_exit;
    }

    u64* curr_credit_ptr = bpf_map_lookup_elem(credit_map, &prev_pid);
    u64 curr_credit = (curr_credit_ptr ? *curr_credit_ptr : 0);
    u64 new_credit = curr_credit + runtime * cpu_ctx->cur_freq;
    bpf_map_update_elem(credit_map, &prev_pid, &new_credit, BPF_ANY);

sched_switch_exit:
    update_per_cpu_ctx(cpu_ctx, now, next_pid, 0); // Can't update frequency since there is no context
    return 0;
}

SEC("raw_tp/cpu_frequency")
int BPF_PROG(cpu_frequency, unsigned int frequency, unsigned int cpu_id) {
    // The CPU processing the event may not be the same as cpu_id
    u64 now = bpf_ktime_get_boot_ns();
    u32 prev_pid = 0;

    void* time_map = get_local_time_map(cpu_id);
    void* credit_map = get_local_credit_map(cpu_id);
    if (!time_map || !credit_map) {
        return 0;
    }

    struct per_cpu_ctx* cpu_ctx;
    cpu_ctx = get_local_cpu_ctx(cpu_id);
    if (!cpu_ctx) {
        return 0;
    }

    u64 runtime = now - cpu_ctx->start_time;
    prev_pid = cpu_ctx->cur_pid;

    if (!prev_pid) {
        /*
         * Either the current state is idle, or we haven't seen a sched_switch event yet.
         * In either case, just record the start time, frequency, and return.
         */
        goto cpu_frequency_exit;
    }

    if (!cpu_ctx->start_time) {
        // BPF just started without seeing any event. Record the start time and return
        goto cpu_frequency_exit;
    }

    // Always update the runtime since we update the start time
    u64* curr_time_ptr = bpf_map_lookup_elem(time_map, &prev_pid);
    u64 curr_time = (curr_time_ptr ? *curr_time_ptr : 0);
    u64 new_time = curr_time + runtime;
    bpf_map_update_elem(time_map, &prev_pid, &new_time, BPF_ANY);

    if (!cpu_ctx->cur_freq) {
        // We don't have any initial frequency. Can't calculate the credit.
        goto cpu_frequency_exit;
    }
    u64* curr_credit_ptr = bpf_map_lookup_elem(credit_map, &prev_pid);
    u64 curr_credit = (curr_credit_ptr ? *curr_credit_ptr : 0);
    u64 new_credit = curr_credit + runtime * cpu_ctx->cur_freq;
    bpf_map_update_elem(credit_map, &prev_pid, &new_credit, BPF_ANY);

cpu_frequency_exit:
    update_per_cpu_ctx(cpu_ctx, now, prev_pid, frequency); // prev_pid is actually never changed here
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
