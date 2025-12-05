// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
// Copyright (C) 2025 Meta Platforms, Inc. and affiliates. All rights reserved.
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <core_fixes.bpf.h>

#include "credits.bpf.h"

// #define USE_BPF_SPIN_LOCK when used we get 'tracing progs cannot
// #use bpf_spin_lock yet' in the logs. Our critical sections being
// #unprotected may lead to some accounting errors, but the error is
// #probably not a big deal in practice.

typedef struct {
    uint64_t last_time;
    u32 last_pwrlevel;
    u32 padding;
#ifdef USE_BPF_SPIN_LOCK
    struct bpf_spin_lock mux;
#endif
} GlobalData;

// A map containing a single entry of |GlobalData|.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, GlobalData);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} gpu_tis_global_data SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, kMaxPids);
    __type(key, PidGpuIdUid);
    __type(value, NsPerPwrLevel);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} gpu_uid_time_in_state_map SEC(".maps");

// map pwrlevel -> Residency at power level
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PWRLEVELS + 1);
    __type(key, u32);
    __type(value, BpfStateResidency);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} gpu_time_in_state_map SEC(".maps");

// Map to track pid -> PidGpuIdUid for efficient cleanup on process exit
// Currently this is a 1:1 mapping but if we have multiple GPUs in the future, we will extend this
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, kMaxPids);
    __type(key, u32); // pid
    __type(value, PidGpuIdUid);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pid_to_gpu_map SEC(".maps");

//  /sys/kernel/tracing/events/power/gpu_work_period/
typedef struct {
    // Actual fields start at offset 8.
    uint64_t common;

    // A value that uniquely identifies the GPU within the system.
    u32 gpu_id;

    // The UID of the application (i.e. persistent, unique ID of the Android
    // app) that submitted work to the GPU.
    u32 uid;

    // The start time of the period in nanoseconds. The clock must be
    // CLOCK_MONOTONIC_RAW, as returned by the ktime_get_raw_ns(void) function.
    uint64_t start_time_ns;

    // The end time of the period in nanoseconds. The clock must be
    // CLOCK_MONOTONIC_RAW, as returned by the ktime_get_raw_ns(void) function.
    uint64_t end_time_ns;

    // The amount of time the GPU was running GPU work for |pid| during the
    // period, in nanoseconds, without double-counting parallel GPU work for the
    // same |pid|. For example, this might include the amount of time the GPU
    // spent performing shader work (vertex work, fragment work, etc.) for
    // |pid|.
    uint64_t total_active_duration_ns;

    // The PID of the application that submitted work to the GPU.
    u32 pid;

} GpuWorkPeriodEvent;

_Static_assert(offsetof(GpuWorkPeriodEvent, gpu_id) == 8 &&
                       offsetof(GpuWorkPeriodEvent, uid) == 12 &&
                       offsetof(GpuWorkPeriodEvent, start_time_ns) == 16 &&
                       offsetof(GpuWorkPeriodEvent, end_time_ns) == 24 &&
                       offsetof(GpuWorkPeriodEvent, total_active_duration_ns) == 32 &&
                       offsetof(GpuWorkPeriodEvent, pid) == 40,
               "Field offsets of struct GpuWorkPeriodEvent must not be changed because they "
               "must match the tracepoint field offsets found via adb shell cat "
               "/sys/kernel/tracing/events/power/gpu_work_period/format");

typedef struct {
    // structure must match /sys/kernel/tracing/events/kgsl/kgsl_pwrlevel/format
    uint64_t common;

    // this is four bytes of type field:__data_loc char[], probably an
    // offset from some point, not a raw pointer due to width.
    char device_name[4];

    u32 pwrlevel;
    u32 freq;
    u32 prev_pwrlevel;
    u32 prev_freq;
} KgslPwrLevelEvent;

_Static_assert(offsetof(KgslPwrLevelEvent, pwrlevel) == 12 &&
                       offsetof(KgslPwrLevelEvent, freq) == 16 &&
                       offsetof(KgslPwrLevelEvent, prev_pwrlevel) == 20 &&
                       offsetof(KgslPwrLevelEvent, prev_freq) == 24,
               "Field offsets of struct KgslPwrLevelEvent must not be changed because they "
               "must match the tracepoint field offsets found via adb shell cat "
               "/sys/kernel/tracing/events/kgsl/kgsl_pwrlevel/format");

SEC("tracepoint/kgsl/kgsl_pwrlevel")
int trace_kgsl_pwrlevel(KgslPwrLevelEvent* const ctx) {
    // as of the time of this writing, there is only one GPU, but if we
    // acquire multiple, will have to incorporate gpu-id into the keys.
    const int ALLOW = 1;

    uint64_t start;
    u32 last_pwr = 0;
    u32 is_exit = 0;
    uint64_t last_start = 0;

    const u32 zero = 0;
    // Get the |GlobalData|.
    GlobalData* global_data = bpf_map_lookup_elem(&gpu_tis_global_data, &zero);
    // Getting the global data never fails because it is an |ARRAY| map,
    // but we need to keep the verifier happy.
    if (!global_data) {
        return ALLOW;
    }

    start = bpf_ktime_get_ns();

#ifdef USE_BPF_SPIN_LOCK
    bpf_spin_lock(&global_data->mux);
#endif
    last_pwr = global_data->last_pwrlevel;
    last_start = global_data->last_time;
    is_exit = last_pwr != ctx->pwrlevel ? 1 : 0;
    global_data->last_pwrlevel = ctx->pwrlevel;  // used for uid_time_in_state
    global_data->last_time = start;
#ifdef USE_BPF_SPIN_LOCK
    bpf_spin_unlock(&global_data->mux);
#endif

    if (last_start >= start) {
        // monotonic clock not strictly monotonic or it's our first update. Just drop update.
        return ALLOW;
    }

    // since we are transitioning from last_pwrlevel to pwrlevel, just
    // add the delta to prev_pwrlevel

    uint64_t delta = start - last_start;

    last_pwr = last_pwr >= PWRLEVELS ? PWRLEVELS - 1 : last_pwr;

    BpfStateResidency* residency = bpf_map_lookup_elem(&gpu_time_in_state_map, &last_pwr);
    if (residency) {
        __sync_fetch_and_add(&residency->totalTimeInStateNs, delta);
        residency->lastEntryTimestampNs =
                start;  // even if we have spinlocks, losing a race and being a few ns off is fine,
                        // so do not acquire crit sec
        if (is_exit) {
            // reduce map lookups/writes a bit by counting exits instead of entries. lagging
            // off-by-one for current state is fine.
            __sync_fetch_and_add(&residency->totalStateEntryCount, is_exit);
        }
    }

    return ALLOW;
}

SEC("tracepoint/power/gpu_work_period")
int trace_gpu_work_period(GpuWorkPeriodEvent* const period) {
    const int ALLOW = 1;

    u32 pwrlevel;

    // If |total_active_duration_ns| is 0 then no GPU work occurred and there is
    // nothing to do.
    if (period->total_active_duration_ns == 0) {
        return ALLOW;
    }
    uint64_t start = bpf_ktime_get_ns();
    const u32 pid = period->pid;

    PidGpuIdUid pid_gpu_id_and_uid = {.gpu_id = period->gpu_id, .uid = period->uid, .pid = pid};

    const u32 zero = 0;
    // Get the |GlobalData|.
    GlobalData* global_data = bpf_map_lookup_elem(&gpu_tis_global_data, &zero);
    // Getting the global data never fails because it is an |ARRAY| map,
    // but we need to keep the verifier happy.
    if (!global_data) {
        return ALLOW;
    }

    // if a work period is ending and concurrently the pwrlevel
    // changes, this work period may be attributed to the wrong
    // pwrlevel. Similarly if work periods can overlap between two
    // power levels (I do not know if that's possible), this heuristic
    // will be inaccurate. These issues are unlikely to occur
    // frequently enough to significantly affect data accuracy.
    pwrlevel = global_data->last_pwrlevel;
    pwrlevel = pwrlevel >= PWRLEVELS ? PWRLEVELS - 1 : pwrlevel;

    NsPerPwrLevel* time_in_state = bpf_map_lookup_elem(&gpu_uid_time_in_state_map, &pid_gpu_id_and_uid);
    if (!time_in_state) {
        NsPerPwrLevel initial_state;
        __builtin_memset(&initial_state, 0, sizeof(initial_state));
        initial_state.nsAtLevel[pwrlevel] = period->total_active_duration_ns;
        bpf_map_update_elem(&gpu_uid_time_in_state_map, &pid_gpu_id_and_uid, &initial_state,
                            BPF_NOEXIST);
        time_in_state = bpf_map_lookup_elem(&gpu_uid_time_in_state_map, &pid_gpu_id_and_uid);
        bpf_map_update_elem(&pid_to_gpu_map, &pid, &pid_gpu_id_and_uid, BPF_ANY);
    }
    if (time_in_state) {
        __sync_fetch_and_add(&time_in_state->nsAtLevel[pwrlevel], period->total_active_duration_ns);
    }

    /* we only accrue aggregate device time in state when kgsl state
     * changes. See if we should update those stats here */
    uint64_t last_time = global_data->last_time;
    if (start < last_time) { /* power levels changed while we were running. do nothing */
        return ALLOW;
    } else if (start - last_time > 1000000000) {
        /* we've been at the same power level for a whole second. Go ahead and add current time to
         * accounting.  */
        BpfStateResidency* residency = bpf_map_lookup_elem(&gpu_time_in_state_map, &pwrlevel);
#ifdef USE_BPF_SPIN_LOCK
        bpf_spin_lock(&global_data->mux);
#endif

        last_time = global_data->last_time;
        // recheck conditions now that we're locked. If this condition is still true, pwrlevel will
        // not have changed either
        if (start > last_time && start - last_time > 1000000000 && residency) {
            __sync_fetch_and_add(&residency->totalTimeInStateNs, start - last_time);
            global_data->last_time = start;
        }
#ifdef USE_BPF_SPIN_LOCK
        bpf_spin_unlock(&global_data->mux);
#endif
    }

    return ALLOW;
}

SEC("raw_tracepoint/sched_process_exit")
int trace_sched_process_exit(struct task_struct* task) {
    u32 tgid = BPF_CORE_READ(task, group_leader, pid);
    const atomic_t live = BPF_CORE_READ(task, signal, live);

    // Only care when the last thread exits
    if (live.counter != 0) return 0;

    // Delete GPU time-in-state entry using the tracked pid->gpu mapping
    PidGpuIdUid* gpu_key = bpf_map_lookup_elem(&pid_to_gpu_map, &tgid);

    if (gpu_key) {
        bpf_map_delete_elem(&gpu_uid_time_in_state_map, gpu_key);
        bpf_map_delete_elem(&pid_to_gpu_map, &tgid);
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
