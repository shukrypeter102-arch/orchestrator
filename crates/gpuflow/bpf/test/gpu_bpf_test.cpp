/*
 * Copyright (C) 2025 Meta Platforms, Inc. and affiliates. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <FrlGtestWrapper.h>
#include <OculusTestUtils.h>

#include "bpf/bpf.h"
#include "bpf/libbpf.h"

#include <chrono>
#include <iomanip>
#include <iostream>
#include <thread>

#include "credits_bpf.skel.h"
#include "../credits.bpf.h"

class GpuBpfTest : public ::testing::Test {
protected:
    struct credits_bpf *skel{};

    void SetUp() override {
        OCULUS_UNSUPPORTED_TEST_DEVICES("starlet", "hollywood", "seacliff", "sekiu", "sekiu_arm64");

        auto setup_begin = std::chrono::high_resolution_clock::now();

        // Clean up any existing pinned maps from previous runs
        printf("Cleaning up existing pinned maps...\n");
        unlink("/sys/fs/bpf/gpu_tis_global_data");
        unlink("/sys/fs/bpf/gpu_time_in_state_map");
        unlink("/sys/fs/bpf/gpu_uid_time_in_state_map");
        unlink("/sys/fs/bpf/pid_to_gpu_map");
        printf("Cleanup complete\n");

        auto begin = std::chrono::high_resolution_clock::now();
        skel = credits_bpf__open();
        ASSERT_NE(skel, nullptr);

        ASSERT_EQ(credits_bpf__load(skel), 0);

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - begin);
        printf("BPF program loaded in %llu us\n", duration.count());

        begin = std::chrono::high_resolution_clock::now();
        ASSERT_EQ(credits_bpf__attach(skel), 0);
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(end - begin);
        printf("BPF program attached in %llu us\n", duration.count());

        auto setup_end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(setup_end - setup_begin);
        printf("Setup total: %llu us\n", duration.count());

        // Sleep to allow GPU events to be captured
        printf("Waiting 2 seconds for GPU activity...\n");
        std::this_thread::sleep_for(std::chrono::seconds(2));
        printf("Capture period complete\n");
    }

    void TearDown() override {
        credits_bpf__destroy(skel);
        printf("Destroyed BPF program\n");
    }
};

FRL_TEST_F_ONCALL(GpuBpfTest, PrintAllMaps, vros_system_health_compute_and_memory) {
    printf("\n========== GPU BPF Maps ==========\n\n");

    // Print gpu_tis_global_data map
    printf("1. gpu_tis_global_data (BPF_MAP_TYPE_ARRAY)\n");
    printf("   Description: Contains a single entry of GlobalData with last_time and last_pwrlevel\n");
    int global_data_fd = bpf_map__fd(skel->maps.gpu_tis_global_data);
    printf("   Map FD: %d\n", global_data_fd);
    printf("   Max entries: %u\n", bpf_map__max_entries(skel->maps.gpu_tis_global_data));
    printf("   Key size: %u bytes\n", bpf_map__key_size(skel->maps.gpu_tis_global_data));
    printf("   Value size: %u bytes\n", bpf_map__value_size(skel->maps.gpu_tis_global_data));
    printf("   Map type: %u\n", bpf_map__type(skel->maps.gpu_tis_global_data));
    printf("   Map name: %s\n", bpf_map__name(skel->maps.gpu_tis_global_data));
    EXPECT_GT(global_data_fd, 0);

    // Read actual global data value
    struct {
        uint64_t last_time;
        uint32_t last_pwrlevel;
    } global_data{};
    uint32_t key = 0;
    if (bpf_map_lookup_elem(global_data_fd, &key, &global_data) == 0) {
        printf("   Actual Values:\n");
        printf("     last_time: %llu ns\n", (unsigned long long)global_data.last_time);
        printf("     last_pwrlevel: %u\n", global_data.last_pwrlevel);
    } else {
        printf("   Unable to read global data (map may be empty)\n");
    }
    printf("\n");

    // Print gpu_time_in_state_map
    printf("2. gpu_time_in_state_map (BPF_MAP_TYPE_ARRAY)\n");
    printf("   Description: Maps pwrlevel -> BpfStateResidency (totalTimeInStateNs, totalStateEntryCount, lastEntryTimestampNs)\n");
    int time_in_state_fd = bpf_map__fd(skel->maps.gpu_time_in_state_map);
    printf("   Map FD: %d\n", time_in_state_fd);
    printf("   Max entries: %u (power levels)\n", bpf_map__max_entries(skel->maps.gpu_time_in_state_map));
    printf("   Key size: %u bytes (u32)\n", bpf_map__key_size(skel->maps.gpu_time_in_state_map));
    printf("   Value size: %u bytes (BpfStateResidency)\n", bpf_map__value_size(skel->maps.gpu_time_in_state_map));
    printf("   Map type: %u\n", bpf_map__type(skel->maps.gpu_time_in_state_map));
    printf("   Map name: %s\n", bpf_map__name(skel->maps.gpu_time_in_state_map));
    EXPECT_GT(time_in_state_fd, 0);

    // Read actual power level residency data
    printf("   Actual Values (per power level):\n");
    struct {
        uint64_t totalTimeInStateNs;
        uint64_t totalStateEntryCount;
        uint64_t lastEntryTimestampNs;
    } residency;

    bool has_data = false;
    for (uint32_t pwrlevel = 0; pwrlevel <= android::bpf::PWRLEVELS; pwrlevel++) {
        if (bpf_map_lookup_elem(time_in_state_fd, &pwrlevel, &residency) == 0) {
            if (residency.totalTimeInStateNs > 0 || residency.totalStateEntryCount > 0) {
                has_data = true;
                printf("     Power Level %u:\n", pwrlevel);
                printf("       totalTimeInStateNs: %llu ns (%.3f ms)\n",
                       (unsigned long long)residency.totalTimeInStateNs,
                       residency.totalTimeInStateNs / 1000000.0);
                printf("       totalStateEntryCount: %llu\n", (unsigned long long)residency.totalStateEntryCount);
                printf("       lastEntryTimestampNs: %llu ns\n", (unsigned long long)residency.lastEntryTimestampNs);
            }
        }
    }
    if (!has_data) {
        printf("     (No power level data recorded yet)\n");
    }
    printf("\n");

    // Print gpu_uid_time_in_state_map
    printf("3. gpu_uid_time_in_state_map (BPF_MAP_TYPE_HASH)\n");
    printf("   Description: Maps PidGpuIdUid (gpu_id, uid, pid) -> NsPerPwrLevel (nsAtLevel array)\n");
    int uid_time_in_state_fd = bpf_map__fd(skel->maps.gpu_uid_time_in_state_map);
    printf("   Map FD: %d\n", uid_time_in_state_fd);
    printf("   Max entries: %u (tracked GPU ID/UID/PID tuples)\n", bpf_map__max_entries(skel->maps.gpu_uid_time_in_state_map));
    printf("   Key size: %u bytes (PidGpuIdUid: gpu_id + uid + pid)\n", bpf_map__key_size(skel->maps.gpu_uid_time_in_state_map));
    printf("   Value size: %u bytes (NsPerPwrLevel: array of 17 uint64_t)\n", bpf_map__value_size(skel->maps.gpu_uid_time_in_state_map));
    printf("   Map type: %u\n", bpf_map__type(skel->maps.gpu_uid_time_in_state_map));
    printf("   Map name: %s\n", bpf_map__name(skel->maps.gpu_uid_time_in_state_map));
    EXPECT_GT(uid_time_in_state_fd, 0);

    // Read actual UID time-in-state data
    printf("   Actual Values:\n");
    struct {
        uint32_t gpu_id;
        uint32_t uid;
        uint32_t pid;
    } pid_gpu_id_uid_key{}, prev_key{};

    struct {
        uint64_t nsAtLevel[android::bpf::PWRLEVELS + 1];
    } ns_per_pwr_level{};

    int entry_count = 0;
    bool first = true;
    while (bpf_map_get_next_key(uid_time_in_state_fd,
                                 first ? nullptr : &prev_key,
                                 &pid_gpu_id_uid_key) == 0) {
        first = false;
        prev_key = pid_gpu_id_uid_key;

        if (bpf_map_lookup_elem(uid_time_in_state_fd, &pid_gpu_id_uid_key, &ns_per_pwr_level) == 0) {
            entry_count++;
            printf("     Entry %d: GPU ID %u, UID %u, PID %u\n", entry_count,
                   pid_gpu_id_uid_key.gpu_id, pid_gpu_id_uid_key.uid, pid_gpu_id_uid_key.pid);

            uint64_t total_ns = 0;
            for (int i = 0; i <= android::bpf::PWRLEVELS; i++) {
                total_ns += ns_per_pwr_level.nsAtLevel[i];
                if (ns_per_pwr_level.nsAtLevel[i] > 0) {
                    printf("       Power Level %d: %llu ns (%.3f ms)\n",
                           i, (unsigned long long)ns_per_pwr_level.nsAtLevel[i],
                           ns_per_pwr_level.nsAtLevel[i] / 1000000.0);
                }
            }
            printf("       Total: %llu ns (%.3f ms)\n", (unsigned long long)total_ns, total_ns / 1000000.0);
        }
    }

    if (entry_count == 0) {
        printf("     (No UID data recorded yet)\n");
    } else {
        printf("   Total entries: %d\n", entry_count);
    }
    printf("\n");

    // Print pid_to_gpu_map
    printf("4. pid_to_gpu_map (BPF_MAP_TYPE_HASH)\n");
    printf("   Description: Maps PID -> PidGpuIdUid for efficient cleanup on process exit\n");
    int pid_to_gpu_fd = bpf_map__fd(skel->maps.pid_to_gpu_map);
    printf("   Map FD: %d\n", pid_to_gpu_fd);
    printf("   Max entries: %u (tracked PIDs)\n", bpf_map__max_entries(skel->maps.pid_to_gpu_map));
    printf("   Key size: %u bytes (u32 pid)\n", bpf_map__key_size(skel->maps.pid_to_gpu_map));
    printf("   Value size: %u bytes (PidGpuIdUid)\n", bpf_map__value_size(skel->maps.pid_to_gpu_map));
    printf("   Map type: %u\n", bpf_map__type(skel->maps.pid_to_gpu_map));
    printf("   Map name: %s\n", bpf_map__name(skel->maps.pid_to_gpu_map));
    EXPECT_GT(pid_to_gpu_fd, 0);

    // Read actual PID to GPU mapping data
    printf("   Actual Values:\n");
    uint32_t pid_key = 0, prev_pid_key = 0;
    struct {
        uint32_t gpu_id;
        uint32_t uid;
        uint32_t pid;
    } pid_gpu_value = {};

    int pid_entry_count = 0;
    bool first_pid = true;
    while (bpf_map_get_next_key(pid_to_gpu_fd,
                                 first_pid ? nullptr : &prev_pid_key,
                                 &pid_key) == 0) {
        first_pid = false;
        prev_pid_key = pid_key;

        if (bpf_map_lookup_elem(pid_to_gpu_fd, &pid_key, &pid_gpu_value) == 0) {
            pid_entry_count++;
            printf("     Entry %d: PID %u -> GPU ID %u, UID %u, PID %u\n",
                   pid_entry_count, pid_key,
                   pid_gpu_value.gpu_id, pid_gpu_value.uid, pid_gpu_value.pid);
        }
    }

    if (pid_entry_count == 0) {
        printf("     (No PID mappings recorded yet)\n");
    } else {
        printf("   Total entries: %d\n", pid_entry_count);
    }
    printf("\n");

    printf("========== Map Summary ==========\n");
    printf("Total maps: 4\n");
    printf("- 1 global data map (ARRAY, 1 entry)\n");
    printf("- 1 time-in-state map (ARRAY, 17 power levels)\n");
    printf("- 1 UID time-in-state map (HASH, up to 32768 GPU ID/UID/PID tuples)\n");
    printf("- 1 PID to GPU map (HASH, up to 32768 PID mappings)\n");
    printf("\n");

    printf("========== Attached Programs ==========\n");
    printf("1. trace_kgsl_pwrlevel (tracepoint/kgsl/kgsl_pwrlevel)\n");
    printf("   - Tracks GPU power level transitions\n");
    printf("   - Updates gpu_tis_global_data and gpu_time_in_state_map\n");
    printf("\n");
    printf("2. trace_gpu_work_period (tracepoint/power/gpu_work_period)\n");
    printf("   - Tracks GPU work periods per UID/PID\n");
    printf("   - Updates gpu_uid_time_in_state_map and pid_to_gpu_map\n");
    printf("\n");
    printf("3. trace_sched_process_exit (raw_tracepoint/sched_process_exit)\n");
    printf("   - Cleans up map entries when processes exit\n");
    printf("   - Removes entries from gpu_uid_time_in_state_map and pid_to_gpu_map\n");
    printf("\n");

    // Verify all maps are accessible
    EXPECT_GT(global_data_fd, 0);
    EXPECT_GT(time_in_state_fd, 0);
    EXPECT_GT(uid_time_in_state_fd, 0);
    EXPECT_GT(pid_to_gpu_fd, 0);

    printf("All maps are successfully loaded and accessible!\n");
}
