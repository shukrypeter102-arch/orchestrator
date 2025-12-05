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

#include <sched.h>

#include <chrono>
#include <fstream>
#include <thread>

#include "cpuflow_bpf.skel.h"

// Per-CPU context data type
struct per_cpu_ctx {
    // The time when the current task started running on this CPU.
    __u64 start_time;
    // The current pid running on this CPU.
    __u32 cur_pid;
    // The current frequency of the CPU.
    __u32 cur_freq;
};

const static std::string current_freq = "cpuinfo_cur_freq";
const static std::string max_freq = "scaling_max_freq";
const static std::string min_freq = "scaling_min_freq";
constexpr int kMaxPid = 32768;
constexpr int kMaxCpu = 16;

class CpuBpfTest : public ::testing::Test {
protected:
    struct cpuflow_bpf *skel{};
    int time_map_fd = -1;
    int credit_map_fd = -1;
    int num_cpus = 0;
    int inner_time_map_fds[kMaxCpu] = {0};
    int inner_credit_map_fds[kMaxCpu] = {0};
    int ctx_fd = -1;

    static unsigned int cpufreq(int cpu, const std::string& fs_name) {
        std::string path =
            "/sys/devices/system/cpu/cpu" + std::to_string(cpu) + "/cpufreq/" + fs_name;
        std::fstream sysfs_file(path, std::ios_base::in);

        if (!sysfs_file.is_open()) {
            printf("cpufreq(): Failed to open %s", path.c_str());
            return 0;
        }

        unsigned int freq = 0;
        sysfs_file >> freq;
        sysfs_file.close();

        printf("cpufreq(): cpu %d %s: %u\n", cpu, fs_name.c_str(), freq);

        return freq;
    }

    static unsigned long long get_busy_time() {
        std::ifstream stat_file("/proc/stat");
        std::string line;
        unsigned long long user, nice, system, idle, iowait, irq, softirq, steal;
        std::getline(stat_file, line); // get rid of the first line
        std::istringstream iss(line);
        std::string cpu_label;
        iss >> cpu_label; // "cpu"
        iss >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal;
        unsigned long long total = user + nice + system; // Do not + iowait + irq + softirq + steal;
        printf("get_busy_time(): busy %llu = user %llu + nice %llu + system %llu, idle %llu, iowait %llu, irq %llu, softirq %llu, steal %llu\n",
                total, user, nice, system, idle, iowait, irq, softirq, steal);
        return total;
    }

    static std::string get_comm(int pid) {
        std::string path = "/proc/" + std::to_string(pid) + "/comm";
        std::fstream sysfs_file(path, std::ios_base::in);
        if (!sysfs_file.is_open()) {
            printf("get_comm(): Failed to open %s", path.c_str());
            return "";
        }
        std::string comm;
        sysfs_file >> comm;
        sysfs_file.close();
        return comm;
    }


    void SetUp() override {
        OCULUS_UNSUPPORTED_TEST_DEVICES("starlet");

        auto setup_begin = std::chrono::high_resolution_clock::now();

        num_cpus = libbpf_num_possible_cpus();
        ASSERT_GT(num_cpus, 1); // We need at least 2 CPUs to test

        auto begin = std::chrono::high_resolution_clock::now();
        skel = cpuflow_bpf__open();
        ASSERT_NE(skel, nullptr);

        EXPECT_EQ(bpf_map__set_max_entries(skel->maps.time_maps, num_cpus), 0);
        EXPECT_EQ(bpf_map__set_max_entries(skel->maps.credit_maps, num_cpus), 0);
        EXPECT_EQ(bpf_map__set_max_entries(skel->maps.per_cpu_ctxs, num_cpus), 0);

        ASSERT_EQ(cpuflow_bpf__load(skel), 0);

        time_map_fd = bpf_map__fd(skel->maps.time_maps);
        EXPECT_GT(time_map_fd, 0);

        credit_map_fd = bpf_map__fd(skel->maps.credit_maps);
        EXPECT_GT(credit_map_fd, 0);

        ctx_fd = bpf_map__fd(skel->maps.per_cpu_ctxs);
        EXPECT_GT(ctx_fd, 0);

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - begin);
        printf("LINE %d/%d: SETUP() BPF program loaded in %llu us\n", __LINE__, sched_getcpu(), duration.count());

        begin = std::chrono::high_resolution_clock::now();;
        for (int i = 0; i < num_cpus; i++) {
            struct per_cpu_ctx ctx = {
                  .start_time = 0,
                  .cur_pid = 0,
                  .cur_freq = cpufreq(i, current_freq),
            };
            EXPECT_EQ(bpf_map_update_elem(ctx_fd, &i, &ctx, 0), 0);
            // This initialization step is NEEDED to have a default value of cpu frequency

            LIBBPF_OPTS(bpf_map_create_opts, create_opts_rb);

            inner_time_map_fds[i] = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, 4, 8, kMaxPid, &create_opts_rb);
            EXPECT_GT(inner_time_map_fds[i], 0);
            EXPECT_EQ(bpf_map_update_elem(time_map_fd, &i, &inner_time_map_fds[i], 0), 0);

            inner_credit_map_fds[i] = bpf_map_create(BPF_MAP_TYPE_ARRAY, nullptr, 4, 8, kMaxPid, &create_opts_rb);
            EXPECT_GT(inner_credit_map_fds[i], 0);
            EXPECT_EQ(bpf_map_update_elem(credit_map_fd, &i, &inner_credit_map_fds[i], 0), 0);
        }

        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(end - begin);
        printf("LINE %d/%d: SETUP() BPF map created in %llu us\n", __LINE__, sched_getcpu(), duration.count());

        begin = std::chrono::high_resolution_clock::now();
        ASSERT_EQ(cpuflow_bpf__attach(skel), 0);
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(end - begin);
        printf("LINE %d/%d: SETUP() BPF program attached in %llu us\n", __LINE__, sched_getcpu(), duration.count());

        auto setup_end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(setup_end - setup_begin);
        printf("LINE %d/%d: SETUP() total %llu us\n", __LINE__, sched_getcpu(), duration.count());
    }

    void TearDown() override {
        for (int i = 0; i < num_cpus; i++) {
            close(inner_time_map_fds[i]);
            close(inner_credit_map_fds[i]);
        }
        close(time_map_fd);
        close(credit_map_fd);
        close(ctx_fd);
        cpuflow_bpf__destroy(skel);
        printf("LINE %d/%d: TEARDOWN(): Destroyed BPF program\n", __LINE__, sched_getcpu());
    }
};

FRL_TEST_F_ONCALL(CpuBpfTest, Sanity, vros_system_health_compute_and_memory) {
    int pid = gettid();

    uint64_t time = 0;
    printf("Main thread %d on cpu %d\n", gettid(), sched_getcpu());

    // Sleep to trigger context switch
    auto begin = std::chrono::high_resolution_clock::now();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - begin);
    printf("LINE %d/%d: Main thread %d after %llu us sleep\n", __LINE__, sched_getcpu(), gettid(), duration.count());

    // Sleep again so the execution is accounted as second - first
    begin = std::chrono::high_resolution_clock::now();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    end = std::chrono::high_resolution_clock::now();
    printf("LINE %d/%d: Main thread %d after %llu us sleep again\n", __LINE__, sched_getcpu(), gettid(), duration.count());

    for (int i = 0; i < num_cpus; i++) {
        uint64_t cpu_time = 0;
        begin = std::chrono::high_resolution_clock::now();
        EXPECT_EQ(bpf_map_lookup_elem(inner_time_map_fds[i], &pid, &cpu_time), 0);
        end = std::chrono::high_resolution_clock::now();
        duration = std::chrono::duration_cast<std::chrono::microseconds>(end - begin);
        printf("LINE %d/%d: Main thread time account on cpu %d: %llu (look_up cost %llu us)\n",
                __LINE__, sched_getcpu(), i, (unsigned long long)cpu_time, duration.count());
        time += cpu_time;
    }
    printf("LINE %d/%d: Main thread time account overall: %llu\n", __LINE__, sched_getcpu(), (unsigned long long)time);
    EXPECT_GT(time, 0);
}

FRL_TEST_F_ONCALL(CpuBpfTest, BusyThread, vros_system_health_compute_and_memory) {
    OCULUS_SKIP_TEST_IF_EMULATOR(); // Emulator doesn't have CPU freq

    bool killed = false;
    int pid = -1;
    uint64_t counter = 0;
    int cpu = sched_getcpu();
    printf("Main thread %d on cpu: %d\n", gettid(), cpu);

    std::thread t([&]() {
        int cur_cpu = sched_getcpu();
        printf("Worker thread %d on cpu: %d\n", gettid(), cur_cpu);
        pid = gettid(); // Get the thread ID
        cpu_set_t cpuset_;
        CPU_ZERO(&cpuset_);
        if (cpu == cur_cpu) {
            // If the current CPU is the same as the main thread, move to another CPU and pin to it.
            if (cpu == 0) {
                cpu = 1; // Set the CPU to 1 if the current CPU is 0
            } else {
                cpu--; // Set the CPU to the current CPU - 1
            }
        } else {
            cpu = cur_cpu; // Set the CPU to the current CPU
        }
        CPU_SET(cpu, &cpuset_);
        sched_setaffinity(pid, sizeof(cpuset_), &cpuset_); // Pin to cpu
        struct sched_param param_{};
        param_.sched_priority = 99; // Set to highest priority so it is not preempted
        sched_setscheduler(pid, SCHED_FIFO, &param_); // Set to RT priority
        printf("LINE %d/%d: Worker thread %d pinned to cpu: %d\n", __LINE__, sched_getcpu(), gettid(), cpu);
        auto begin = std::chrono::high_resolution_clock::now();
        while (!killed) {
            counter++;
            unsigned long long period = 10000000;
            if (counter % period == 0) {
                printf("LINE %d/%d: Worker thread %d 10M-counter: %llu\n",
                        __LINE__, sched_getcpu(), gettid(), counter / period);
            }
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - begin);
        printf("LINE %d/%d: Worker thread %d killed on counter: %llu (after %llu us)\n",
                __LINE__, sched_getcpu(), gettid(), (unsigned long long)counter, duration.count());
    });

    auto begin = std::chrono::high_resolution_clock::now();
    while (!counter) {} // Busy wait until we are certain the worker thread is running
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - begin);
    printf("LINE %d/%d: Main thread %d after %llu us busy wait\n", __LINE__, sched_getcpu(), gettid(), duration.count());

    begin = std::chrono::high_resolution_clock::now();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>(end - begin);
    printf("LINE %d/%d: Main thread %d after %llu us sleep\n", __LINE__, sched_getcpu(), gettid(),  duration.count());

    begin = std::chrono::high_resolution_clock::now();
    killed = true;
    t.join();
    // Terminate worker thread so it is accounted
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>(end - begin);
    printf("LINE %d/%d: Main thread %d after %llu us for worker to join\n", __LINE__, sched_getcpu(), gettid(), duration.count());

    uint64_t min_freq_val = cpufreq(cpu, min_freq);
    uint64_t max_freq_val = cpufreq(cpu, max_freq);

    std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Sleep to ensure the context switch is accounted

    uint64_t time = 0;
    EXPECT_EQ(bpf_map_lookup_elem(inner_time_map_fds[cpu], &pid, &time), 0);
    printf("Worker thread %d total time account: %llu\n", pid, (unsigned long long)time);
    EXPECT_GT(time, 0);
    EXPECT_NEAR((double)time / (1e6 * 500), 1.0, 0.15); // 15% error margin

    uint64_t credit = 0;
    EXPECT_EQ(bpf_map_lookup_elem(inner_credit_map_fds[cpu], &pid, &credit), 0);
    printf("Worker thread %d total raw credit: %llu\n", pid, (unsigned long long)credit);
    printf("Worker thread %d average freq: %f\n", pid, (double)credit / (double)time);
    EXPECT_GT(credit, 0);
    EXPECT_GE((double)credit / (double)(min_freq_val * time), 0.9); // 10% error margin
    EXPECT_LE((double)credit / (double)(max_freq_val * time), 1.1); // 10% error margin
    // NOTE: it is very unlikely that the DVFS min/max is changed during this run

    if (min_freq_val == max_freq_val) {
        // For constant frequency, the credit should be exactly equal to the time * frequency
        // as the thread is already terminated so change between two readings is not expected
        EXPECT_EQ(credit, min_freq_val * time);
    }
}

FRL_TEST_F_ONCALL(CpuBpfTest, Iterate, vros_system_health_compute_and_memory) {
    OCULUS_SKIP_TEST_IF_EMULATOR();

    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // Sleep to ensure something is running

    int idle_cpu_count = 0;

    for (int cpu = 0; cpu < num_cpus; cpu++) {
        __u32 key = 0;
        __u64 time_value = 0;
        __u64 credit_value = 0;

        __u64 total_busy_time = 0;

        auto begin = std::chrono::high_resolution_clock::now();
        while (bpf_map_get_next_key(inner_time_map_fds[cpu], &key, &key) == 0) {
            // This will actually iterate from 0 to 32768 if we print
            EXPECT_EQ(bpf_map_lookup_elem(inner_time_map_fds[cpu], &key, &time_value), 0);
            EXPECT_EQ(bpf_map_lookup_elem(inner_credit_map_fds[cpu], &key, &credit_value), 0);
            if (time_value > 0) {
                total_busy_time += time_value;
            }
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - begin);
        printf("LINE %d/%d: cpu %d total busy time: %llu (iterate cost %llu us) \n",
                __LINE__, sched_getcpu(), cpu, (unsigned long long)total_busy_time, duration.count());
        if (total_busy_time == 0) {
            idle_cpu_count++;
        }
    }
    EXPECT_LE(idle_cpu_count, 1); // At most one CPU is idle. Theoretically, all CPUs should be busy
}

FRL_TEST_F_ONCALL(CpuBpfTest, Top, vros_system_health_compute_and_memory) {
    OCULUS_SKIP_TEST_IF_EMULATOR();

    std::map<int, std::pair<unsigned long long, unsigned long long>> prev_time_and_credit;

    // Read snapshot of bpf map and stats
    auto begin = std::chrono::high_resolution_clock::now();
    for (int cpu = 0; cpu < num_cpus; cpu++) {
        __u32 count = kMaxPid;
        __u32 next_key = 0;
        __u32 keys[kMaxPid];
        __u64 times[kMaxPid];
        __u64 credits[kMaxPid];

        auto local_begin = std::chrono::high_resolution_clock::now();
        LIBBPF_OPTS(bpf_map_batch_opts, opts);
        EXPECT_EQ(bpf_map_lookup_batch(inner_time_map_fds[cpu], nullptr, &next_key, keys, times, &count, &opts), 0);
        EXPECT_EQ(count, kMaxPid); // We should be able to get all the keys
        EXPECT_EQ(bpf_map_lookup_batch(inner_credit_map_fds[cpu], nullptr, &next_key, keys, credits, &count, &opts), 0);
        EXPECT_EQ(count, kMaxPid); // We should be able to get all the keys again
        auto local_end = std::chrono::high_resolution_clock::now();
        auto local_duration = std::chrono::duration_cast<std::chrono::microseconds>(local_end - local_begin);
        printf("LINE %d/%d: cpu %d: BPF map batch lookup cost %llu us\n", __LINE__, sched_getcpu(), cpu, local_duration.count());

        local_begin = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < kMaxPid; i++) {
            if (times[i] > 0) {
                prev_time_and_credit[keys[i]] = std::make_pair(times[i], credits[i]);
            }
        }
        local_end = std::chrono::high_resolution_clock::now();
        local_duration = std::chrono::duration_cast<std::chrono::microseconds>(local_end - local_begin);
        printf("LINE %d/%d: cpu %d: accounting cost %llu us\n", __LINE__, sched_getcpu(), cpu, local_duration.count());
    }
    unsigned long long prev_busy_times = get_busy_time();
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - begin);
    printf("LINE %d/%d: BPF map total batch lookup cost %llu us\n", __LINE__, sched_getcpu(), duration.count());

    begin = std::chrono::high_resolution_clock::now();
    std::this_thread::sleep_for(std::chrono::seconds(5)); // It's a long time so we can try to avoid truncation errors
    std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Sleep again to ensure the context switch is accounted
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>(end - begin);
    printf("LINE %d/%d: Main thread %d after %llu us sleep\n", __LINE__, sched_getcpu(), gettid(), duration.count());

    // Read snapshot of bpf map and stats again
    std::map<int, std::pair<unsigned long long, unsigned long long>> curr_time_and_credit;

    begin = std::chrono::high_resolution_clock::now();
    for (int cpu = 0; cpu < num_cpus; cpu++) {
        __u32 count = kMaxPid;
        __u32 next_key = 0;
        __u32 keys[kMaxPid];
        __u64 times[kMaxPid];
        __u64 credits[kMaxPid];
        auto local_begin = std::chrono::high_resolution_clock::now();
        LIBBPF_OPTS(bpf_map_batch_opts, opts);
        EXPECT_EQ(bpf_map_lookup_batch(inner_time_map_fds[cpu], nullptr, &next_key, keys, times, &count, &opts), 0);
        EXPECT_EQ(count, kMaxPid); // We should be able to get all the keys
        EXPECT_EQ(bpf_map_lookup_batch(inner_credit_map_fds[cpu], nullptr, &next_key, keys, credits, &count, &opts), 0);
        EXPECT_EQ(count, kMaxPid); // We should be able to get all the keys again
        auto local_end = std::chrono::high_resolution_clock::now();
        auto local_duration = std::chrono::duration_cast<std::chrono::microseconds>(local_end - local_begin);
        printf("LINE %d/%d: cpu %d: BPF map batch lookup cost %llu us\n", __LINE__, sched_getcpu(), cpu, local_duration.count());

        local_begin = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < kMaxPid; i++) {
            if (times[i] > 0) {
                curr_time_and_credit[keys[i]] = std::make_pair(times[i], credits[i]);
            }
        }
        local_end = std::chrono::high_resolution_clock::now();
        local_duration = std::chrono::duration_cast<std::chrono::microseconds>(local_end - local_begin);
        printf("LINE %d/%d: cpu %d: accounting cost %llu us\n", __LINE__, sched_getcpu(), cpu, local_duration.count());
    }
    unsigned long long curr_busy_time = get_busy_time();
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>(end - begin);
    printf("LINE %d/%d: BPF map total batch lookup cost %llu us\n", __LINE__, sched_getcpu(), duration.count());

    // All the data are now captured, we can do the calculation

    unsigned long long busy_time_diff = curr_busy_time - prev_busy_times;
    printf("Stat busy time diff: %llu\n", busy_time_diff);
    std::vector<std::pair<unsigned long long, int>> time_diff_and_pid;
    std::map<int, std::pair<unsigned long long, unsigned long long>> time_and_credit_diff;

    unsigned long long total_time_diff = 0;

    for (const auto& [pid, pair] : prev_time_and_credit) {
        EXPECT_EQ(curr_time_and_credit.count(pid), 1) << get_comm(pid); // All the PIDs in prev should be also in the current map
    }

    begin = std::chrono::high_resolution_clock::now();
    for (const auto& [pid, pair] : curr_time_and_credit) {
        if (pair.first < prev_time_and_credit[pid].first) {
            printf("PID %d time diff is negative: %llu -> %llu (%s)\n", pid, prev_time_and_credit[pid].first, pair.first, get_comm(pid).c_str());
            continue;
            // Ignore negative time diff since it's likely due to concurrency async issue
            // TODO: observe how often this happens and see if we can fix it
        } else if (pair.first == prev_time_and_credit[pid].first) {
            continue; // Ignore zero time diff since the PID is not running in the time window
        }
        unsigned long long time_diff = pair.first - prev_time_and_credit[pid].first;
        unsigned long long credit_diff = pair.second - prev_time_and_credit[pid].second;
        time_diff_and_pid.push_back(std::make_pair(time_diff, pid));
        time_and_credit_diff[pid] = std::make_pair(time_diff, credit_diff);
        total_time_diff += pair.first - prev_time_and_credit[pid].first;
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>(end - begin);
    printf("BPF busy time diff: %llu\n", total_time_diff);
    printf("LINE %d/%d: Snapshot delta cost %llu us\n", __LINE__, sched_getcpu(), duration.count());

    // stat time is in 10ms tick; add 5x margin so they are at least in the same magnitude
    // Note: the negative time diff may cause the total time diff to be smaller than the stat time diff
    EXPECT_LT(total_time_diff / 1e7, busy_time_diff * 5.0);
    EXPECT_GT(total_time_diff / 1e7, busy_time_diff / 5.0);

    std::sort(time_diff_and_pid.begin(), time_diff_and_pid.end(), std::greater<>());
    printf("Accounted PIDs %d:\n", (int)time_diff_and_pid.size());
    EXPECT_GE(time_diff_and_pid.size(), 10 * num_cpus); // At least 10 PIDs for each CPU

    for (int i = 0; i < time_diff_and_pid.size() && i <= 20; i++) {
        int pid = time_diff_and_pid[i].second;
        printf("[%5d] %5.2fms, %6.1f$, %6.2fMHz | %s\n", pid,
            time_and_credit_diff[pid].first / 1e6, time_and_credit_diff[pid].second / 1e12,
            (double)time_and_credit_diff[pid].second / time_and_credit_diff[pid].first / 1e3,
            get_comm(pid).c_str());
    }
    // NOTE: the raw credit is not converted to real CPU credit yet
}

FRL_TEST_F_ONCALL(CpuBpfTest, MapLookupBatchProfile, vros_system_health_compute_and_memory) {
    OCULUS_SKIP_TEST_IF_EMULATOR();

    __u32 count = kMaxPid;
    __u32 next_key = 0;
    __u32 keys[kMaxCpu][kMaxPid];
    __u64 credits[kMaxCpu][kMaxPid];
    LIBBPF_OPTS(bpf_map_batch_opts, opts);

    std::chrono::microseconds accumulated_duration{}, max_duration{};

    auto begin = std::chrono::high_resolution_clock::now();

    constexpr int kNumIterations = 50;

    // Repeat to get the average time
    for (int i = 0; i < kNumIterations; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        for (int cpu = 0; cpu < num_cpus; cpu++) {
            auto local_begin = std::chrono::high_resolution_clock::now();
            int ret = bpf_map_lookup_batch(inner_credit_map_fds[cpu], nullptr, &next_key, keys[cpu], credits[cpu], &count, &opts);
            auto local_end = std::chrono::high_resolution_clock::now();
            if (ret) {
                printf("BPF map lookup failed %d/%d: %d, %s\n", i, cpu, ret, strerror(errno));
            }
            auto local_duration = std::chrono::duration_cast<std::chrono::microseconds>(local_end - local_begin);
            accumulated_duration += local_duration;
            if (local_duration > max_duration) {
                max_duration = local_duration;
            }
        }
    }
    auto end = std::chrono::high_resolution_clock::now();
    printf("LINE %d/%d: average/max per-cpu-map batch lookup %llu/%llu us\n", __LINE__, sched_getcpu(),
            accumulated_duration.count() / kNumIterations / num_cpus, max_duration.count());
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - begin);
    printf("LINE %d/%d: 50 total batch lookup cost %llu us\n", __LINE__, sched_getcpu(), duration.count());
    EXPECT_NEAR((double)(accumulated_duration.count() + 100 * 1000 * kNumIterations) / (double)duration.count(), 1, 0.2); // 20% error margin
}
