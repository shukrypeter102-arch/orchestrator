// Copyright (C) 2025 Meta Platforms, Inc. and affiliates. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Memory Budget Policy: provides memory stats and enforcement for processes
//! based on system budget configuration.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::anyhow;
use async_trait::async_trait;
use hzos_budget::EnforcementContext;
use hzos_budget::EnforcementLevel;
use hzos_budget::PerContextEnforcementSet;
use hzos_budget::ResourceType;
use hzos_memory::heap::get_heap_memory_stats;
use hzos_memory::memtrack::MemTrackSessionAsync;
use hzos_trace::parfait::TraceContext;
use hzos_trace::parfait::TraceMetadata;
use hzos_trace::parfait::TraceTriggerAsync;
use log::error;
use log::info;
use log::warn;
use orchestrator_common::budget_enforcement;
use orchestrator_common::cgroup::CgroupEntry;
use orchestrator_common::cgroup::FileSystemCgroup;
use orchestrator_common::cgroup::ReclaimType;
use orchestrator_common::config;
use orchestrator_common::process_monitor::AggregatePolicy;
use orchestrator_common::process_monitor::ProcessInfo;
use orchestrator_common::sysprop;
use orchestrator_common::utils::KIB_TO_BYTES;
use orchestrator_common::utils::MIB_TO_BYTES;

const TICK_RATE_DEFAULT: Duration = Duration::from_secs(10 * 60);

pub struct MemoryBudgetConfig {
    pub is_dry_run: bool,
    pub tick_rate: Duration,
}

impl MemoryBudgetConfig {
    pub fn from_sysprops() -> anyhow::Result<Self> {
        // TODO: T245699353 - add support for configuring dry_run from sysprops. For now, default to true
        // since that is the initial roll out configuration.
        let is_dry_run = true;

        let tick_rate = sysprop::memflow_budget_tick_rate(TICK_RATE_DEFAULT);

        Ok(Self {
            is_dry_run,
            tick_rate,
        })
    }
}

pub struct MemoryBudgetPolicy {
    config: MemoryBudgetConfig,
    exe_to_pids: HashMap<String, Vec<ProcessInfo>>,
    pid_to_exe: HashMap<u32, String>,
    pid_to_cgroup: HashMap<u32, FileSystemCgroup>,
}

impl MemoryBudgetPolicy {
    pub fn new(config: MemoryBudgetConfig) -> Self {
        Self {
            config,
            exe_to_pids: HashMap::new(),
            pid_to_exe: HashMap::new(),
            pid_to_cgroup: HashMap::new(),
        }
    }

    /// Scans all the budgets assigned to this process and checks if they have
    /// been violated.
    async fn scan_enforcements(
        &self,
        memtrack: &mut MemTrackSessionAsync,
        process: &ProcessInfo,
        enforcements: &PerContextEnforcementSet,
    ) -> anyhow::Result<()> {
        let cgroup = self
            .pid_to_cgroup
            .get(&process.pid)
            .ok_or(anyhow!("no cgroup"))?;
        let record = memtrack.process_record(process.pid as i32).await?;

        let current_mem_bytes = cgroup.memory_current().await?;
        let swap_mem_bytes = cgroup.memory_swap_current().await?;
        let memtrack_mem_bytes = record.total_pss_bytes() as u64;
        let total_mem_bytes = current_mem_bytes + swap_mem_bytes + memtrack_mem_bytes;

        if let Some(thresholds) = enforcements.get_thresholds_for_context_resource_pair(
            EnforcementContext::All,
            ResourceType::MemoryMib,
        ) {
            for (level, threshold_mib) in thresholds {
                let memory_sla_bytes = *threshold_mib as u64 * MIB_TO_BYTES as u64;
                if total_mem_bytes >= memory_sla_bytes {
                    let mut cgroup_mem_limit_bytes = memory_sla_bytes;
                    if memtrack_mem_bytes >= memory_sla_bytes {
                        // We assign to 1 byte in this case to force the cgroup to close.
                        cgroup_mem_limit_bytes = 1;
                    } else if memtrack_mem_bytes < memory_sla_bytes {
                        cgroup_mem_limit_bytes -= memtrack_mem_bytes;
                    }
                    self.enforce(
                        process,
                        *level,
                        memory_sla_bytes,
                        total_mem_bytes,
                        swap_mem_bytes,
                        memtrack_mem_bytes,
                        memory_sla_bytes,
                        cgroup_mem_limit_bytes,
                        cgroup,
                    )
                    .await?;
                }
            }
        }
        Ok(())
    }

    /// The process has violated a policy; enforce based on the level.
    async fn enforce(
        &self,
        process: &ProcessInfo,
        level: EnforcementLevel,
        threshold_bytes: u64,
        total_mem_bytes: u64,
        swap_mem_bytes: u64,
        memtrack_mem_bytes: u64,
        memory_sla_bytes: u64,
        cgroup_mem_limit_bytes: u64,
        cgroup: &FileSystemCgroup,
    ) -> anyhow::Result<()> {
        warn!("Budget Enforcement {level:?}: {}:{}, sla:{memory_sla_bytes}, total:{total_mem_bytes}, swap: {swap_mem_bytes}, memtrack:{memtrack_mem_bytes}", process.exe, process.pid);

        // Perform main enforcement logic, including telemetry.
        budget_enforcement::do_enforcement(
            process,
            level,
            ResourceType::MemoryMib,
            self.config.is_dry_run,
            threshold_bytes / MIB_TO_BYTES as u64,
            total_mem_bytes / MIB_TO_BYTES as u64,
        );

        // Some enforcement levels require additional custom logic.
        if !self.config.is_dry_run {
            match level {
                EnforcementLevel::Trace => {
                    let (java_heap_size_bytes, native_heap_size_bytes) =
                        match get_heap_memory_stats(process.pid as i32).await {
                            Ok(mut heap_memory_stats) => {
                                let java_size = heap_memory_stats
                                    .get_java_heap_size_kib()
                                    .map(|size| size as i64 * KIB_TO_BYTES as i64)
                                    .unwrap_or(-1);
                                let native_size = heap_memory_stats
                                    .get_native_heap_size_kib()
                                    .map(|size| size as i64 * KIB_TO_BYTES as i64)
                                    .unwrap_or(-1);
                                (java_size, native_size)
                            }
                            Err(_) => (-1, -1),
                        };

                    let mut metadata = TraceMetadata::new();
                    metadata.insert("memory_sla_bytes", memory_sla_bytes.to_string());
                    metadata.insert("swap_mem_bytes", swap_mem_bytes.to_string());
                    metadata.insert("total_mem_bytes", total_mem_bytes.to_string());
                    metadata.insert("memtrack_mem_bytes", memtrack_mem_bytes.to_string());
                    metadata.insert("java_heap_size_bytes", java_heap_size_bytes.to_string());
                    metadata.insert("native_heap_size_bytes", native_heap_size_bytes.to_string());

                    let context =
                        TraceContext::new(format!("memory_over_budget:{}", process.exe), 0)
                            .with_target_process(&process.exe)
                            .with_metadata(metadata);
                    let trace = TraceTriggerAsync::connect().await?;
                    trace.start(&context).await?;
                }
                EnforcementLevel::Throttle => {
                    info!(
                        "memory_high: {}:{} = {cgroup_mem_limit_bytes}",
                        process.exe, process.pid
                    );
                    cgroup.write_memory_high(cgroup_mem_limit_bytes).await?;
                }
                _ => {}
            }
        }

        Ok(())
    }
}

#[async_trait]
impl AggregatePolicy for MemoryBudgetPolicy {
    fn name(&self) -> &'static str {
        "MemoryBudget"
    }

    /// Bookkeeping to track of all the comm->pids and pid->comm mappings. It
    /// is possible that a comm can be assigned to more than one pid.
    async fn process_create(&mut self, process: &ProcessInfo) -> anyhow::Result<bool> {
        self.exe_to_pids
            .entry(process.exe.clone())
            .or_insert_with(Vec::new)
            .push(process.clone());
        self.pid_to_exe.insert(process.pid, process.exe.clone());
        self.pid_to_cgroup.insert(
            process.pid,
            FileSystemCgroup::from_uid_and_pid_with_reclaim(
                process.uid,
                process.pid,
                ReclaimType::Asynchronous,
            ),
        );
        Ok(true)
    }

    /// Bookkeeping to remove mappings that no longer apply.
    async fn process_remove(&mut self, pid: u32) -> anyhow::Result<bool> {
        if let Some(exe) = self.pid_to_exe.get(&pid) {
            if let Some(processes) = self.exe_to_pids.get_mut(exe) {
                processes.retain(|p| p.pid != pid);
                if processes.is_empty() {
                    self.exe_to_pids.remove(exe);
                }
            }
        }
        self.pid_to_exe.remove(&pid);
        self.pid_to_cgroup.remove(&pid);
        Ok(true)
    }

    fn tick_rate(&self) -> std::time::Duration {
        self.config.tick_rate
    }

    async fn tick(&mut self, _delta_time: std::time::Duration) -> anyhow::Result<()> {
        info!(
            "Starting Memory Budget Enforcement (tick rate {:?})",
            self.tick_rate()
        );
        let budget = config::budget_config();
        let mut memtrack = MemTrackSessionAsync::connect().await?;
        for (exe, enforcements) in budget.processes.iter() {
            if let Some(processes) = self.exe_to_pids.get(exe) {
                for process_info in processes.iter() {
                    if let Err(e) = self
                        .scan_enforcements(&mut memtrack, &process_info, &enforcements)
                        .await
                    {
                        error!(
                            "Failed to Scan Memory Budget For: {}:{} - {e}",
                            process_info.exe, process_info.pid
                        );
                    }
                }
            }
        }
        info!("Memory Budget Enforcement Completed.");
        Ok(())
    }

    async fn cleanup(&mut self) {
        for (pid, cgroup) in self.pid_to_cgroup.iter() {
            if let Err(e) = cgroup.write_memory_high(u64::MAX).await {
                warn!(
                    "Failed to reset memory.high (policy: {}, pid: {pid}): {e:?}",
                    self.name(),
                );
            }
        }
    }
}
