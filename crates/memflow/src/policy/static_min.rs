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

use std::collections::HashMap;
use std::time::Duration;

use anyhow::bail;
use anyhow::Context as _;
use async_trait::async_trait;
use hzos_system_native_sysprops::hzos_system_native;
use log::warn;
use orchestrator_common::cgroup::CgroupEntry;
use orchestrator_common::cgroup::FileSystemCgroup;
use orchestrator_common::process_monitor::AggregatePolicy;
use orchestrator_common::process_monitor::ProcessInfo;
use orchestrator_common::utils::MIB_TO_BYTES;

pub struct StaticMinConfig {
    exe_to_bytes: HashMap<String, u64>,
    tick_rate: Duration,
}

impl StaticMinConfig {
    pub fn from_sysprops() -> anyhow::Result<Self> {
        let mb_csv = hzos_system_native::memflow_staticexp_list()
            .context("Could not read 'memflow_staticexp_list' sysprop")?
            .context("Value not set on 'memflow_staticexp_list' sysprop")?;
        let tick_rate = Duration::from_millis(
            hzos_system_native::memflow_staticexp_tick_rate()
                .context("Could not read 'memflow_staticexp_tick_rate' sysprop")?
                .context("Value not set on 'memflow_staticexp_tick_rate' sysprop")?
                .try_into()
                .context("'memflow_staticexp_tick_rate' must be non-negative")?,
        );

        const EXE_NAMES: [&str; 5] = [
            "vendor.oculus.hardware.sensors@1.0-flicker",
            "vendor.oculus.hardware.sensors@1.0-iad",
            "vendor.oculus.hardware.sensors@1.0-service",
            "mrsystemservice",
            "trackingservice",
        ];

        let iterator = mb_csv.split(",");

        if iterator.clone().count() != EXE_NAMES.len() {
            bail!("Invalid number of entries in sysprop");
        }

        let mut exe_to_bytes = HashMap::new();
        for (index, item) in iterator.enumerate() {
            let bytes_mb = item
                .parse::<f64>()
                .context("Failed to parse MB value from sysprop")?;
            let bytes = (bytes_mb * MIB_TO_BYTES as f64) as u64;
            exe_to_bytes.insert(
                EXE_NAMES
                    .get(index)
                    .context("Invalid number of entries in sysprop")?
                    .to_string(),
                bytes,
            );
        }

        Ok(Self {
            exe_to_bytes,
            tick_rate,
        })
    }
}

struct PidEntry {
    info: ProcessInfo,
    cgroup: FileSystemCgroup,
    min_bytes: u64,
}

struct UidEntry {
    cgroup: FileSystemCgroup,
    min_bytes: u64,
}

pub struct StaticMinPolicy {
    config: StaticMinConfig,
    pid_to_entry: HashMap<u32, PidEntry>,
    uid_to_entry: HashMap<u32, UidEntry>,
}

impl StaticMinPolicy {
    pub fn new(config: StaticMinConfig) -> Self {
        Self {
            config,
            pid_to_entry: HashMap::new(),
            uid_to_entry: HashMap::new(),
        }
    }
}

#[async_trait]
impl AggregatePolicy for StaticMinPolicy {
    fn name(&self) -> &'static str {
        "StaticMin"
    }

    async fn process_create(&mut self, process: &ProcessInfo) -> anyhow::Result<bool> {
        if let Some(bytes) = self.config.exe_to_bytes.get(&process.exe) {
            self.pid_to_entry.insert(
                process.pid,
                PidEntry {
                    info: process.clone(),
                    cgroup: FileSystemCgroup::from_uid_and_pid(process.uid, process.pid),
                    min_bytes: *bytes,
                },
            );

            self.uid_to_entry
                .entry(process.uid)
                .and_modify(|entry| entry.min_bytes += *bytes)
                .or_insert(UidEntry {
                    cgroup: FileSystemCgroup::from_uid(process.uid),
                    min_bytes: *bytes,
                });

            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn process_remove(&mut self, pid: u32) -> anyhow::Result<bool> {
        if let Some(pid_entry) = self.pid_to_entry.remove(&pid) {
            self.uid_to_entry
                .entry(pid_entry.info.uid)
                .and_modify(|entry| entry.min_bytes -= pid_entry.min_bytes);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn tick_rate(&self) -> Duration {
        self.config.tick_rate
    }

    async fn tick(&mut self, _delta_time: Duration) -> anyhow::Result<()> {
        for entry in self.pid_to_entry.values() {
            entry.cgroup.write_memory_min(entry.min_bytes).await?;
        }

        for entry in self.uid_to_entry.values() {
            entry.cgroup.write_memory_min(entry.min_bytes).await?;
        }

        Ok(())
    }

    async fn cleanup(&mut self) {
        for (pid, entry) in self.pid_to_entry.iter() {
            if let Err(e) = entry.cgroup.write_memory_min(0).await {
                warn!(
                    "Failed to reset memory.min (policy: {}, pid: {pid}): {e:?}",
                    self.name(),
                );
            }
        }

        for (uid, entry) in self.uid_to_entry.iter() {
            if let Err(e) = entry.cgroup.write_memory_min(0).await {
                warn!(
                    "Failed to reset memory.min (policy: {}, uid: {uid}): {e:?}",
                    self.name(),
                );
            }
        }
    }
}
