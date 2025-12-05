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

use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use hzos_system_native_sysprops::hzos_system_native;
use log::error;
use log::trace;
use log::warn;
use orchestrator_common::cgroup::CgroupEntry;
use orchestrator_common::cgroup::FileSystemCgroup;
use orchestrator_common::process_monitor::Policy;
use orchestrator_common::process_monitor::PolicyFactory;
use orchestrator_common::process_monitor::ProcessInfo;
use orchestrator_common::utils::build_memory_stats;

#[derive(Clone, Copy)]
pub struct TelemetryConfig {
    pub tick_rate: Duration,
    pub sysexp_enabled: bool,
    pub syssenpaiexp_enabled: bool,
}

impl TelemetryConfig {
    pub fn from_sysprops() -> anyhow::Result<Self> {
        let tick_rate = Duration::from_millis(
            hzos_system_native::memflow_telemetry_tick_rate()
                .context("Could not read 'memflow_telemetry_tick_rate' sysprop")?
                .context("Value not set on 'memflow_telemetry_tick_rate' sysprop")?
                .try_into()
                .context("'memflow_telemetry_tick_rate' must be non-negative")?,
        );

        let sysexp_enabled = hzos_system_native::memflow_sysexp()
            .unwrap_or_else(|e| {
                warn!("Could not read 'memflow_sysexp' sysprop: {e:?}, Defaulting to false");
                None
            })
            .unwrap_or(false);

        let syssenpaiexp_enabled: bool = hzos_system_native::memflow_syssenpaiexp()
            .unwrap_or_else(|e| {
                warn!("Could not read 'memflow_syssenpaiexp' sysprop: {e:?}, Defaulting to false");
                None
            })
            .unwrap_or(false);

        Ok(Self {
            tick_rate,
            sysexp_enabled,
            syssenpaiexp_enabled,
        })
    }
}

pub struct TelemetryPolicyFactory {
    config: TelemetryConfig,
}

impl TelemetryPolicyFactory {
    pub fn new(config: TelemetryConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl PolicyFactory for TelemetryPolicyFactory {
    fn name(&self) -> &'static str {
        "Telemetry Controller"
    }

    async fn create(&self, process: &ProcessInfo) -> anyhow::Result<Option<Box<dyn Policy>>> {
        let policy = TelemetryPolicy::new(process.clone(), self.config).await?;
        Ok(Some(Box::new(policy)))
    }
}

pub struct TelemetryPolicy {
    process_info: ProcessInfo,
    config: TelemetryConfig,
    cgroup: FileSystemCgroup,
}

impl TelemetryPolicy {
    pub async fn new(process_info: ProcessInfo, config: TelemetryConfig) -> anyhow::Result<Self> {
        let cgroup: FileSystemCgroup =
            FileSystemCgroup::from_uid_and_pid(process_info.uid, process_info.pid);

        Ok(Self {
            process_info,
            config,
            cgroup,
        })
    }
}

#[async_trait]
impl Policy for TelemetryPolicy {
    fn tick_rate(&self) -> Duration {
        self.config.tick_rate
    }
    #[allow(unused_variables)]
    async fn tick(&mut self, delta_time: Duration) -> anyhow::Result<()> {
        let Self {
            process_info,
            config,
            cgroup,
        } = self;

        // When TMO experiments log WSS for system services only (since they're only enabled for systme services currently)
        let wss = {
            if process_info.uid == 1000 && (config.sysexp_enabled || config.syssenpaiexp_enabled) {
                cgroup
                    .memory_current()
                    .await
                    .map(|val| val as i64)
                    .unwrap_or_else(|_| {
                        warn!("Could not read memory.current for {}", process_info.uid);
                        -1
                    })
            } else {
                -1
            }
        };

        let process_memory_info = build_memory_stats(cgroup, &process_info, wss).await?;

        let result = process_memory_info.stats_write();

        // Handle the result
        match result {
            Ok(()) => trace!("Memflow stats logged successfully"),
            Err(e) => error!("Failed to log memflow stats: {:?}", e),
        }

        Ok(())
    }

    async fn cleanup(&mut self) {
        // No-op: No cleanup needed as telemetry policy doesn't modify cgroup nodes
    }
}
