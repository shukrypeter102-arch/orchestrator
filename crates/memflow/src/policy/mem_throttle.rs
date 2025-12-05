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

use anyhow::anyhow;
use anyhow::Context as _;
use async_trait::async_trait;
use hzos_system_native_sysprops::hzos_system_native;
use log::debug;
use log::error;
use log::trace;
use log::warn;
use orchestrator_common::cgroup::CgroupEntry;
use orchestrator_common::cgroup::FileSystemCgroup;
use orchestrator_common::cgroup::ReclaimType;
use orchestrator_common::process_monitor::Policy;
use orchestrator_common::process_monitor::PolicyFactory;
use orchestrator_common::process_monitor::ProcessInfo;
use orchestrator_common::utils::build_memory_stats;
use orchestrator_common::utils::MIB_TO_BYTES;
use tokio::time::Instant;

use crate::policy::SYSTEM_UID;

const MEMORY_HIGH_LOW_THRESHOLD_MIB: u32 = 1; // Set low threshold of memory.high to 1 MB

// List of process names to exclude from memory throttling
// TODO: T237325279 - Move excluded processes list to a config file
const EXCLUDED_PROCESSES: &[&str] = &[
    "com.oculus.vrruntimeservice",
    "vendor.oculus.hardware.sensors@1.0-service",
    "trackingservice",
    "com.oculus.vrshell",
    "com.oculus.mrservice",
    "zygote64",
];

#[derive(Clone, Copy)]
pub struct MemThrottleConfig {
    pub tick_rate: Duration,
    pub throttle_duration: Duration,
}

impl MemThrottleConfig {
    pub fn from_sysprops() -> anyhow::Result<Self> {
        let tick_rate = Duration::from_millis(
            hzos_system_native::memflow_throttle_tick_rate()
                .context("Could not read 'memflow_throttle_tick_rate' sysprop")?
                .context("Value not set on 'memflow_throttle_tick_rate' sysprop")?
                .try_into()
                .context("'memflow_throttle_tick_rate' must be non-negative")?,
        );
        let throttle_duration = Duration::from_millis(
            hzos_system_native::memflow_throttle_duration_ms()
                .context("Could not read 'memflow_throttle_duration_ms' sysprop")?
                .context("Value not set on 'memflow_throttle_duration_ms' sysprop")?
                .try_into()
                .context("'memflow_throttle_duration_ms' must be non-negative")?,
        );

        Ok(Self {
            tick_rate,
            throttle_duration,
        })
    }
}

pub struct MemThrottlePolicyFactory {
    config: MemThrottleConfig,
}

impl MemThrottlePolicyFactory {
    pub fn new(config: MemThrottleConfig) -> Self {
        Self { config }
    }
}

// Exclude process if it is:
// 1. in the excluded process list
// 2. a system service (covered by TMO)
// 3. an immersive app (oom_score_adj = 0)
// 4. in the XR group
// 5. in the foreground
fn is_throttling_exempt(process: &ProcessInfo) -> bool {
    return EXCLUDED_PROCESSES.contains(&process.exe.as_str())
        || process.uid == SYSTEM_UID
        || process.oom_score_adj == 0
        || process.cpu == "xr"
        || process.cpu == "foreground"
        || process.cpu == "top-app";
}

#[async_trait]
impl PolicyFactory for MemThrottlePolicyFactory {
    fn name(&self) -> &'static str {
        "Memory throttle controller"
    }

    async fn create(&self, process: &ProcessInfo) -> anyhow::Result<Option<Box<dyn Policy>>> {
        if is_throttling_exempt(process) {
            debug!("Excluding process {}", process.exe);
            return Ok(None);
        }

        let policy = MemThrottlePolicy::new(
            process.clone(),
            self.config,
            FileSystemCgroup::from_uid_and_pid_with_reclaim(
                process.uid,
                process.pid,
                ReclaimType::Asynchronous,
            ),
        )
        .await?;
        Ok(Some(Box::new(policy)))
    }
}

pub struct MemThrottlePolicy<C: CgroupEntry = FileSystemCgroup> {
    process_info: ProcessInfo,
    config: MemThrottleConfig,
    cgroup: C,
}

impl<C: CgroupEntry> MemThrottlePolicy<C> {
    pub async fn new(
        process_info: ProcessInfo,
        config: MemThrottleConfig,
        cgroup: C,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            process_info,
            config,
            cgroup,
        })
    }
}

#[async_trait]
impl<C: CgroupEntry + Send + Sync> Policy for MemThrottlePolicy<C> {
    fn tick_rate(&self) -> Duration {
        self.config.tick_rate
    }

    async fn tick(&mut self, _delta_time: Duration) -> anyhow::Result<()> {
        const MEMORY_HIGH_TIMEOUT: Duration = Duration::from_millis(5);

        let Self {
            process_info,
            config,
            cgroup,
        } = self;

        let prev_memory_high_watermark = cgroup.memory_high().await?;

        let start = Instant::now();
        cgroup
            .write_memory_high((MEMORY_HIGH_LOW_THRESHOLD_MIB * MIB_TO_BYTES) as u64)
            .await?;

        let elapsed = start.elapsed();
        if elapsed > MEMORY_HIGH_TIMEOUT {
            cgroup.write_memory_high(prev_memory_high_watermark).await?;
            return Err(anyhow!(
                "Writing to memory.high exceeded timeout by {}ms",
                (elapsed - MEMORY_HIGH_TIMEOUT).as_millis()
            ));
        }

        tokio::time::sleep(config.throttle_duration).await;
        cgroup.write_memory_high(prev_memory_high_watermark).await?;

        let wss: i64 = cgroup
            .memory_current()
            .await?
            .try_into()
            .map_err(|_| anyhow!("Memory current value too large to fit in i64"))?;

        let process_memory_info = build_memory_stats(cgroup, &process_info, wss).await?;
        let result = process_memory_info.stats_write();
        // Handle the result
        match result {
            Ok(()) => trace!("Stats logged successfully"),
            Err(e) => error!("Failed to log stats: {:?}", e),
        }
        Ok(())
    }

    async fn cleanup(&mut self) {
        if let Err(e) = self.cgroup.write_memory_high(u64::MAX).await {
            warn!(
                "Failed to reset memory.high (policy: MemThrottlePolicy, pid: {}): {e:?}",
                self.process_info.pid
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use orchestrator_common::cgroup::MockCgroupEntry;

    use super::*;
    use crate::stats::MemoryEvents;
    use crate::stats::MemoryStats;
    use crate::stats::PartialReadout;
    use crate::stats::Stats;
    use crate::utils::tests::create_psi_readout;
    use crate::utils::tests::create_test_process_info;

    fn create_test_config() -> MemThrottleConfig {
        MemThrottleConfig {
            tick_rate: Duration::from_millis(1000),
            throttle_duration: Duration::from_millis(1),
        }
    }

    fn create_psi_partial_readout() -> PartialReadout {
        PartialReadout {
            some: Stats {
                avg10: 1.0,
                avg60: 2.0,
                avg300: 3.0,
                total: 4,
            },
        }
    }

    fn create_memory_events() -> MemoryEvents {
        MemoryEvents {
            low: 1,
            high: 2,
            max: 3,
            oom: 4,
            oom_kill: 5,
        }
    }

    fn create_memory_stats() -> MemoryStats {
        MemoryStats {
            anon: 1,
            file: 2,
            kernel_stack: 3,
            percpu: 4,
            sock: 5,
            shmem: 6,
            file_mapped: 7,
            file_dirty: 8,
            file_writeback: 9,
            inactive_anon: 10,
            active_anon: 11,
            inactive_file: 12,
            active_file: 13,
            unevictable: 14,
            slab_reclaimable: 15,
            slab_unreclaimable: 16,
            slab: 17,
            workingset_refault_anon: 18,
            workingset_refault_file: 19,
            workingset_activate_anon: 20,
            workingset_activate_file: 21,
            workingset_restore_anon: 22,
            workingset_restore_file: 23,
            workingset_nodereclaim: 24,
            pgfault: 25,
            pgmajfault: 26,
            pgrefill: 27,
            pgscan: 28,
            pgsteal: 29,
            pgactivate: 30,
            pgdeactivate: 31,
            pglazyfree: 32,
            pglazyfreed: 33,
        }
    }

    async fn create_test_policy_with_mock(
        initial_memory_high: u64,
    ) -> MemThrottlePolicy<MockCgroupEntry> {
        let mut mock_cgroup = MockCgroupEntry::new();
        let process_info = create_test_process_info();
        let config: MemThrottleConfig = create_test_config();

        // Set up initial expectations for the memory values.
        // The mock expectations will verify that:
        // 1. memory_high() was called to get the initial value
        // 2. write_memory_high(MEMORY_HIGH_THRESHOLD) was called for throttling
        // 3. write_memory_high(initial_memory_high) was called to restore the original value

        mock_cgroup
            .expect_memory_high()
            .times(1)
            .returning(move || Box::pin(async move { Ok(initial_memory_high) }));

        mock_cgroup
            .expect_write_memory_high()
            .with(mockall::predicate::eq(
                (MEMORY_HIGH_LOW_THRESHOLD_MIB * MIB_TO_BYTES) as u64,
            ))
            .times(1)
            .returning(|_| Box::pin(async move { Ok(()) }));

        mock_cgroup
            .expect_write_memory_high()
            .with(mockall::predicate::eq(initial_memory_high))
            .times(1)
            .returning(|_| Box::pin(async move { Ok(()) }));

        mock_cgroup
            .expect_memory_current()
            .times(2)
            .returning(move || Box::pin(async move { Ok(0) }));

        mock_cgroup
            .expect_memory_swap_current()
            .times(1)
            .returning(|| Box::pin(async move { Ok(0) }));

        // Set up expectations for pressure and stats calls (needed by build_memory_stats)
        mock_cgroup
            .expect_cpu_pressure()
            .times(1)
            .returning(|| Box::pin(async move { Ok(create_psi_partial_readout()) }));

        mock_cgroup
            .expect_io_pressure()
            .times(1)
            .returning(|| Box::pin(async move { Ok(create_psi_readout(0)) }));

        mock_cgroup
            .expect_memory_pressure()
            .times(1)
            .returning(|| Box::pin(async move { Ok(create_psi_readout(0)) }));

        mock_cgroup
            .expect_memory_stats()
            .times(1)
            .returning(|| Box::pin(async move { Ok(create_memory_stats()) }));

        mock_cgroup
            .expect_memory_events()
            .times(1)
            .returning(|| Box::pin(async move { Ok(create_memory_events()) }));

        MemThrottlePolicy::new(process_info, config, mock_cgroup)
            .await
            .unwrap()
    }

    /// Test that memory_high is restored to its original value after throttling
    #[tokio::test]
    async fn test_throttling_normal_case() {
        let initial_memory_high = 8 * 1024 * 1024; // 8MB

        let mut policy = create_test_policy_with_mock(initial_memory_high).await;

        // Execute the policy tick
        let result = policy.tick(Duration::from_secs(1)).await;

        // Verify the policy executed successfully
        assert!(result.is_ok(), "Policy tick should succeed");
    }

    /// Test that memory_high is stored to original value if it is oroginally set to max
    #[tokio::test]
    async fn test_throttling_max_case() {
        let initial_memory_high = u64::MAX; // Max

        let mut policy = create_test_policy_with_mock(initial_memory_high).await;

        // Execute the policy tick
        let result = policy.tick(Duration::from_secs(1)).await;

        // Verify the policy executed successfully
        assert!(result.is_ok(), "Policy tick should succeed");
    }
}
