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
use hzos_power_manager::Event;
use hzos_power_manager::PowerManagerSession;
use hzos_power_manager::PowerState;
use hzos_soft_error::soft_error;
use hzos_system_native_sysprops::hzos_system_native;
use log::error;
use log::trace;
use log::warn;
use orchestrator_common::cgroup::CgroupEntry;
use orchestrator_common::cgroup::FileSystemCgroup;
use orchestrator_common::process_monitor::Policy;
use orchestrator_common::process_monitor::PolicyFactory;
use orchestrator_common::process_monitor::ProcessInfo;
use orchestrator_common::utils::KIB_TO_BYTES;
use tokio::sync::watch;
use tokio_stream::StreamExt as _;

use crate::policy::human_bytes;
use crate::policy::SYSTEM_UID;

struct FileIO<C: CgroupEntry> {
    entry: C,
    limit_min: u64,
    limit_max: u64,
    last_written_limit: Option<u64>,
}

impl<C: CgroupEntry> FileIO<C> {
    fn new(entry: C, min: u64, max: u64) -> Self {
        Self {
            entry,
            limit_min: min,
            limit_max: max,
            last_written_limit: None,
        }
    }

    #[inline]
    fn sanitize_limit(&self, mut limit: u64) -> u64 {
        // Clamp to configured bounds
        if limit < self.limit_min {
            limit = self.limit_min;
        }
        if limit > self.limit_max {
            limit = self.limit_max;
        }

        // Round to 4KB boundary
        limit & !4095
    }

    /// Ensure we are writing against the kernel's current value.
    /// If external change or first write, reset to memory.current *without* applying the caller's factor.
    async fn maybe_reset_to_current(&mut self) -> anyhow::Result<bool> {
        let kernel_high = self.entry.memory_high().await?;

        if self.last_written_limit != Some(kernel_high) {
            warn!("Mismatch between kernel and last written limit, resetting to current");

            let cur = self.entry.memory_current().await?;
            let new_limit = self.sanitize_limit(cur);
            self.entry.write_memory_high(new_limit).await?;
            self.last_written_limit = Some(new_limit);
            return Ok(true);
        }

        Ok(false)
    }

    /// Adjust memory.high by a multiplicative factor (e.g., +0.1 loosens 10%, -0.01 tightens 1%).
    ///
    /// If kernel value changed externally, we reset to current and **skip** this adjustment
    async fn adjust_by_factor(&mut self, factor: f64) -> anyhow::Result<()> {
        if self.maybe_reset_to_current().await? {
            return Ok(());
        }

        let base = self.entry.memory_high().await?;

        // If "max", use max_size as a sensible base to avoid overflow.
        let base = if base == u64::MAX {
            self.limit_max
        } else {
            base
        };

        // Factor can be negative; clamp above zero before sanitize + clamp again.
        let proposed = if factor >= -1.0 {
            (base as f64 * (1.0 + factor)).max(0.0).round() as u64
        } else {
            0
        };

        let new_limit = self.sanitize_limit(proposed);
        self.entry.write_memory_high(new_limit).await?;
        self.last_written_limit = Some(new_limit);

        Ok(())
    }
}

#[derive(Clone, Copy)]
pub struct SenpaiConfig {
    pub min_size: u64,
    pub max_size: u64,
    pub interval: u32,
    pub pressure: u64,
    pub max_probe: f64,
    pub max_backoff: f64,
    pub coeff_probe: f64,
    pub coeff_backoff: f64,
    pub tick_rate: Duration,
}

impl SenpaiConfig {
    pub fn from_sysprops() -> anyhow::Result<Self> {
        let min_size: u64 = hzos_system_native::memflow_syssenpaiexp_min_size()
            .context("Could not read 'memflow_syssenpaiexp_min_size' sysprop")?
            .context("Value not set on 'memflow_syssenpaiexp_min_size' sysprop")?
            .try_into()
            .context("'memflow_syssenpaiexp_min_size' must be non-negative")?;
        let max_size: u64 = hzos_system_native::memflow_syssenpaiexp_max_size()
            .context("Could not read 'memflow_syssenpaiexp_max_size' sysprop")?
            .context("Value not set on 'memflow_syssenpaiexp_max_size' sysprop")?
            .try_into()
            .context("'memflow_syssenpaiexp_max_size' must be non-negative")?;
        let interval: u32 = hzos_system_native::memflow_syssenpaiexp_interval()
            .context("Could not read 'memflow_syssenpaiexp_interval' sysprop")?
            .context("Value not set on 'memflow_syssenpaiexp_interval' sysprop")?
            .try_into()
            .context("'memflow_syssenpaiexp_interval' must be non-negative")?;
        let pressure: u64 = hzos_system_native::memflow_syssenpaiexp_pressure()
            .context("Could not read 'memflow_syssenpaiexp_pressure' sysprop")?
            .context("Value not set on 'memflow_syssenpaiexp_pressure' sysprop")?
            .try_into()
            .context("'memflow_syssenpaiexp_pressure' must be non-negative")?;
        let max_probe = hzos_system_native::memflow_syssenpaiexp_max_probe()
            .context("Could not read 'memflow_syssenpaiexp_max_probe' sysprop")?
            .context("Value not set on 'memflow_syssenpaiexp_max_probe' sysprop")?;
        let max_backoff = hzos_system_native::memflow_syssenpaiexp_max_backoff()
            .context("Could not read 'memflow_syssenpaiexp_max_backoff' sysprop")?
            .context("Value not set on 'memflow_syssenpaiexp_max_backoff' sysprop")?;
        let coeff_probe = hzos_system_native::memflow_syssenpaiexp_coeff_probe()
            .context("Could not read 'memflow_syssenpaiexp_coeff_probe' sysprop")?
            .context("Value not set on 'memflow_syssenpaiexp_coeff_probe' sysprop")?;
        let coeff_backoff = hzos_system_native::memflow_syssenpaiexp_coeff_backoff()
            .context("Could not read 'memflow_syssenpaiexp_coeff_backoff' sysprop")?
            .context("Value not set on 'memflow_syssenpaiexp_coeff_backoff' sysprop")?;
        let tick_rate = Duration::from_millis(
            hzos_system_native::memflow_syssenpaiexp_tick_rate()
                .context("Could not read 'memflow_syssenpaiexp_tick_rate' sysprop")?
                .context("Value not set on 'memflow_syssenpaiexp_tick_rate' sysprop")?
                .try_into()
                .context("'memflow_syssenpaiexp_tick_rate' must be non-negative")?,
        );

        Ok(Self {
            min_size: min_size * (KIB_TO_BYTES as u64),
            max_size: max_size * (KIB_TO_BYTES as u64),
            interval,
            pressure,
            max_probe,
            max_backoff,
            coeff_probe,
            coeff_backoff,
            tick_rate,
        })
    }
}

pub struct SenpaiPolicyFactory {
    config: SenpaiConfig,
    power_state_stream: watch::Receiver<Option<PowerState>>,
}

impl SenpaiPolicyFactory {
    pub fn new(config: SenpaiConfig) -> Self {
        let (tx, rx) = watch::channel(None);

        tokio::task::spawn(async move {
            loop {
                let session = match PowerManagerSession::connect().await {
                    Ok(session) => session,
                    Err(e) => {
                        soft_error!("Could not connect to PowerManagerSession: {e:?}");
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        continue;
                    }
                };

                let mut client = match session.register_client().await {
                    Ok(client) => client,
                    Err(e) => {
                        soft_error!(
                            "Could not connect to register client in PowerManagerSession: {e:?}"
                        );
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        continue;
                    }
                };

                while let Some(Event::StateChange { state }) = client.next().await {
                    if let Err(e) = tx.send(Some(state)) {
                        error!("Failed to send event: {e:?}");
                    }
                }
            }
        });

        Self {
            config,
            power_state_stream: rx,
        }
    }
}

#[async_trait]
impl PolicyFactory for SenpaiPolicyFactory {
    fn name(&self) -> &'static str {
        "Senpai System"
    }

    async fn create(&self, process: &ProcessInfo) -> anyhow::Result<Option<Box<dyn Policy>>> {
        if process.uid == SYSTEM_UID {
            let policy = SenpaiPolicy::new(
                process.clone(),
                self.config,
                FileSystemCgroup::from_uid_and_pid(process.uid, process.pid),
                self.power_state_stream.clone(),
            )
            .await?;
            Ok(Some(Box::new(policy)))
        } else {
            Ok(None)
        }
    }
}

pub struct SenpaiPolicy<C: CgroupEntry = FileSystemCgroup> {
    process_info: ProcessInfo,
    config: SenpaiConfig,
    integral_us: u64,
    grace_ticks: u64,
    last_pressure: u64,
    io: FileIO<C>,
    power_state_stream: watch::Receiver<Option<PowerState>>,
}

impl<C: CgroupEntry> SenpaiPolicy<C> {
    pub async fn new(
        process_info: ProcessInfo,
        config: SenpaiConfig,
        cgroup: C,
        power_state_stream: watch::Receiver<Option<PowerState>>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            process_info,
            config,
            integral_us: 0,
            grace_ticks: config.interval as u64,
            last_pressure: 0,
            io: FileIO::new(cgroup, config.min_size as u64, config.max_size as u64),
            power_state_stream,
        })
    }
}

#[async_trait]
impl<C: CgroupEntry + Send + Sync> Policy for SenpaiPolicy<C> {
    fn tick_rate(&self) -> Duration {
        self.config.tick_rate
    }

    async fn tick(&mut self, _delta_time: Duration) -> anyhow::Result<()> {
        let Self {
            process_info,
            config,
            integral_us,
            grace_ticks,
            last_pressure,
            io,
            power_state_stream,
        } = self;

        if *power_state_stream.borrow() != Some(PowerState::HeadsetMounted) {
            trace!(
                "Skipping policy tick for (pid: {}, exe: {}), headset is not donned",
                process_info.pid,
                process_info.exe
            );

            *last_pressure = 0;
            *integral_us = 0;
            *grace_ticks = config.interval as u64;
            io.entry.write_memory_high(u64::MAX).await?;

            return Ok(());
        }

        let current_pressure = io.entry.memory_pressure().await?.some.total;
        let delta_pressure = current_pressure - *last_pressure;
        *last_pressure = current_pressure;

        *integral_us += delta_pressure;

        trace!(
            "Process ({}, {}, {}): {}us high={}",
            process_info.pid,
            process_info.comm,
            process_info.oom_score_adj,
            *integral_us,
            human_bytes(io.entry.memory_high().await?)
        );

        if *integral_us > config.pressure as u64 {
            let err = *integral_us as f64 / config.pressure as f64;
            let mut adj = (err / config.coeff_backoff).powi(2);
            adj = (adj * config.max_backoff).min(config.max_backoff);

            io.adjust_by_factor(adj).await?;
            *integral_us = 0;

            *grace_ticks = config.interval.saturating_sub(1) as u64;

            return Ok(());
        }

        // Grace period
        if *grace_ticks > 0 {
            *grace_ticks -= 1;
            return Ok(());
        }

        // Probe: tighten when pressure is below target
        let denom = (*integral_us).max(1) as f64;
        let err = config.pressure as f64 / denom;
        let mut adj = (err / config.coeff_probe).powi(2);
        adj = (adj * config.max_probe).min(config.max_probe);

        io.adjust_by_factor(-adj).await?;
        *integral_us = 0;

        *grace_ticks = config.interval.saturating_sub(1) as u64;
        Ok(())
    }

    async fn cleanup(&mut self) {
        if let Err(e) = self.io.entry.write_memory_high(u64::MAX).await {
            warn!(
                "Failed to reset memory.high (policy: SenpaiPolicy, pid: {}): {e:?}",
                self.process_info.pid
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use orchestrator_common::cgroup::MockCgroupEntry;
    use tokio::sync::watch::Sender;

    use super::*;
    use crate::utils::tests::create_psi_readout;
    use crate::utils::tests::create_test_process_info;

    fn create_test_config() -> SenpaiConfig {
        SenpaiConfig {
            min_size: 4096,                    // 4KB
            max_size: 1048576,                 // 1MB
            interval: 5,                       // 5 ticks
            pressure: 1000,                    // 1000 microseconds
            max_probe: 0.1,                    // 10% max probe adjustment
            max_backoff: 0.2,                  // 20% max backoff adjustment
            coeff_probe: 10.0,                 // Probe coefficient
            coeff_backoff: 10.0,               // Backoff coefficient
            tick_rate: Duration::from_secs(1), // Not actually used since we will be manually ticking
        }
    }

    async fn create_test_policy_with_mock(
        config: SenpaiConfig,
        initial_pressure: u64,
        initial_memory_high: u64,
    ) -> (Sender<Option<PowerState>>, SenpaiPolicy<MockCgroupEntry>) {
        let mock_cgroup = MockCgroupEntry::new();
        let process_info = create_test_process_info();
        let (tx, rx) = watch::channel(Some(PowerState::HeadsetMounted));

        let mut policy = SenpaiPolicy::new(process_info, config, mock_cgroup, rx)
            .await
            .unwrap();

        // Initialize last_written_limit to prevent maybe_reset_to_current from triggering
        policy.io.last_written_limit = Some(initial_memory_high);
        policy.last_pressure = initial_pressure;

        (tx, policy)
    }

    /// Test 1: Pressure is at config.pressure, no change in output
    #[tokio::test]
    async fn test_pressure_at_target_no_change() {
        let config = create_test_config();
        let initial_pressure = config.pressure;
        let initial_memory_high = 4 * (KIB_TO_BYTES as u64); // 4KB

        let (_, mut policy) =
            create_test_policy_with_mock(config, initial_pressure, initial_memory_high).await;

        // Set integral_us to exactly config.pressure
        policy.integral_us = config.pressure as u64;
        policy.last_pressure = config.pressure;

        policy
            .io
            .entry
            .expect_memory_pressure()
            .times(1)
            .returning(move || Box::pin(async move { Ok(create_psi_readout(initial_pressure)) }));

        // Should not call write_memory_high since we're exactly at the pressure target
        // Grace period should trigger instead

        let result = policy.tick(Duration::from_secs(1)).await;
        assert!(result.is_ok());
        assert_eq!(policy.grace_ticks, (config.interval - 1) as u64);
        assert_eq!(policy.integral_us, config.pressure as u64);
    }

    /// Test 2: Pressure exceeds config.pressure, verify we adjust output up by correct factor
    #[tokio::test]
    async fn test_pressure_exceeds_target_backoff() {
        let config = create_test_config();
        let initial_pressure = 5000;
        let initial_memory_high = 8192; // 8KB

        let (_, mut policy) =
            create_test_policy_with_mock(config, initial_pressure, initial_memory_high).await;

        // Set initial integral_us to exceed pressure
        policy.integral_us = 2000; // Exceeds config.pressure (1000)

        let current_pressure = initial_pressure; // No delta

        policy
            .io
            .entry
            .expect_memory_pressure()
            .times(1)
            .returning(move || Box::pin(async move { Ok(create_psi_readout(current_pressure)) }));

        policy
            .io
            .entry
            .expect_memory_high()
            .times(2) // Only called once in adjust_by_factor since maybe_reset_to_current won't trigger
            .returning(move || Box::pin(async move { Ok(initial_memory_high) }));

        // Calculate expected adjustment
        let err = 2000.0 / config.pressure as f64; // 2.0
        let mut adj = (err / config.coeff_backoff).powi(2); // (2.0 / 10.0)^2 = 0.04
        adj = (adj * config.max_backoff).min(config.max_backoff); // min(0.04 * 0.2, 0.2) = 0.008

        let expected_new_limit =
            ((initial_memory_high as f64 * (1.0 + adj)).round() as u64) & !4095;

        policy
            .io
            .entry
            .expect_write_memory_high()
            .times(1)
            .returning(move |value| {
                assert_eq!(
                    value, expected_new_limit,
                    "Expected memory limit to be {}, got {}",
                    expected_new_limit, value
                );
                Box::pin(async move { Ok(()) })
            });

        let result = policy.tick(Duration::from_secs(1)).await;
        assert!(result.is_ok());
        assert_eq!(policy.integral_us, 0); // Should be reset
        assert_eq!(policy.grace_ticks, config.interval.saturating_sub(1) as u64);
    }

    /// Test 3: Pressure below target for grace_ticks, verify downward adjustment
    #[tokio::test]
    async fn test_pressure_below_target_probe() {
        let config = create_test_config();
        let initial_pressure = 5000;
        let initial_memory_high = 8192; // 8KB

        let (_, mut policy) =
            create_test_policy_with_mock(config, initial_pressure, initial_memory_high).await;

        // Set integral_us below pressure and grace_ticks to 0
        policy.integral_us = 500; // Below config.pressure
        policy.grace_ticks = 0; // Grace period expired

        let current_pressure = initial_pressure; // No delta

        policy
            .io
            .entry
            .expect_memory_pressure()
            .times(1)
            .returning(move || Box::pin(async move { Ok(create_psi_readout(current_pressure)) }));

        // For this test, `maybe_reset_to_current()` will NOT be triggered because
        // we initialized `last_written_limit` to match `initial_memory_high`
        policy
            .io
            .entry
            .expect_memory_high()
            .times(2) // Only called once since maybe_reset_to_current won't trigger
            .returning(move || Box::pin(async move { Ok(initial_memory_high) }));

        // Calculate expected probe adjustment
        let denom = policy.integral_us.max(1) as f64; // 500.0
        let err = config.pressure as f64 / denom; // 1000.0 / 500.0 = 2.0
        let mut adj = (err / config.coeff_probe).powi(2); // (2.0 / 10.0)^2 = 0.04
        adj = (adj * config.max_probe).min(config.max_probe); // min(0.04 * 0.1, 0.1) = 0.004

        let expected_new_limit = if adj >= 1.0 {
            0
        } else {
            ((initial_memory_high as f64 * (1.0 - adj)).round() as u64) & !4095
        };

        policy
            .io
            .entry
            .expect_write_memory_high()
            .times(1)
            .returning(move |value| {
                assert_eq!(
                    value, expected_new_limit,
                    "Expected memory limit to be {}, got {}",
                    expected_new_limit, value
                );
                Box::pin(async move { Ok(()) })
            });

        let result = policy.tick(Duration::from_secs(1)).await;
        assert!(result.is_ok());
        assert_eq!(policy.integral_us, 0); // Should be reset
        assert_eq!(policy.grace_ticks, config.interval.saturating_sub(1) as u64);
    }

    /// Test 4: Verify exponential adjustment of the output
    #[tokio::test]
    async fn test_exponential_adjustment() {
        let config = create_test_config();
        let initial_pressure = 5000;
        let initial_memory_high = 8192; // 8KB

        // Test with different error levels to verify exponential behavior
        let test_cases = vec![
            (2000, "2x pressure"), // err = 2.0
            (3000, "3x pressure"), // err = 3.0
            (4000, "4x pressure"), // err = 4.0
        ];

        for (integral_us, description) in test_cases {
            let (_, mut policy) =
                create_test_policy_with_mock(config, initial_pressure, initial_memory_high).await;

            policy.integral_us = integral_us;

            let current_pressure = initial_pressure;

            policy
                .io
                .entry
                .expect_memory_pressure()
                .times(1)
                .returning(move || {
                    Box::pin(async move { Ok(create_psi_readout(current_pressure)) })
                });

            policy
                .io
                .entry
                .expect_memory_high()
                .times(2) // Only called once since maybe_reset_to_current won't trigger
                .returning(move || Box::pin(async move { Ok(initial_memory_high) }));

            // Calculate expected exponential adjustment
            let err = integral_us as f64 / config.pressure as f64;
            let mut adj = (err / config.coeff_backoff).powi(2); // Exponential: err^2
            adj = (adj * config.max_backoff).min(config.max_backoff);

            let expected_new_limit =
                ((initial_memory_high as f64 * (1.0 + adj)).round() as u64) & !4095;

            policy
                .io
                .entry
                .expect_write_memory_high()
                .times(1)
                .returning(move |value| {
                    assert_eq!(
                        value, expected_new_limit,
                        "Expected memory limit to be {}, got {}",
                        expected_new_limit, value
                    );
                    Box::pin(async move { Ok(()) })
                });

            let result = policy.tick(Duration::from_secs(1)).await;
            assert!(result.is_ok(), "Failed for case: {}", description);

            // Verify exponential scaling: higher error should result in higher adjustment
            let computed_adj = (err / config.coeff_backoff).powi(2) * config.max_backoff;
            let clamped_adj = computed_adj.min(config.max_backoff);

            // For higher errors, we should see higher adjustments (until clamped)
            if integral_us == 2000 {
                assert!(
                    clamped_adj > 0.0,
                    "Should have positive adjustment for {}",
                    description
                );
            }
        }
    }

    /// Test 5: Grace period behavior
    #[tokio::test]
    async fn test_grace_period_behavior() {
        let config = create_test_config();
        let initial_pressure = 5000;
        let initial_memory_high = 8192; // 8KB

        let (_, mut policy) =
            create_test_policy_with_mock(config, initial_pressure, initial_memory_high).await;

        // Set grace_ticks to a positive value
        policy.grace_ticks = 3;
        policy.integral_us = 100; // Below pressure

        let mut current_pressure = initial_pressure;

        for i in (1..=3).rev() {
            // Increase the pressure a constant step every tick
            current_pressure += 50;

            policy
                .io
                .entry
                .expect_memory_pressure()
                .times(1)
                .returning(move || {
                    Box::pin(async move { Ok(create_psi_readout(current_pressure)) })
                });

            // During grace period, no memory operations should occur
            let result = policy.tick(Duration::from_secs(1)).await;
            assert!(result.is_ok());
            assert_eq!(policy.grace_ticks, i - 1);

            // integral_us should accumulate during grace period
            // Starting from 100, adding 50 each tick: 150, 200, 250
            assert_eq!(policy.integral_us, 100 + 50 * (4 - i));
        }
    }

    /// Test: Memory limit sanitization and clamping
    #[tokio::test]
    async fn test_memory_limit_clamping() {
        let mut config = create_test_config();
        config.min_size = 8192; // 8KB
        config.max_size = 16384; // 16KB

        let initial_pressure = 5000;
        let initial_memory_high = 12288; // 12KB

        let (_, mut policy) =
            create_test_policy_with_mock(config, initial_pressure, initial_memory_high).await;

        // Test extreme downward adjustment that should be clamped to min_size
        policy.integral_us = 100; // Very low, should cause large downward adjustment
        policy.grace_ticks = 0;

        let current_pressure = initial_pressure;

        policy
            .io
            .entry
            .expect_memory_pressure()
            .times(1)
            .returning(move || Box::pin(async move { Ok(create_psi_readout(current_pressure)) }));

        policy
            .io
            .entry
            .expect_memory_high()
            .times(2) // Only called once since maybe_reset_to_current won't trigger
            .returning(move || Box::pin(async move { Ok(initial_memory_high) }));

        // The adjustment should be clamped to min_size and aligned to 4KB boundary
        let expected_new_limit = config.min_size & !4095;

        policy
            .io
            .entry
            .expect_write_memory_high()
            .times(1)
            .returning(move |value| {
                assert!(
                    value >= expected_new_limit,
                    "Expected memory limit to be >= {}, got {}",
                    expected_new_limit,
                    value
                );
                Box::pin(async move { Ok(()) })
            });

        let result = policy.tick(Duration::from_secs(1)).await;
        assert!(result.is_ok());
    }

    /// Test: Edge case with zero integral_us
    #[tokio::test]
    async fn test_zero_integral_probe() {
        let config = create_test_config();
        let initial_pressure = 5000;
        let initial_memory_high = 8192; // 8KB

        let (_, mut policy) =
            create_test_policy_with_mock(config, initial_pressure, initial_memory_high).await;

        // Set integral_us to 0 and grace_ticks to 0
        policy.integral_us = 0;
        policy.grace_ticks = 0;

        let current_pressure = initial_pressure; // No delta

        policy
            .io
            .entry
            .expect_memory_pressure()
            .times(1)
            .returning(move || Box::pin(async move { Ok(create_psi_readout(current_pressure)) }));

        policy
            .io
            .entry
            .expect_memory_high()
            .times(2) // Only called once since maybe_reset_to_current won't trigger
            .returning(move || Box::pin(async move { Ok(initial_memory_high) }));

        // With integral_us = 0, denom becomes max(0, 1) = 1
        // err = 1000.0 / 1.0 = 1000.0
        // adj = (1000.0 / 10.0)^2 * 0.1 = 10000.0 * 0.1 = 1000.0, clamped to 0.1
        // let expected_adj = config.max_probe; // Should be clamped

        // Since adj > 1.0 when clamped, the result should be 0 or min_size
        policy
            .io
            .entry
            .expect_write_memory_high()
            .times(1)
            .returning(move |value| {
                assert!(
                    value <= config.min_size,
                    "Expected memory limit to be <= {}, got {}",
                    config.min_size,
                    value
                );
                Box::pin(async move { Ok(()) })
            });

        let result = policy.tick(Duration::from_secs(1)).await;
        assert!(result.is_ok());
    }

    /// Test: Policy resets when headset is not donned
    #[tokio::test]
    async fn test_policy_resets_when_headset_not_donned() {
        let config = create_test_config();
        let initial_pressure = 5000;
        let initial_memory_high = 8192; // 8KB

        let (tx, mut policy) =
            create_test_policy_with_mock(config, initial_pressure, initial_memory_high).await;

        // Build up some state by running a few ticks with mounted headset
        policy.integral_us = 1500;
        policy.last_pressure = initial_pressure;
        policy.grace_ticks = 2;

        // Change power state to unmounted
        tx.send(Some(PowerState::HeadsetUnmounted))
            .expect("Failed to send power state");

        // Mock should expect memory.high to be reset to u64::MAX
        policy
            .io
            .entry
            .expect_write_memory_high()
            .times(1)
            .returning(move |value| {
                assert_eq!(
                    value,
                    u64::MAX,
                    "Expected memory.high to be reset to u64::MAX, got {}",
                    value
                );
                Box::pin(async move { Ok(()) })
            });

        // Tick with unmounted headset
        let result = policy.tick(Duration::from_secs(1)).await;
        assert!(result.is_ok());

        // Verify policy state has been reset
        assert_eq!(
            policy.last_pressure, 0,
            "last_pressure should be reset to 0"
        );
        assert_eq!(policy.integral_us, 0, "integral_us should be reset to 0");
        assert_eq!(
            policy.grace_ticks, config.interval as u64,
            "grace_ticks should be reset to config.interval"
        );

        // Try other non-mounted states as well
        for state in [
            PowerState::Standby,
            PowerState::WaitingForSleepMsg,
            PowerState::WarmUp,
        ] {
            policy.integral_us = 1000;
            policy.last_pressure = 5000;
            policy.grace_ticks = 1;

            tx.send(Some(state)).expect("Failed to send power state");

            policy
                .io
                .entry
                .expect_write_memory_high()
                .times(1)
                .returning(move |value| {
                    assert_eq!(value, u64::MAX);
                    Box::pin(async move { Ok(()) })
                });

            let result = policy.tick(Duration::from_secs(1)).await;
            assert!(result.is_ok());

            assert_eq!(policy.last_pressure, 0);
            assert_eq!(policy.integral_us, 0);
            assert_eq!(policy.grace_ticks, config.interval as u64);
        }
    }
}
