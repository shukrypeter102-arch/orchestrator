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
use log::trace;
use log::warn;
use orchestrator_common::cgroup::CgroupEntry;
use orchestrator_common::cgroup::FileSystemCgroup;
use orchestrator_common::process_monitor::Policy;
use orchestrator_common::process_monitor::PolicyFactory;
use orchestrator_common::process_monitor::ProcessInfo;
use orchestrator_common::utils::KIB_TO_BYTES;
use orchestrator_common::utils::MIB_TO_BYTES;
use orchestrator_common::utils::PAGE_SIZE;

use crate::policy::human_bytes;
use crate::policy::SYSTEM_UID;

#[derive(Default, Debug)]
struct ControllerState {
    u: f64,
    prev_error: f64,
    prev_pressure: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct SystemConfig {
    pub setpoint: f64,
    pub integral_max: f64,
    pub deadband: f64,
    pub output_min: u64,
    pub output_max: u64,
    pub p_gain: f64,
    pub i_gain: f64,
    pub tick_rate: Duration,
}

impl SystemConfig {
    pub fn from_sysprops() -> anyhow::Result<Self> {
        let setpoint = hzos_system_native::memflow_sysexp_setpoint()
            .context("Could not read 'memflow_sysexp_setpoint' sysprop")?
            .context("Value not set on 'memflow_sysexp_setpoint' sysprop")?;
        let integral_max = hzos_system_native::memflow_sysexp_integral_max()
            .context("Could not read 'memflow_sysexp_integral_max' sysprop")?
            .context("Value not set on 'memflow_sysexp_integral_max' sysprop")?;
        let deadband = hzos_system_native::memflow_sysexp_deadband()
            .context("Could not read 'memflow_sysexp_deadband' sysprop")?
            .context("Value not set on 'memflow_sysexp_deadband' sysprop")?;
        let output_min = hzos_system_native::memflow_sysexp_output_min()
            .context("Could not read 'memflow_sysexp_output_min' sysprop")?
            .context("Value not set on 'memflow_sysexp_output_min' sysprop")?;
        let output_max = hzos_system_native::memflow_sysexp_output_max()
            .context("Could not read 'memflow_sysexp_output_max' sysprop")?
            .context("Value not set on 'memflow_sysexp_output_max' sysprop")?;
        let p_gain = hzos_system_native::memflow_sysexp_p_gain()
            .context("Could not read 'memflow_sysexp_p_gain' sysprop")?
            .context("Value not set on 'memflow_sysexp_p_gain' sysprop")?;
        let i_gain = hzos_system_native::memflow_sysexp_i_gain()
            .context("Could not read 'memflow_sysexp_i_gain' sysprop")?
            .context("Value not set on 'memflow_sysexp_i_gain' sysprop")?;
        let tick_rate = Duration::from_millis(
            hzos_system_native::memflow_sysexp_tick_rate()
                .context("Could not read 'memflow_sysexp_tick_rate' sysprop")?
                .context("Value not set on 'memflow_sysexp_tick_rate' sysprop")?
                .try_into()
                .context("'memflow_sysexp_tick_rate' must be non-negative")?,
        );

        Ok(Self {
            setpoint,
            integral_max: if integral_max <= 0.0 {
                f64::MAX
            } else {
                integral_max
            },
            deadband,
            output_min: if output_min <= 0 {
                PAGE_SIZE as u64
            } else {
                (output_min as u64) * (KIB_TO_BYTES as u64)
            },
            output_max: if output_max <= 0 {
                u64::MAX
            } else {
                (output_max as u64) * (KIB_TO_BYTES as u64)
            },
            p_gain,
            i_gain,
            tick_rate,
        })
    }
}

pub struct SystemPolicyFactory {
    config: SystemConfig,
}

impl SystemPolicyFactory {
    pub fn new(config: SystemConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl PolicyFactory for SystemPolicyFactory {
    fn name(&self) -> &'static str {
        "System PI Controler"
    }

    async fn create(&self, process: &ProcessInfo) -> anyhow::Result<Option<Box<dyn Policy>>> {
        if process.uid == SYSTEM_UID {
            let policy = SystemPolicy::<FileSystemCgroup>::new(
                process.clone(),
                self.config,
                FileSystemCgroup::from_uid_and_pid(process.uid, process.pid),
            )
            .await?;
            Ok(Some(Box::new(policy)))
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug)]
pub struct SystemPolicy<C: CgroupEntry> {
    process_info: ProcessInfo,
    config: SystemConfig,
    controller_state: ControllerState,
    cgroup: C,
}

impl<C: CgroupEntry> SystemPolicy<C> {
    pub async fn new(
        process_info: ProcessInfo,
        config: SystemConfig,
        cgroup: C,
    ) -> anyhow::Result<Self> {
        if config.output_min > config.output_max {
            return Err(anyhow::anyhow!(
                "output_min ({}) cannot be greater than output_max ({})",
                config.output_min,
                config.output_max
            ));
        }

        let initial_u = cgroup
            .memory_current()
            .await
            .map_err(anyhow::Error::from)
            .unwrap_or_else(|_| {
                eprintln!(
                    "Failed to read memory.current for pid {}, using default",
                    process_info.pid
                );
                (1 * MIB_TO_BYTES) as u64 // 1MB default
            });
        let prev_pressure = cgroup.memory_pressure().await?.some.total;

        Ok(Self {
            process_info,
            config,
            controller_state: ControllerState {
                u: initial_u as f64,
                prev_error: 0.0,
                prev_pressure,
            },
            cgroup,
        })
    }
}

#[async_trait]
impl<C: CgroupEntry + Send + Sync> Policy for SystemPolicy<C> {
    fn tick_rate(&self) -> Duration {
        self.config.tick_rate
    }

    async fn tick(&mut self, delta_time: Duration) -> anyhow::Result<()> {
        let Self {
            process_info,
            config,
            controller_state,
            cgroup,
        } = self;

        let current_pressure = cgroup.memory_pressure().await?.some.total;
        let delta_pressure = current_pressure - controller_state.prev_pressure;
        (*controller_state).prev_pressure = current_pressure;

        // Calculate the the time (as a percent) that the process was in the some pressure state.
        // The "total" field of the PSI file is reported in microseconds, so use the same unit here.
        let pressure_percent = if delta_time.as_micros() > 0 {
            ((delta_pressure as f64) / (delta_time.as_micros() as f64)) * 100.0
        } else {
            0.0
        };

        // Apply a deadband around the setpoint to prevent oscillation. This means that if we
        // are within the deadband of the setpoint, we consider the error to be zero.
        let error = {
            let raw_error = pressure_percent - config.setpoint;
            if raw_error.abs() <= (config.setpoint * config.deadband / 100.0) {
                0.0
            } else {
                raw_error
            }
        };

        // Finally calculate the output. The output of this controller is gains of both the
        // proportional and integral terms. The PI controller is in velocity form, so the
        // integral term takes the error while the proportional term takes the change in error.
        // We then clamp du to the integral_max and add it to the previous integral term. We then
        // clamp the output to the output_min and output_max.
        let output = {
            let delta_error = error - controller_state.prev_error;
            let du = {
                let du_unclamped: f64 = (config.p_gain * delta_error)
                    + (config.i_gain * error * delta_time.as_secs_f64());
                let at_high = controller_state.u > config.integral_max;
                let at_low = controller_state.u < -config.integral_max;

                if (at_high && du_unclamped > 0.0) || (at_low && du_unclamped < 0.0) {
                    0.0
                } else {
                    du_unclamped
                }
            };

            controller_state.u += du;
            controller_state.u =
                (controller_state.u).clamp(config.output_min as f64, config.output_max as f64);
            controller_state.prev_error = error;

            controller_state.u
        };

        // Round the output to the nearest 4KB boundary and convert to KB
        let output_bytes = (((output.ceil() as i64 + 4095) / 4096) * 4096) as u64;

        // Write the output to the cgroup memory.high file
        cgroup.write_memory_high(output_bytes).await?;

        trace!(
            "Process ({}, {}, {}): {} - {}%\n",
            process_info.pid,
            process_info.comm,
            process_info.oom_score_adj,
            human_bytes(output_bytes),
            pressure_percent
        );

        Ok(())
    }

    async fn cleanup(&mut self) {
        if let Err(e) = self.cgroup.write_memory_high(u64::MAX).await {
            warn!(
                "Failed to reset memory.high (policy: SystemPolicy, pid: {}): {e:?}",
                self.process_info.pid
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use orchestrator_common::cgroup::MockCgroupEntry;
    use orchestrator_common::utils::KIB_TO_BYTES;
    use tokio;

    use super::*;
    use crate::utils::tests::create_psi_readout;
    use crate::utils::tests::create_test_process_info;

    fn create_test_config() -> SystemConfig {
        SystemConfig {
            setpoint: 10.0,                            // 10% memory pressure setpoint
            integral_max: 200.0 * MIB_TO_BYTES as f64, // 200MB - larger than test memory values
            deadband: 5.0,                             // 0.5% deadband around setpoint
            output_min: MIB_TO_BYTES as u64,           // 1MB
            output_max: (100 * MIB_TO_BYTES) as u64,   // 100MB
            p_gain: (2 * KIB_TO_BYTES) as f64,         // 2 KB per 1% error
            i_gain: (1 * KIB_TO_BYTES) as f64, // 1 KB per second per 1% of accumulated error
            tick_rate: Duration::from_secs(1), // Not actually used since we will be manually ticking
        }
    }

    async fn create_test_policy_with_mock(
        config: SystemConfig,
        initial_pressure: u64,
        initial_memory: u64,
    ) -> SystemPolicy<MockCgroupEntry> {
        let mut mock_cgroup = MockCgroupEntry::new();

        // Setup initial expectations for policy creation
        mock_cgroup
            .expect_memory_current()
            .times(1)
            .returning(move || Box::pin(async move { Ok(initial_memory) }));

        mock_cgroup
            .expect_memory_pressure()
            .times(1)
            .returning(move || Box::pin(async move { Ok(create_psi_readout(initial_pressure)) }));

        let process_info = create_test_process_info();
        SystemPolicy::new(process_info, config, mock_cgroup)
            .await
            .expect("Could not create policy")
    }

    /// Test that a policy does not increase the memory.high value if the pressure is exactly equal to the setpoint
    #[tokio::test]
    async fn test_pressure_equals_setpoint_no_change() {
        let config = create_test_config();
        let initial_pressure = 1000; // Starting pressure
        let initial_memory = 10 * MIB_TO_BYTES as u64; // 10MB

        let mut policy =
            create_test_policy_with_mock(config, initial_pressure, initial_memory).await;

        // Calculate pressure that equals setpoint: 10% over 1 second = 10000 microseconds increase
        let delta_time = Duration::from_secs(1);
        let pressure_increase = (config.setpoint / 100.0 * delta_time.as_micros() as f64) as u64;
        let new_pressure = initial_pressure + pressure_increase;

        policy
            .cgroup
            .expect_memory_pressure()
            .times(1)
            .returning(move || Box::pin(async move { Ok(create_psi_readout(new_pressure)) }));

        policy
            .cgroup
            .expect_write_memory_high()
            .times(1)
            .withf(move |value| *value == initial_memory) // Should remain the same
            .returning(|_| Box::pin(async move { Ok(()) }));

        let result = policy.tick(delta_time).await;
        assert!(result.is_ok());
    }

    /// Test that a policy does not increase the memory.high value if the pressure is within the deadband of the setpoint
    #[tokio::test]
    async fn test_pressure_within_deadband_no_change() {
        let config = create_test_config();
        let initial_pressure = 1000;
        let initial_memory = 10 * MIB_TO_BYTES as u64; // 10MB

        let mut policy =
            create_test_policy_with_mock(config, initial_pressure, initial_memory).await;

        // Calculate pressure within deadband (setpoint ± deadband%)
        // Deadband is 5% of setpoint = 0.5%, so within ±0.5% of 10% should be no change
        let delta_time = Duration::from_secs(1);
        let pressure_within_deadband =
            (config.setpoint * 0.97 / 100.0 * delta_time.as_micros() as f64) as u64;
        let new_pressure = initial_pressure + pressure_within_deadband;

        policy
            .cgroup
            .expect_memory_pressure()
            .times(1)
            .returning(move || Box::pin(async move { Ok(create_psi_readout(new_pressure)) }));

        policy
            .cgroup
            .expect_write_memory_high()
            .times(1)
            .withf(move |value| *value == initial_memory)
            .returning(|_| Box::pin(async move { Ok(()) }));

        let result = policy.tick(delta_time).await;
        assert!(result.is_ok());
    }

    /// Test that a policy increases the memory.high proportional to the error
    #[tokio::test]
    async fn test_proportional_and_integral_gains() {
        let config = create_test_config();
        let initial_pressure = 1000;
        let initial_memory = 10 * MIB_TO_BYTES as u64; // 10MB

        let mut policy =
            create_test_policy_with_mock(config, initial_pressure, initial_memory).await;

        let initial_u = policy.controller_state.u;

        // Apply known error
        let delta_time = Duration::from_secs(1);
        let pressure_increase =
            (config.setpoint * 2.0 / 100.0 * delta_time.as_micros() as f64) as u64; // 20%
        let new_pressure = initial_pressure + pressure_increase;

        // Calculate expected error (20% - 10% = 10%, outside deadband)
        let expected_error = 10.0; // 20% - 10% setpoint

        policy
            .cgroup
            .expect_memory_pressure()
            .times(1)
            .returning(move || Box::pin(async move { Ok(create_psi_readout(new_pressure)) }));

        policy
            .cgroup
            .expect_write_memory_high()
            .times(1)
            .returning(move |value| {
                // Calculate expected change
                // delta_error = expected_error - 0 (prev_error)
                // du = p_gain * delta_error + i_gain * error * delta_time
                let delta_error = expected_error;
                let expected_du = config.p_gain * delta_error
                    + config.i_gain * expected_error * delta_time.as_secs_f64();
                let expected_new_u = initial_u + expected_du;
                let expected_output = ((expected_new_u.ceil() as i64 + 4095) / 4096) * 4096;

                // Allow some tolerance for floating point arithmetic
                assert!((value as i64 - expected_output).abs() <= 4096);

                Box::pin(async move { Ok(()) })
            });

        let result = policy.tick(delta_time).await;
        assert!(result.is_ok());
    }

    /// Test that a policy does accumulate the integral term when between ticks
    #[tokio::test]
    async fn test_consecutive_ticks_accumulate_error() {
        let config = create_test_config();
        let initial_pressure = 1000;
        let initial_memory = 10 * MIB_TO_BYTES as u64; // 10MB

        let mut policy =
            create_test_policy_with_mock(config, initial_pressure, initial_memory).await;

        let delta_time = Duration::from_secs(1);
        let pressure_increase =
            (config.setpoint * 2.0 / 100.0 * delta_time.as_micros() as f64) as u64; // 20%

        // First tick
        let first_tick_pressure = initial_pressure + pressure_increase;
        policy
            .cgroup
            .expect_memory_pressure()
            .times(1)
            .returning(move || {
                Box::pin(async move { Ok(create_psi_readout(first_tick_pressure)) })
            });

        policy
            .cgroup
            .expect_write_memory_high()
            .times(1)
            .returning(|_| Box::pin(async move { Ok(()) }));

        let result = policy.tick(delta_time).await;
        assert!(result.is_ok());

        let u_after_first_tick = policy.controller_state.u;
        let prev_error_after_first = policy.controller_state.prev_error;

        // Second tick - increase pressure further so delta_pressure creates same error again
        // This will create the same error, so the integral term will accumulate
        let second_tick_pressure = first_tick_pressure + pressure_increase;
        policy
            .cgroup
            .expect_memory_pressure()
            .times(1)
            .returning(move || {
                Box::pin(async move { Ok(create_psi_readout(second_tick_pressure)) })
            });

        policy
            .cgroup
            .expect_write_memory_high()
            .times(1)
            .returning(|_| Box::pin(async move { Ok(()) }));

        let result = policy.tick(delta_time).await;
        assert!(result.is_ok());

        // Verify that error accumulated (prev_error was stored and used)
        assert_ne!(prev_error_after_first, 0.0);
        // Even with same error, the integral term should accumulate, making u increase
        assert!(policy.controller_state.u > u_after_first_tick); // Should continue increasing due to integral accumulation
    }

    /// Verify that we do not crash when delta_time is zero
    #[tokio::test]
    async fn test_zero_delta_time_handling() {
        let config = create_test_config();
        let initial_pressure = 1000;
        let initial_memory = 10 * MIB_TO_BYTES as u64; // 10MB

        let mut policy =
            create_test_policy_with_mock(config, initial_pressure, initial_memory).await;

        let delta_time = Duration::from_micros(0); // Zero time
        let new_pressure = initial_pressure + 10000; // Large pressure increase

        policy
            .cgroup
            .expect_memory_pressure()
            .times(1)
            .returning(move || Box::pin(async move { Ok(create_psi_readout(new_pressure)) }));

        policy
            .cgroup
            .expect_write_memory_high()
            .times(1)
            .returning(move |_| Box::pin(async move { Ok(()) }));

        let result = policy.tick(delta_time).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_policy_creation_with_invalid_bounds() {
        let mut config = create_test_config();
        config.output_min = 100 * MIB_TO_BYTES as u64; // 100MB
        config.output_max = 50 * MIB_TO_BYTES as u64; // 50MB (less than min)

        let mock_cgroup = MockCgroupEntry::new();
        let process_info = create_test_process_info();

        let result = SystemPolicy::new(process_info, config, mock_cgroup).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("output_min"));
    }
}
