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

use std::mem::MaybeUninit;
use std::panic;
use std::path::Path;
use std::time::Duration;

use anyhow::anyhow;
use anyhow::bail;
use async_trait::async_trait;
use futures::StreamExt as _;
use hzos_soft_error::soft_error;
use hzos_system_native_sysprops::hzos_system_native;
use log::error;
use log::info;
use log::warn;
use orchestrator_common::cgroup_monitor;
use orchestrator_common::config;
use orchestrator_common::stats;
use orchestrator_common::Flow;
use tokio::select;

mod utils;
mod policy {
    pub const SYSTEM_UID: u32 = 1000;

    /// Converts a byte count to a human-readable string with appropriate size suffix.
    ///
    /// This function takes a byte count and converts it to a more readable format by
    /// scaling the value and adding an appropriate suffix (k, M, G, T).
    ///
    /// # Arguments
    ///
    /// * `bytes` - The number of bytes to format
    ///
    /// # Returns
    ///
    /// A formatted string with two decimal places and an appropriate size suffix.
    ///
    /// # Examples
    ///
    /// ```
    /// let formatted = human_bytes(1536);
    /// assert_eq!(formatted, "1.50k");
    /// ```
    fn human_bytes(mut bytes: u64) -> String {
        const ORDER_OF_MAGNITUDE: u64 = 1024;

        const SUFFIX: [&str; 5] = ["", "k", "M", "G", "T"];
        let mut order = 0usize;
        while bytes > ORDER_OF_MAGNITUDE && order < SUFFIX.len() - 1 {
            bytes /= ORDER_OF_MAGNITUDE;
            order += 1;
        }
        format!("{:.2}{}", bytes, SUFFIX.get(order).unwrap_or(&"?"))
    }

    pub mod heap_telemetry;
    // TODO(T242598008): Re-enable immersive sla policy
    // pub mod immersive_sla;
    pub mod mem_budget;
    pub mod mem_throttle;
    pub mod senpai_psi;
    pub mod static_min;
    pub mod system_psi;
    pub mod telemetry;
}

use orchestrator_common::cgroup::CgroupControllerType;
use orchestrator_common::cgroup::CgroupEntry as _;
use orchestrator_common::cgroup::FileSystemCgroup;
use orchestrator_common::process_monitor::AggregatePolicy;
use orchestrator_common::process_monitor::PolicyFactory;
use orchestrator_common::process_monitor::ProcessMonitor;
use policy::heap_telemetry::HeapTelemetryConfig;
use policy::heap_telemetry::HeapTelemetryPolicyFactory;
use policy::mem_budget::MemoryBudgetConfig;
use policy::mem_budget::MemoryBudgetPolicy;
use policy::mem_throttle::MemThrottleConfig;
use policy::mem_throttle::MemThrottlePolicyFactory;
use policy::senpai_psi::SenpaiConfig;
use policy::senpai_psi::SenpaiPolicyFactory;
use policy::static_min::StaticMinConfig;
use policy::static_min::StaticMinPolicy;
use policy::system_psi::SystemConfig;
use policy::system_psi::SystemPolicyFactory;
use policy::telemetry::TelemetryConfig;
use policy::telemetry::TelemetryPolicyFactory;
use tokio_util::sync::CancellationToken;

// TODO: T243091680 Implement policies for cgroup v1
fn policies_for_cgroup_v1(
    experiments_config: ExperimentsConfig,
) -> anyhow::Result<(Vec<Box<dyn PolicyFactory>>, Vec<Box<dyn AggregatePolicy>>)> {
    let mut policy_factories: Vec<Box<dyn PolicyFactory>> = Vec::new();
    let aggregate_policies: Vec<Box<dyn AggregatePolicy>> = Vec::new();

    if experiments_config.memflow_heap_telemetry_enabled {
        info!("Heap telemetry experiment enabled");
        let config = HeapTelemetryConfig::from_sysprops()?;
        policy_factories.push(Box::new(HeapTelemetryPolicyFactory::new(config)));
    }

    Ok((policy_factories, aggregate_policies))
}

fn policies_for_cgroup_v2(
    experiments_config: ExperimentsConfig,
) -> anyhow::Result<(Vec<Box<dyn PolicyFactory>>, Vec<Box<dyn AggregatePolicy>>)> {
    let mut policy_factories: Vec<Box<dyn PolicyFactory>> = Vec::new();
    let mut aggregate_policies: Vec<Box<dyn AggregatePolicy>> = Vec::new();

    if experiments_config.memflow_telemetry_enabled {
        info!("Telemetry experiment enabled");
        let config = TelemetryConfig::from_sysprops()?;
        policy_factories.push(Box::new(TelemetryPolicyFactory::new(config)));
    }

    if experiments_config.memflow_heap_telemetry_enabled {
        info!("Heap telemetry experiment enabled");
        let config = HeapTelemetryConfig::from_sysprops()?;
        policy_factories.push(Box::new(HeapTelemetryPolicyFactory::new(config)));
    }

    if experiments_config.memflow_throttle_enabled {
        info!("Throttle experiment enabled");
        let config = MemThrottleConfig::from_sysprops()?;
        policy_factories.push(Box::new(MemThrottlePolicyFactory::new(config)));
    }

    if experiments_config.memflow_sysexp_enabled {
        info!("System PI experiment enabled");
        let config = SystemConfig::from_sysprops()?;
        policy_factories.push(Box::new(SystemPolicyFactory::new(config)));
    }

    if experiments_config.memflow_syssenpaiexp_enabled {
        info!("Senpai experiment enabled");
        let config = SenpaiConfig::from_sysprops()?;
        policy_factories.push(Box::new(SenpaiPolicyFactory::new(config)));
    }

    if experiments_config.memflow_static_fixed_enabled {
        info!("Static min experiment enabled");
        let config = StaticMinConfig::from_sysprops()?;
        aggregate_policies.push(Box::new(StaticMinPolicy::new(config)));
    }

    if experiments_config.memflow_budget_enforcement_enabled {
        info!("Budget enforcement experiment enabled");
        config::spawn_config_updater();
        let config = MemoryBudgetConfig::from_sysprops()?;
        aggregate_policies.push(Box::new(MemoryBudgetPolicy::new(config)));
    }

    // TODO(T242598008): Re-enable immersive sla policy
    // if experiments_config.memflow_immersive_sla_enabled {
    //     info!("Immersive SLA experiment enabled");
    //     let config = ImmersiveSlaConfig::from_sysprops();

    //     match ProtectionSession::connect().await {
    //         Ok(protection_session) => {
    //             aggregate_policies.push(Box::new(
    //                 ImmersiveSla::new(config, protection_session).await?,
    //             ));
    //         }
    //         Err(e) => {
    //             warn!("Failed to connect to protection session: {e:?}");
    //         }
    //     }
    // }

    Ok((policy_factories, aggregate_policies))
}
struct ExperimentsConfig {
    memflow_budget_enforcement_enabled: bool,
    memflow_sysexp_enabled: bool,
    memflow_syssenpaiexp_enabled: bool,
    memflow_static_fixed_enabled: bool,
    memflow_telemetry_enabled: bool,
    memflow_heap_telemetry_enabled: bool,
    memflow_throttle_enabled: bool,
    // TODO(T242598008): Re-enable immersive sla policy
    // memflow_immersive_sla_enabled: bool,
}

impl ExperimentsConfig {
    fn from_sysprops() -> anyhow::Result<Self> {
        let memflow_budget_enforcement_enabled =
            hzos_system_native::memflow_budget_enforcement_enabled()
                .unwrap_or_else(|e| {
                    warn!("Could not read 'memflow_budget_enforcement_enabled' sysprop: {e:?}, Defaulting to false");
                    None
                })
                .unwrap_or(false);

        let memflow_sysexp_enabled = hzos_system_native::memflow_sysexp()
            .unwrap_or_else(|e| {
                warn!("Could not read 'memflow_sysexp' sysprop: {e:?}, Defaulting to false");
                None
            })
            .unwrap_or(false);

        let memflow_syssenpaiexp_enabled = hzos_system_native::memflow_syssenpaiexp()
            .unwrap_or_else(|e| {
                warn!("Could not read 'memflow_syssenpaiexp' sysprop: {e:?}, Defaulting to false");
                None
            })
            .unwrap_or(false);

        let memflow_static_fixed_enabled = hzos_system_native::memflow_staticexp()
            .unwrap_or_else(|e| {
                warn!("Could not read 'memflow_staticexp' sysprop: {e:?}, Defaulting to false");
                None
            })
            .unwrap_or(false);

        let memflow_telemetry_enabled = hzos_system_native::memflow_telemetry()
            .unwrap_or_else(|e| {
                warn!("Could not read 'memflow_telemetry' sysprop: {e:?}, Defaulting to false");
                None
            })
            .unwrap_or(false);

        let memflow_heap_telemetry_enabled = hzos_system_native::memflow_heap_telemetry()
            .unwrap_or_else(|e| {
                warn!(
                    "Could not read 'memflow_heap_telemetry' sysprop: {e:?}, Defaulting to false"
                );
                None
            })
            .unwrap_or(false);

        let memflow_throttle_enabled = hzos_system_native::memflow_throttle()
            .unwrap_or_else(|e| {
                warn!("Could not read 'memflow_throttle' sysprop: {e:?}, Defaulting to false");
                None
            })
            .unwrap_or(false);

        // TODO(T242598008): Re-enable immersive sla policy
        // let memflow_immersive_sla_enabled = hzos_system_native::memflow_immersiveslaexp()
        //     .unwrap_or_else(|e| {
        //         warn!(
        //             "Could not read 'memflow_immersiveslaexp' sysprop: {e:?}, Defaulting to false"
        //         );
        //         None
        //     })
        //     .unwrap_or(false);

        if memflow_sysexp_enabled && memflow_syssenpaiexp_enabled {
            bail!("Only one of memflow_sysexp and memflow_syssenpaiexp can be enabled at a time");
        }

        Ok(Self {
            memflow_budget_enforcement_enabled,
            memflow_sysexp_enabled,
            memflow_syssenpaiexp_enabled,
            memflow_static_fixed_enabled,
            memflow_telemetry_enabled,
            memflow_heap_telemetry_enabled,
            memflow_throttle_enabled,
            // TODO(T242598008): Re-enable immersive sla policy
            // memflow_immersive_sla_enabled,
        })
    }
}

pub struct Memflow {
    bpf_object: MaybeUninit<libbpf_rs::OpenObject>,
}

impl Memflow {
    pub fn new() -> Self {
        Self {
            bpf_object: MaybeUninit::uninit(),
        }
    }
}

unsafe impl Send for Memflow {}

#[async_trait]
impl Flow for Memflow {
    async fn run(&mut self, cancel_token: CancellationToken) -> anyhow::Result<()> {
        info!("Starting memflow...");

        // Verify that memcgv2 is enabled
        let is_memcgv2_enabled = FileSystemCgroup::base_path()
            .controllers()
            .await?
            .into_iter()
            .flatten()
            .any(|controller| controller == CgroupControllerType::Memory);

        let (pressure, evt) = stats::Pressure::new(Path::new("/proc/pressure/memory"))?;
        info!("initial pressure: {evt:?}");

        let mut monitor = cgroup_monitor::CgroupMonitor::new(&mut self.bpf_object)?;

        let mut process_monitor = {
            let experiments_config = ExperimentsConfig::from_sysprops()?;

            let (policy_factories, aggregate_policies) = if is_memcgv2_enabled {
                policies_for_cgroup_v2(experiments_config)
            } else {
                policies_for_cgroup_v1(experiments_config)
            }?;

            if policy_factories.is_empty() && aggregate_policies.is_empty() {
                soft_error!("Memflow started with no policies enabled");
            }

            ProcessMonitor::new(policy_factories, aggregate_policies)
        };

        // Start the cgroup and process monitor tasks
        let (cgroup_stream, mut monitor_support_tasks) = monitor.watch()?;
        let mut process_monitor_task = process_monitor.run(cgroup_stream).await;
        let pressure_stream = pressure.watch(stats::Trigger {
            what: stats::StallType::Some,
            threshold: Duration::from_micros(10),
            window: Duration::from_secs(2),
        })?;
        let mut pressure_stream_fused = pressure_stream.fuse();

        info!("waiting for events...");

        // Handle pressure events in the main loop
        let dispatch_loop_result = loop {
            select! {
                biased;
                _ = cancel_token.cancelled() => {
                    info!("memflow cancelled, shutting down...");
                    break Ok(());
                },
                join_result = &mut process_monitor_task => {
                    match join_result {
                        Ok(Ok(_)) => {
                            error!("Process monitor exited unexpectedly");
                            break Err(anyhow!("Process monitor exited unexpectedly"));
                        }
                        Ok(Err(e)) => {
                            error!("Process monitor task failed: {e:?}");
                            break Err(anyhow!("Process monitor task failed: {e:?}"));
                        }
                        Err(e) => {
                            error!("Process monitor task panicked: {e:?}");
                            break Err(anyhow!("Process monitor task panicked: {e:?}"));
                        }
                    }
                },
                result = monitor_support_tasks.join_next() => {
                    match result {
                        Some(Ok(_)) | None => {
                            error!("Monitor support tasks exited unexpectedly");
                            break Err(anyhow!("Monitor support tasks exited unexpectedly"));
                        }
                        Some(Err(e)) => {
                            error!("Monitor support tasks failed: {e:?}");
                            break Err(anyhow!("Monitor support tasks failed: {e:?}"));
                        }
                    }
                },
                maybe_pressure_event = pressure_stream_fused.next() => {
                    if let Some(pressure_event) = maybe_pressure_event {
                        info!("Event triggered: {pressure_event:?}");
                    }
                },
            }
        };

        // Allow the process monitor to clean up before we exit.
        process_monitor.cleanup().await;

        info!("Resource cleanup complete, exiting...");

        dispatch_loop_result
    }
}
