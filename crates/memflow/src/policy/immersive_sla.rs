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
use futures::StreamExt as _;
use hzos_protection::Event;
use hzos_protection::ProtectionSession;
use hzos_system_native_sysprops::hzos_system_native;
use log::debug;
use log::error;
use log::info;

use crate::cgroup::CgroupEntry;
use crate::cgroup::FileSystemCgroup;
use crate::policy::human_bytes;
use crate::process_monitor::AggregatePolicy;
use crate::process_monitor::ProcessInfo;
use crate::utils::KIB_TO_BYTES;

pub struct ImmersiveSlaConfig {
    memory_high: Option<u64>,
    memory_low: Option<u64>,
    memory_max: Option<u64>,
}

impl ImmersiveSlaConfig {
    pub fn from_sysprops() -> anyhow::Result<Self> {
        /// Converts a system property value to bytes.
        ///
        /// # Arguments
        ///
        /// * `sysprop_value` - The system property value in KB
        ///
        /// # Returns
        ///
        /// * `Some(u64)` - If the system property value is greater than 0, returns the value converted from KB to bytes
        /// * `None` - If the system property value is 0 or negative, indicating the property is not set
        fn sysprop_limit_to_bytes(sysprop_value: i32) -> Option<u64> {
            if sysprop_value > 0 {
                Some(sysprop_value as u64 * KIB_TO_BYTES as u64)
            } else {
                None
            }
        }

        let memory_high = hzos_system_native::memflow_immersiveslaexp_soft()
            .context("Could not read 'memflow_immersiveslaexp_soft' sysprop")?
            .context("Value not set on 'memflow_immersiveslaexp_soft' sysprop")?;

        let memory_low = hzos_system_native::memflow_immersiveslaexp_low()
            .context("Could not read 'memflow_immersiveslaexp_low' sysprop")?
            .context("Value not set on 'memflow_immersiveslaexp_low' sysprop")?;

        let memory_max = hzos_system_native::memflow_immersiveslaexp_hard()
            .context("Could not read 'memflow_immersiveslaexp_hard' sysprop")?
            .context("Value not set on 'memflow_immersiveslaexp_hard' sysprop")?;

        Ok(ImmersiveSlaConfig {
            memory_high: sysprop_limit_to_bytes(memory_high),
            memory_low: sysprop_limit_to_bytes(memory_low),
            memory_max: sysprop_limit_to_bytes(memory_max),
        })
    }
}

#[allow(dead_code)]
pub struct ImmersiveSla {
    session: ProtectionSession,
}

impl ImmersiveSla {
    pub async fn new(
        config: ImmersiveSlaConfig,
        session: ProtectionSession,
    ) -> anyhow::Result<Self> {
        let mut subscriber_stream = session.register_subscriber().await?;

        tokio::task::spawn(async move {
            while let Some(event) = subscriber_stream.next().await {
                match event {
                    Event::ImmersiveProcessEnrolled {
                        package_name,
                        uid,
                        pid,
                    } => {
                        debug!(
                            "onImmersiveProcessEnrolled: {package_name} (uid: {uid} pid: {pid})"
                        );

                        let parent_cgroup = FileSystemCgroup::from_uid(uid as u32);
                        let cgroup = FileSystemCgroup::from_uid_and_pid(uid as u32, pid as u32);

                        if let Some(memory_high) = config.memory_high {
                            match cgroup.write_memory_high(memory_high).await {
                                Ok(_) => info!(
                                    "Setting memory.high ({}) for {pid}",
                                    human_bytes(memory_high)
                                ),
                                Err(e) => error!(
                                    "Failed to set memory.high ({}) for {pid}: {e:?}",
                                    human_bytes(memory_high)
                                ),
                            }
                        }

                        if let Some(memory_low) = config.memory_low {
                            let parent_result = parent_cgroup.write_memory_low(memory_low).await;
                            let result = cgroup.write_memory_low(memory_low).await;

                            match (parent_result, result) {
                                (Ok(_), Ok(_)) => info!(
                                    "Setting memory.low ({}) for {pid}",
                                    human_bytes(memory_low)
                                ),
                                (Err(e), Ok(_)) => error!(
                                    "Failed to set memory.low ({}) for {pid}: {e:?}",
                                    human_bytes(memory_low)
                                ),
                                (Ok(_), Err(e)) => error!(
                                    "Failed to set memory.low ({}) for {pid}: {e:?}",
                                    human_bytes(memory_low)
                                ),
                                (Err(e1), Err(e2)) => error!(
                                    "Failed to set memory.low ({}) for {pid}: {e1:?} {e2:?}",
                                    human_bytes(memory_low)
                                ),
                            }
                        }

                        if let Some(memory_max) = config.memory_max {
                            match cgroup.write_memory_max(memory_max).await {
                                Ok(_) => info!(
                                    "Setting memory.max ({}) for {pid}",
                                    human_bytes(memory_max)
                                ),
                                Err(e) => error!(
                                    "Failed to set memory.max ({}) for {pid}: {e:?}",
                                    human_bytes(memory_max)
                                ),
                            }
                        }
                    }
                    Event::ImmersiveProcessUnenrolled {
                        package_name,
                        uid,
                        pid,
                    } => {
                        debug!(
                            "ImmersiveProcessUnenrolled: {package_name} (uid: {uid} pid: {pid})"
                        );

                        let parent_cgroup = FileSystemCgroup::from_uid(uid as u32);
                        let cgroup = FileSystemCgroup::from_uid_and_pid(uid as u32, pid as u32);

                        match cgroup.write_memory_high(u64::MAX).await {
                            Ok(_) => info!("Reset memory.high for {pid}"),
                            Err(e) => error!("Failed to reset memory.high for {pid}: {e:?}"),
                        }

                        match (
                            parent_cgroup.write_memory_low(0).await,
                            cgroup.write_memory_low(0).await,
                        ) {
                            (Ok(_), Ok(_)) => {
                                info!("Reset memory.low for {pid}")
                            }
                            (Err(e), Ok(_)) => {
                                error!("Failed to reset memory.low for {pid}: {e:?}")
                            }
                            (Ok(_), Err(e)) => {
                                error!("Failed to reset memory.low for {pid}: {e:?}")
                            }
                            (Err(e1), Err(e2)) => {
                                error!("Failed to reset memory.low for {pid}: {e1:?} {e2:?}")
                            }
                        }

                        match cgroup.write_memory_max(u64::MAX).await {
                            Ok(_) => info!("Reset memory.max for {pid}"),
                            Err(e) => error!("Failed to reset memory.max for {pid}: {e:?}"),
                        }
                    }
                }
            }
        });

        Ok(Self { session })
    }
}

#[async_trait]
impl AggregatePolicy for ImmersiveSla {
    fn name(&self) -> &'static str {
        "ImmersiveSla"
    }

    async fn process_create(&mut self, _process: &ProcessInfo) -> anyhow::Result<bool> {
        Ok(true)
    }

    async fn process_remove(&mut self, _pid: u32) -> anyhow::Result<bool> {
        Ok(true)
    }

    async fn tick(&mut self, _delta_time: Duration) -> anyhow::Result<()> {
        Ok(())
    }

    fn tick_rate(&self) -> Duration {
        Duration::from_secs(1)
    }

    async fn cleanup(&mut self) {
        // TODO(T242598008): Re-enable immersive sla policy
        unimplemented!()
    }
}
