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

//! Budget enforcement support. Allow Orchestrator components to perform enforcement actions in a
//! uniform way.

use hzos_budget::EnforcementLevel;
use hzos_budget::ResourceType;
use hzos_soft_error::soft_error;
use log::info;
use nix::sys::signal::kill;
use nix::sys::signal::Signal;
use nix::unistd::Pid;

use crate::process_monitor::ProcessInfo;
use crate::telemetry::log_telemetry;

pub fn do_enforcement(
    process: &ProcessInfo,
    level: EnforcementLevel,
    resource_type: ResourceType,
    is_dry_run: bool,
    threshold: u64,
    current_usage: u64,
) {
    info!(
        "Taking action {level:?} for {}:{} due to {resource_type:?} usage {current_usage} exceeding threshold {threshold}, dry-run={is_dry_run}",
        process.exe, process.pid
    );

    if !is_dry_run {
        match level {
            EnforcementLevel::Kill => {
                let pid = Pid::from_raw(process.pid as i32);
                match kill(pid, Signal::SIGABRT) {
                    Ok(_) => info!("Killed process {}:{}", process.exe, process.pid),
                    Err(e) => {
                        soft_error!("Failed to kill process: {e:?}");
                    }
                }
            }
            _ => {}
        }
    }

    log_telemetry(
        &process.exe,
        resource_type,
        level,
        hzos_budget::EnforcementContext::All,
        threshold as i64,
        current_usage as i64,
        is_dry_run,
    );
}
