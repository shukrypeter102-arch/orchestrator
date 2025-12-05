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

//! Telemetry logging for the orchestator service. Abstracts away the
//! statsd types so that we use the types defined in the hzos_budget crate
//! without leaking the underlying statsd generated types.

use hzos_budget::EnforcementContext;
use hzos_budget::EnforcementLevel;
use hzos_budget::ResourceType;
use hzos_soft_error::soft_error;
use log::trace;
use statslog_meta_memflow::enforcement_action as statsd;

/// Logs a resource enforcement action telemetry event to statsd.
///
/// This function creates and writes an [`EnforcementAction`] atom to the telemetry
/// system (statsd) for tracking resource budget enforcement actions across the system.
/// The logged data is used for monitoring, analytics, and debugging resource management
/// in the orchestrator service.
///
/// # Parameters
///
/// * `process_identifer` - The process identifier to which the enforcement action applies.
/// * `resource_type` - The type of resource whose budget was enforced.
/// * `level` - The enforcement level applied to the resource.
/// * `context` - The context that was active when the enforcement action was applied.
/// * `budget` - The configured budget value that was exceeded.
/// * `current_usage` - The current usage of the resource at the time of enforcement,
///   measured in the same units as the `budget` parameter.
/// * `is_dry_run` - Whether the system was in dry-run mode at the time of enforcement.
///   If `true`, the enforcement action was not actually performed (simulation mode).
///
/// # Example
///
/// ```rust,no_run
/// use hzos_budget::EnforcementContext;
/// use hzos_budget::EnforcementLevel;
/// use hzos_budget::ResourceType;
///
/// // Log a memory enforcement action for a process exceeding its budget
/// log_telemetry(
///     "com.meta.example.app",
///     ResourceType::Memory,
///     EnforcementLevel::Throttle,
///     EnforcementContext::VrImmersive,
///     512,   // Budget: 512 MiB
///     650,   // Current usage: 650 MiB (exceeded budget by 138 MiB)
///     false, // Not a dry run - action was actually performed
/// );
///
/// // Log a dry-run warning for CPU budget monitoring
/// log_telemetry(
///     "background_service",
///     ResourceType::Cpu,
///     EnforcementLevel::Warn,
///     EnforcementContext::MrHome,
///     1000, // Budget: 1000 CPU credits
///     1200, // Current usage: 1200 CPU credits
///     true, // Dry run - only monitoring, no actual enforcement
/// );
/// ```
///
/// # Proto Definition
///
/// This function logs data according to the `EnforcementAction` message defined in
/// `/vendor/meta/services/telemetry/proto_logging/stats/atoms/memflow/memflow_atoms.proto`.
///
/// [`EnforcementAction`]: statslog_meta_memflow::enforcement_action::EnforcementAction
pub fn log_telemetry(
    process_identifer: &str,
    resource_type: ResourceType,
    level: EnforcementLevel,
    context: EnforcementContext,
    budget: i64,
    current_usage: i64,
    is_dry_run: bool,
) {
    let enforcement_action_atom = statsd::EnforcementAction {
        process_identifer,
        resource_type: resource_type.into(),
        level: level.into(),
        context: context.into(),
        budget,
        current_usage,
        is_dry_run,
    };

    if let Err(e) = enforcement_action_atom.stats_write() {
        soft_error!("Failed to write enforcement action to statsd: {e:?}");
    } else {
        trace!("Logged enforcement action to statsd");
    }
}
