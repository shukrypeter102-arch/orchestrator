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

//! Orchestrator sysprop helpers for properties not defined via MDC.

use std::str::FromStr;
use std::time::Duration;

const BUDGET_CONFIG_TICK_RATE_PROP: &str = "hzos.orchestrator.common.budget_config.tick_rate";
const MEMFLOW_BUDGET_TICK_RATE_PROP: &str = "hzos.orchestrator.memflow.budget.tick_rate";

/// Return the value of a debug sysprop if possible, otherwise the supplied default value.
///
/// This function attempts to read and parse the value of a debug sysprop. If this is a debug build
/// and the property can be parsed, its value is returned. Otherwise, the supplied default value is
/// returned.
///
/// # Arguments
///
/// * `prop_name` - Name of the sysprop to read.
/// * `default` - Default value to return if the property cannot be read or parsed.
///
/// # Returns
///
/// The value of the sysprop if it can be read and parsed, otherwise the supplied default value.
fn get_debug_sysprop<T: FromStr>(prop_name: &str, default: T) -> T {
    if !crate::USERDEBUG {
        return default;
    }

    android_properties::getprop(prop_name)
        .value()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

pub fn budget_config_tick_rate(default_value: Duration) -> Duration {
    Duration::from_millis(get_debug_sysprop(
        BUDGET_CONFIG_TICK_RATE_PROP,
        default_value.as_millis() as u64,
    ))
}

pub fn memflow_budget_tick_rate(default_value: Duration) -> Duration {
    Duration::from_millis(get_debug_sysprop(
        MEMFLOW_BUDGET_TICK_RATE_PROP,
        default_value.as_millis() as u64,
    ))
}
