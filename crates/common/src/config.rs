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

use hzos_budget::Budget;
use hzos_config::cache::ConfigCache;
use hzos_config::query::ConfigQuerySessionAsync;
use log::error;
use log::info;
use tokio::time::interval;

use crate::sysprop;

const BUDGET_ENFORCEMENT_DEFAULT_PATH: &str = "/vendor/etc/budget_enforcement.json";
const BUDGET_ENFORCEMENT_FILE: &str = "budget_enforcement.json";
const CONFIG_POLL_INTERVAL: Duration = Duration::from_secs(15 * 60); // 15 minutes
const ORCHESTRATOR_CONFIG_NAME: &str = "orchestrator";

/// Retrieves the current budget enforcement configuration.
pub fn budget_config() -> Budget {
    let config_cache = ConfigCache::new(ORCHESTRATOR_CONFIG_NAME);
    // Check for a cached budget first.
    if let Ok(Some(budget_str)) = config_cache.read(BUDGET_ENFORCEMENT_FILE) {
        if let Ok(budget) = Budget::from_str(&budget_str) {
            info!("Loading cached budget");
            return budget;
        }
    }
    // Fallback to the /vendor/etc budget on disk.
    if let Ok(budget) = Budget::from_file(BUDGET_ENFORCEMENT_DEFAULT_PATH) {
        info!("Loading fallback /vendor/etc budget");
        return budget;
    }
    // Fallback to just defaults if we cannot read.
    info!("Loading fallback empty budget");
    Budget::default()
}

pub fn spawn_config_updater() {
    tokio::spawn(async move {
        let config_cache = ConfigCache::new(ORCHESTRATOR_CONFIG_NAME);
        let mut current_budget = budget_config();
        let poll_rate = sysprop::budget_config_tick_rate(CONFIG_POLL_INTERVAL);
        let mut interval = interval(poll_rate);
        loop {
            interval.tick().await;
            info!("Checking for enforcement budgets (poll rate {poll_rate:?})");
            match ConfigQuerySessionAsync::connect().await {
                Ok(mut query_session) => {
                    if let Err(e) =
                        update_config(&mut query_session, &config_cache, &mut current_budget).await
                    {
                        error!("Failed to poll and update config: {e:?}");
                    }
                }
                Err(e) => {
                    error!("Failed to connect to ConfigQuerySessionAsync: {e:?}");
                }
            }
            info!("Checking for enforcement budgets complete.");
        }
    });
}

/// Polls for configuration query session for updates.
async fn update_config(
    query_session: &mut ConfigQuerySessionAsync,
    config_cache: &ConfigCache,
    current_budget: &mut Budget,
) -> anyhow::Result<()> {
    let new_budget = match query_session.query(ORCHESTRATOR_CONFIG_NAME).await? {
        Some(budget_str) => Budget::from_str(&budget_str)?,
        None => {
            return Ok(());
        }
    };
    if *current_budget == new_budget {
        return Ok(());
    }
    let budget_json = match serde_json::to_string_pretty(&new_budget) {
        Ok(json) => json,
        Err(e) => {
            error!("Failed to serialize validated budget to JSON: {e:?}");
            return Err(e.into());
        }
    };
    match config_cache.write(BUDGET_ENFORCEMENT_FILE, budget_json) {
        Ok(()) => {
            *current_budget = new_budget;
            info!("Successfully updated budget enforcement configuration.");
        }
        Err(e) => {
            error!("Failed to write budget enforcement config to cache: {e:?}");
            return Err(e.into());
        }
    }
    Ok(())
}
