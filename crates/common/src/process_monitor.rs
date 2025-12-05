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

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use async_trait::async_trait;
use dashmap::DashMap;
use hzos_soft_error::soft_error;
use log::debug;
use log::error;
use log::info;
use tokio::select;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_stream::StreamExt as _;
use tokio_util::sync::CancellationToken;

use crate::cgroup_monitor::CgroupEvent;
use crate::stats::ProcessCgroupInfo;

/// Errors that can occur when reading process executable information
#[derive(Debug)]
enum ProcessExeError {
    AndroidZygote,
    AndroidPreInitialized,
    IoError(anyhow::Error),
}

impl std::fmt::Display for ProcessExeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AndroidZygote => write!(f, "Android zygote detected)"),
            Self::AndroidPreInitialized => write!(f, "Android pre-initialized detected"),
            Self::IoError(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ProcessExeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IoError(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

/// Factory trait for creating memory policies for processes.
///
/// Policy factories are responsible for creating policies in the `create` function. If the
/// process meets the condition of the policy, a `Some` option containing the policy is returned.
/// If the process does not meet the conditions, `None` is returned.
#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait PolicyFactory: Send + Sync {
    /// Returns the name of this policy factory.
    ///
    /// This name is used for logging and debugging purposes to identify which
    /// policy factory is being used.
    fn name(&self) -> &'static str {
        "Unknown"
    }

    /// Creates a policy for the given process if it meets the factory's conditions.
    ///
    /// # Arguments
    ///
    /// * `process` - Information about the process to potentially create a policy for
    ///
    /// # Returns
    ///
    /// * `Ok(Some(policy))` - If the process meets the conditions and a policy should be created
    /// * `Ok(None)` - If the process does not meet the conditions
    /// * `Err(_)` - If an error occurred while checking conditions or creating the policy
    async fn create(&self, process: &ProcessInfo) -> anyhow::Result<Option<Box<dyn Policy>>>;
}

/// Trait for policies that manage individual cgroup hierarchies.
///
/// Policies are responsible for managing individual cgroup hierarchies for processes
/// that have been enrolled in a policy. They receive periodic tick events to perform
/// their management logic.
#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait Policy: Send + Sync {
    /// Returns the tick rate for this policy.
    ///
    /// This is the interval at which the policy will be ticked. The executor will attempt to
    /// tick the policy at this specified interval, but it may be delayed if the executor is
    /// busy with other policies. The developer of a policy should always use the `delta_time`
    /// argument passed to the `tick` method to determine how long it has been since the last
    /// tick. The duration return by this method is static and will not change during the
    /// lifetime of the policy.
    ///
    /// # Returns
    ///
    /// * `Duration` - The tick rate for this policy
    fn tick_rate(&self) -> Duration;

    /// Performs a policy tick for this process.
    ///
    /// This method is called periodically to allow the policy to perform its management
    /// logic, such as adjusting memory limits or monitoring resource usage.
    ///
    /// # Arguments
    ///
    /// * `delta_time` - The time elapsed since the last tick
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the tick completed successfully
    /// * `Err(_)` - If an error occurred during the tick
    async fn tick(&mut self, delta_time: Duration) -> anyhow::Result<()>;

    /// Called when a policy is removed. MUST restore cgroup values to defaults.
    ///
    /// This function is called when a policy is removed, and it should be used to clean up any
    /// resources or state associated with the policy.
    ///
    /// NOTE: The cgroup that the policy was managing might already be removed when cleanup is called.
    /// Policies should be resilient to this and not fail if the cgroup is gone. Any other errors
    /// should be logged but the cleanup logic should continue to do a best effort cleanup.
    async fn cleanup(&mut self);
}

/// Trait for policies that manage multiple processes collectively.
///
/// Aggregate policies are responsible for managing multiple processes and receive events
/// when processes are created and destroyed. They can perform cross-process optimizations
/// and resource management.
#[async_trait]
#[cfg_attr(test, mockall::automock)]
pub trait AggregatePolicy: Send + Sync {
    /// Returns the name of this aggregate policy.
    ///
    /// This name is used for logging and debugging purposes to identify which
    /// aggregate policy is being used.
    fn name(&self) -> &'static str {
        "Unknown"
    }

    /// Called when a new process is created.
    ///
    /// This method allows the aggregate policy to enroll the process in its
    /// management strategy if appropriate.
    ///
    /// # Arguments
    ///
    /// * `process` - Information about the newly created process
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - If the process was enrolled in this aggregate policy
    /// * `Ok(false)` - If the process was not enrolled
    /// * `Err(_)` - If an error occurred while processing the creation event
    async fn process_create(&mut self, process: &ProcessInfo) -> anyhow::Result<bool>;

    /// Called when a process is destroyed.
    ///
    /// This method allows the aggregate policy to clean up any resources or
    /// state associated with the removed process.
    ///
    /// # Arguments
    ///
    /// * `pid` - The process ID of the removed process
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - If the process was successfully unenrolled from this aggregate policy
    /// * `Ok(false)` - If the process was not enrolled in this policy
    /// * `Err(_)` - If an error occurred while processing the removal event
    async fn process_remove(&mut self, pid: u32) -> anyhow::Result<bool>;

    /// Performs a periodic tick for this aggregate policy.
    ///
    /// This method is called periodically to allow the aggregate policy to perform
    /// its management logic across all enrolled processes.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If the tick completed successfully
    /// * `Err(_)` - If an error occurred during the tick
    async fn tick(&mut self, delta_time: Duration) -> anyhow::Result<()>;

    /// Returns the tick rate for this policy.
    ///
    /// This is the interval at which the policy will be ticked. The executor will attempt to
    /// tick the policy at this specified interval, but it may be delayed if the executor is
    /// busy with other policies. The developer of a policy should always use the `delta_time`
    /// argument passed to the `tick` method to determine how long it has been since the last
    /// tick. The duration return by this method is static and will not change during the
    /// lifetime of the policy.
    ///
    /// # Returns
    ///
    /// * `Duration` - The tick rate for this policy
    fn tick_rate(&self) -> Duration;

    /// Called when a policy is removed. MUST restore cgroup values to defaults.
    ///
    /// This function is called when a policy is removed, and it should be used to clean up any
    /// resources or state associated with the policy.
    ///
    /// NOTE: The cgroup that the policy was managing might already be removed when cleanup is called.
    /// Policies should be resilient to this and not fail if the cgroup is gone. Any other errors
    /// should be logged but the cleanup logic should continue to do a best effort cleanup.
    async fn cleanup(&mut self);
}

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub exe: String,
    pub oom_score_adj: i32,
    pub cpu: String,
}

struct PolicyEntry {
    factory_name: &'static str,
    task_cancel_token: CancellationToken,
    task: JoinHandle<anyhow::Result<()>>,
}

struct AggregatePolicyEntry {
    policy: Arc<Mutex<Box<dyn AggregatePolicy>>>,
    task: JoinHandle<anyhow::Result<()>>,
}

struct Guard {
    policy_factories: Vec<Box<dyn PolicyFactory>>,
    active_policies: HashMap<u32, Vec<PolicyEntry>>,
    aggregate_policies: Vec<AggregatePolicyEntry>,
}

pub struct ProcessMonitor {
    guard: Arc<Mutex<Guard>>,
    global_cancel_token: CancellationToken,
}

impl ProcessMonitor {
    pub fn new(
        policy_factories: Vec<Box<dyn PolicyFactory>>,
        aggregate_policies: Vec<Box<dyn AggregatePolicy>>,
    ) -> Self {
        let global_cancel_token = CancellationToken::new();

        // Aggregate policies are always active, so create a task for each one on startup
        let aggregate_policy_tasks = aggregate_policies
            .into_iter()
            .map(|policy| Self::spawn_aggregate_policy_task(policy, global_cancel_token.clone()))
            .collect();

        Self {
            guard: Arc::new(Mutex::new(Guard {
                policy_factories,
                aggregate_policies: aggregate_policy_tasks,
                active_policies: HashMap::new(),
            })),
            global_cancel_token,
        }
    }

    fn spawn_aggregate_policy_task(
        policy: Box<dyn AggregatePolicy>,
        cancel_token: CancellationToken,
    ) -> AggregatePolicyEntry {
        let policy = Arc::new(Mutex::new(policy));

        let task = tokio::spawn({
            let task_policy = policy.clone();
            async move { Self::aggregate_policy_tick_loop(task_policy, cancel_token).await }
        });

        AggregatePolicyEntry { task, policy }
    }

    async fn aggregate_policy_tick_loop(
        task_policy: Arc<Mutex<Box<dyn AggregatePolicy>>>,
        cancel_token: CancellationToken,
    ) -> anyhow::Result<()> {
        // Initialize with a default tick rate, will be updated on first tick
        let tick_rate = {
            let policy_lock = task_policy.lock().await;
            policy_lock.tick_rate()
        };

        let mut interval = tokio::time::interval(tick_rate);
        let mut last_instant = std::time::Instant::now();

        loop {
            select! {
                biased;
                _ = cancel_token.cancelled() => {
                    info!("Cancelling policy task");
                    break;
                }
                _ = interval.tick() => {
                    let current_instant = std::time::Instant::now();
                    let delta_time = current_instant - last_instant;

                    {
                        let mut task_policy_lock = task_policy.lock().await;
                        match tokio::time::timeout(tick_rate, task_policy_lock.tick(delta_time)).await {
                            Ok(Ok(())) => {},
                            Ok(Err(e)) => error!("Failed to tick aggregate policy (name: {}): {e:?}", task_policy_lock.name()),
                            Err(_) => {
                                soft_error!("Timed out while ticking aggregate policy (name: {})", task_policy_lock.name());
                            }
                        }
                    } // drop(policy_lock)

                    last_instant = current_instant;
                }
            }
        }

        let mut task_policy_lock = task_policy.lock().await;
        task_policy_lock.cleanup().await;

        Ok(())
    }

    fn spawn_individual_policy_task(
        policy: Box<dyn Policy>,
        global_cancel_token: CancellationToken,
        process_info: ProcessInfo,
        factory_name: &'static str,
    ) -> PolicyEntry {
        let task_cancel_token = CancellationToken::new();

        let task = tokio::spawn({
            let task_cancel_token_clone = task_cancel_token.clone();
            async move {
                Self::individual_policy_tick_loop(
                    policy,
                    global_cancel_token,
                    task_cancel_token_clone.clone(),
                    process_info,
                    factory_name,
                )
                .await
            }
        });

        PolicyEntry {
            task_cancel_token,
            task,
            factory_name,
        }
    }

    async fn individual_policy_tick_loop(
        mut policy: Box<dyn Policy>,
        global_cancel_token: CancellationToken,
        task_cancel_token: CancellationToken,
        process_info: ProcessInfo,
        factory_name: &'static str,
    ) -> anyhow::Result<()> {
        let mut interval = tokio::time::interval(policy.tick_rate());
        let mut last_instant = std::time::Instant::now();

        loop {
            select! {
                biased;
                _ = global_cancel_token.cancelled() => {
                    info!("Global cancel policy task for {process_info:?}");
                    break;
                }
                _ = task_cancel_token.cancelled() => {
                    info!("Cancel policy task for {process_info:?}");
                    break;
                }
                _ = interval.tick() => {

                    let current_instant = std::time::Instant::now();
                    let delta_time = current_instant - last_instant;

                    match tokio::time::timeout(policy.tick_rate(), policy.tick(delta_time)).await {
                        Ok(Ok(())) => {},
                        Ok(Err(e)) => error!("Failed to tick policy (name: {factory_name}, pid: {}): {e:?}", process_info.pid),
                        Err(_) => {
                            soft_error!("Timed out while ticking policy (name: {factory_name})");
                        }
                    }

                    last_instant = current_instant;
                }
            }
        }

        policy.cleanup().await;

        Ok(())
    }

    /// Runs the process monitor on a task and enrolls processes into policies.
    ///
    /// This function takes a stream of CgroupEvents and enrolls processes into policies based on
    /// the provided factories.
    ///
    /// # Arguments
    ///
    /// * `stream` - A stream of CgroupEvents to process
    ///
    /// # Returns
    ///
    /// * `JoinHandle` - A handle to the task that is running the process monitor. This join handle
    /// should be monitord to ensure that the process monitor has not exited prematurely or returned
    /// an error. Either of these conditions would indicate that the process monitor has encountered
    /// an unrecoverable error and should be restarted.
    pub async fn run<S>(&self, mut stream: S) -> JoinHandle<anyhow::Result<()>>
    where
        S: futures::Stream<Item = CgroupEvent> + Unpin + Send + 'static,
    {
        let filter = |uid: u32, pid: u32| -> bool {
            // Don't enroll ourself or root processes into policies
            if pid == std::process::id() || uid == 0 {
                true
            } else {
                false
            }
        };

        let task_guard = self.guard.clone();
        let global_cancel_token = self.global_cancel_token.clone();

        tokio::task::spawn(async move {
            // Tracks in-flight attempt_to_read_process_info tasks per PID. Each call spawns on its own
            // tokio task, allowing parallel processing across distinct PIDs. Remove events wait for any
            // in-flight task to complete before cleanup. Note: PIDs no longer process in sequential order,
            // but unblocking the event stream during slow procfs retries justifies this tradeoff.
            let inflight_read_process_info: DashMap<u32, JoinHandle<()>> = DashMap::new();

            while let Some(event) = stream.next().await {
                match event {
                    CgroupEvent::Create { uid, pid } | CgroupEvent::Exists { uid, pid } => {
                        if filter(uid, pid) {
                            debug!("Filtering out process (uid: {uid}, pid: {pid}) from policy enforcement");
                            continue;
                        }

                        let inflight_task = tokio::task::spawn({
                            let inflight_cancel_token = global_cancel_token.clone();
                            let inflight_task_guard = task_guard.clone();

                            async move {
                                // If there's an error with reading process info, we skip enrolling
                                let process_info = attempt_to_read_process_info(pid, uid).await;
                                debug!("Process created: {process_info:?}");

                                {
                                    let mut write_guard = inflight_task_guard.lock().await;

                                    let mut policy_entries_to_create = Vec::new();
                                    for factory in write_guard.policy_factories.iter() {
                                        match factory.create(&process_info).await {
                                            Ok(Some(policy)) => {
                                                info!(
                                                "Enrolling {process_info:?} into memory policy {}",
                                                factory.name()
                                            );

                                                let policy_entry =
                                                    Self::spawn_individual_policy_task(
                                                        policy,
                                                        inflight_cancel_token.clone(),
                                                        process_info.clone(),
                                                        factory.name(),
                                                    );

                                                policy_entries_to_create.push(policy_entry);
                                            }
                                            Err(e) => {
                                                error!(
                                                    "Failed to apply memory policy factory: {e:?}"
                                                );
                                            }
                                            _ => {} // Fallthrough
                                        }
                                    }

                                    write_guard
                                        .active_policies
                                        .entry(pid)
                                        .or_insert_with(Vec::new)
                                        .extend(policy_entries_to_create);

                                    // Process aggregate policies
                                    for policy in write_guard.aggregate_policies.iter_mut() {
                                        let mut policy_lock = policy.policy.lock().await;
                                        match policy_lock.process_create(&process_info).await {
                                            Ok(true) => {
                                                info!(
                                            "Enrolling {process_info:?} into memory aggregate policy {}",
                                            policy_lock.name()
                                        );
                                            }
                                            Err(e) => {
                                                error!(
                                                "Failed to apply memory aggregate policy: {e:?}"
                                            );
                                            }
                                            _ => {} // Fallthrough
                                        }
                                    }
                                } // Release write_guard here
                            }
                        });

                        if let Some(_) = inflight_read_process_info.insert(pid, inflight_task) {
                            soft_error!("Inflight task already exists for pid");
                        }
                    }
                    CgroupEvent::Remove { uid, pid } => {
                        if filter(uid, pid) {
                            debug!("Filtering out process (uid: {uid}, pid: {pid}) from policy enforcement");
                            continue;
                        }

                        tokio::task::spawn({
                            let inflight_entry = inflight_read_process_info.remove(&pid);
                            let remove_task_guard = task_guard.clone();
                            async move {
                                if let Some((_, infight_task)) = inflight_entry {
                                    let _ = infight_task.await;
                                }

                                let mut write_guard = remove_task_guard.lock().await;

                                if let Some(policy_entries) =
                                    write_guard.active_policies.remove(&pid)
                                {
                                    for entry in policy_entries {
                                        // Cancel the task and wait for it to finish
                                        entry.task_cancel_token.cancel();
                                        match entry.task.await {
                                            Ok(Ok(())) => {
                                                info!(
                                                    "Unenrolling pid ({pid}) from policy ({})",
                                                    entry.factory_name
                                                );
                                            }
                                            Ok(Err(e)) => {
                                                error!(
                                                "Policy ({}) for pid ({pid}) exited with an error: {e:?}",
                                                entry.factory_name
                                            );
                                            }
                                            Err(e) => {
                                                error!(
                                                "Failed to join policy ({}) for pid ({pid}): {e:?}",
                                                entry.factory_name
                                            );
                                            }
                                        }
                                    }
                                }

                                for policy in write_guard.aggregate_policies.iter_mut() {
                                    let mut policy_lock = policy.policy.lock().await;
                                    match policy_lock.process_remove(pid).await {
                                        Ok(true) => {
                                            info!(
                                                "Unenrolling {pid} from aggregate policy ({})",
                                                policy_lock.name()
                                            );
                                        }
                                        Err(e) => {
                                            error!("Failed to remove pid ({pid}) from aggregate policy ({}): {e:?}", policy_lock.name());
                                        }
                                        _ => {} // Fallthrough
                                    }
                                }
                            }
                        });
                    }
                }
            }

            Ok(())
        })
    }

    /// Cleans up all active policies and joins on their completion.
    pub async fn cleanup(&mut self) {
        self.global_cancel_token.cancel();

        let (tasks_to_await, agg_tasks_to_await) = {
            let mut tasks_to_await = Vec::new();
            let mut agg_tasks_to_await = Vec::new();

            let mut guard = self.guard.lock().await;
            for (_, policy_entries) in guard.active_policies.drain() {
                tasks_to_await.extend(policy_entries.into_iter().map(|entry| entry.task));
            }

            for entry in guard.aggregate_policies.drain(..) {
                agg_tasks_to_await.push(entry.task);
            }

            (tasks_to_await, agg_tasks_to_await)
        };

        for task in tasks_to_await {
            let _ = task.await;
        }

        for task in agg_tasks_to_await {
            let _ = task.await;
        }
    }
}

impl Drop for ProcessMonitor {
    fn drop(&mut self) {
        self.global_cancel_token.cancel();
    }
}

async fn attempt_to_read_process_info(pid: u32, uid: u32) -> ProcessInfo {
    /// Maximum number of times to retry reading process info
    const MAX_ATTEMPTS: usize = 10;

    /// Default delay for any errors returned by the read_* procfs functions.
    const RETRY_DELAY: Duration = Duration::from_millis(2);

    /// Delay if we detect that the Android Application is in the zygote initialization
    /// setup. Zygote/Java takes a very long time to initialize so this delay is longer.
    /// This is mitigated by the fact that Android Applications do not spawn very often.
    const ZYGOTE_RETRY_DELAY: Duration = Duration::from_millis(50);

    let mut attempt = 0;
    let (comm_result, oom_score_adj_result, process_cgroup_cpu_result, exe_result) = loop {
        let comm_result = read_process_comm(pid).await;
        let oom_score_adj_result = read_oom_score_adj(pid).await.and_then(|oom_score_adj| {
            oom_score_adj
                .parse::<i32>()
                .map_err(|e| anyhow!("Failed to parse oom_score_adj '{oom_score_adj}': {e:?}"))
        });
        let process_cgroup_cpu_result = read_process_cgroup_cpu(pid).await;
        let exe_result = read_process_exe_from_cmdline(pid)
            .await
            .map_err(ProcessExeError::IoError)
            .and_then(|exe| {
                // TODO(T242376314): Unfortunately, for Android applications, they join the cgroupv2 hierarchy
                // while still running as the zygote process. This means the cmdline will reflect the zygote,
                // not the actual application. Unlike native services, there is no execv syscall to detect
                // when the application is running with its real command line arguments. Therefore, we retry
                // if the cmdline is "zygote64" or "zygote" and uid is not 0 (the actual zygote user).
                //
                // If the exe is "<pre-initialized>", it means the process is still in the zygote initialization
                // process. This is a special case for Android applications.
                if (uid != 0) && (exe == "zygote64" || exe == "zygote") {
                    debug!("Android zygote detected for pid ({pid})");
                    Err(ProcessExeError::AndroidZygote)
                } else if exe == "<pre-initialized>" {
                    debug!("Android pre-initialized detected for pid ({pid})");
                    Err(ProcessExeError::AndroidPreInitialized)
                } else {
                    Ok(exe)
                }
            });

        if attempt < MAX_ATTEMPTS {
            match (
                &comm_result,
                &oom_score_adj_result,
                &process_cgroup_cpu_result,
                &exe_result,
            ) {
                // IO errors from procfs reading use the standard retry delay
                (Err(e), _, _, _) | (_, Err(e), _, _) | (_, _, Err(e), _) => {
                    debug!("Failed to read process (pid: {pid}): {e:?}, retrying...");
                    tokio::time::sleep(RETRY_DELAY).await;
                }
                // Zygote errors use a longer delay
                (_, _, _, Err(ProcessExeError::AndroidZygote))
                | (_, _, _, Err(ProcessExeError::AndroidPreInitialized)) => {
                    debug!("Failed to read process (pid: {pid}): Android initialization in progress, retrying...");
                    tokio::time::sleep(ZYGOTE_RETRY_DELAY).await;
                }
                // IO errors from exe reading use the standard retry delay
                (_, _, _, Err(ProcessExeError::IoError(e))) => {
                    debug!("Failed to read process (pid: {pid}): {e:?}, retrying...");
                    tokio::time::sleep(RETRY_DELAY).await;
                }
                (Ok(_), Ok(_), Ok(_), Ok(_)) => {
                    break (
                        comm_result,
                        oom_score_adj_result,
                        process_cgroup_cpu_result,
                        exe_result,
                    );
                }
            }

            attempt += 1;
        } else {
            break (
                comm_result,
                oom_score_adj_result,
                process_cgroup_cpu_result,
                exe_result,
            );
        }
    };

    // Report any errors after exhuasting the retry attempts. We only report the first error matched
    // by the pattern. We also spawn a task to report the error since we do not want to block the
    // completion of attempt_to_read_process_info on an AIDL call.
    let error_description = match (
        &comm_result,
        &oom_score_adj_result,
        &process_cgroup_cpu_result,
        &exe_result,
    ) {
        (Err(e), _, _, _) => Some(format!("Failed to read process comm: {e:?}")),
        (_, Err(e), _, _) => Some(format!("Failed to read process oom_score_adj: {e:?}")),
        (_, _, Err(e), _) => Some(format!("Failed to read process cgroup cpu: {e:?}")),
        (_, _, _, Err(e)) => Some(format!("Failed to read process exe: {e:?}")),
        _ => None,
    };

    if let Some(error_description) = error_description {
        soft_error!("{}", error_description);
    }

    // Extract results, only log warnings for unexpected errors on final attempt
    let comm = comm_result.unwrap_or_else(|e| {
        error!("Failed to read process (pid: {pid}) comm: {e:?}");
        "<unknown>".to_string()
    });

    let exe = exe_result.unwrap_or_else(|e| {
        error!("Failed to read process (pid: {pid}) cmdline: {e:?}");
        "<unknown>".to_string()
    });

    let cpu = process_cgroup_cpu_result.unwrap_or_else(|e| {
        error!("Failed to read process (pid: {pid}) cgroup cpu: {e:?}");
        "".to_string()
    });

    let oom_score_adj = oom_score_adj_result.unwrap_or_else(|e| {
        error!("Failed to read process (pid: {pid}) oom_score_adj: {e:?}");
        0
    });

    ProcessInfo {
        pid,
        uid,
        comm,
        exe,
        oom_score_adj,
        cpu,
    }
}

async fn read_oom_score_adj(pid: u32) -> anyhow::Result<String> {
    let oom_score_adj_path = format!("/proc/{}/oom_score_adj", pid);
    let content = tokio::fs::read_to_string(&oom_score_adj_path).await?;
    Ok(content.trim().to_string())
}

async fn read_process_comm(pid: u32) -> anyhow::Result<String> {
    let comm_path = format!("/proc/{}/comm", pid);
    let content = tokio::fs::read_to_string(&comm_path).await?;
    Ok(content.trim().to_string())
}

async fn read_process_cgroup_cpu(pid: u32) -> anyhow::Result<String> {
    let comm_path = format!("/proc/{}/cgroup", pid);
    let content = tokio::fs::read_to_string(&comm_path).await?;
    let process_cgroup_info = content.parse::<ProcessCgroupInfo>().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Failed to parse process cgroup data",
        )
    })?;
    Ok(process_cgroup_info.cpu)
}

async fn read_process_exe_from_cmdline(pid: u32) -> anyhow::Result<String> {
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    let cmdline = tokio::fs::read_to_string(&cmdline_path).await?;
    parse_exe_from_cmdline(cmdline)
}

fn parse_exe_from_cmdline(cmdline: impl AsRef<str>) -> anyhow::Result<String> {
    let args: Vec<String> = cmdline
        .as_ref()
        .split('\0')
        .filter_map(|s| {
            if !s.is_empty() {
                Some(s.trim().to_string())
            } else {
                None
            }
        })
        .collect();

    if let Some(exe_path) = args.first() {
        Path::new(exe_path)
            .file_name()
            .ok_or_else(|| anyhow!("No filename found in path"))
            .map(|name| name.to_string_lossy().into_owned())
    } else {
        Err(anyhow!("No executable found in cmdline"))
    }
}

#[cfg(test)]
mod tests {
    use nativetestutils::*;
    use tokio::sync::mpsc;
    use tokio::time::sleep;
    use tokio::time::Duration;
    use tokio_stream::wrappers::UnboundedReceiverStream;

    use super::*;

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_cmdline_parse_abs_path_and_args() {
        const CMDLINE: &str = "/usr/bin/python3\x00script.py\x00--flag\x00";
        let exe = parse_exe_from_cmdline(CMDLINE).unwrap();
        assert_eq!(exe, "python3");
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_cmdline_parse_relative_path_and_args() {
        const CMDLINE: &str = "nginx\x00-g\x00daemon off;\x00";
        let exe = parse_exe_from_cmdline(CMDLINE).unwrap();
        assert_eq!(exe, "nginx");
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_cmdline_parse_realative_path_with_dir() {
        const CMDLINE: &str = "./bin/myapp\x00--port\x008080\x00";
        let exe = parse_exe_from_cmdline(CMDLINE).unwrap();
        assert_eq!(exe, "myapp");
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_cmdline_parse_spaces_in_exe() {
        const CMDLINE: &str = "  my app worker\x00--verbose\x00";
        let exe = parse_exe_from_cmdline(CMDLINE).unwrap();
        assert_eq!(exe, "my app worker");
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_cmdline_parse_kernel_style() {
        const CMDLINE: &str = "[kthreadd]\x00";
        let exe = parse_exe_from_cmdline(CMDLINE).unwrap();
        assert_eq!(exe, "[kthreadd]");
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_cmdline_parse_no_exe() {
        const CMDLINE: &str = "";
        let exe_result = parse_exe_from_cmdline(CMDLINE);
        assert!(matches!(exe_result, Err(_)));
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_cmdline_parse_only_exe() {
        const CMDLINE: &str = "sleep\x00";
        let exe = parse_exe_from_cmdline(CMDLINE).unwrap();
        assert_eq!(exe, "sleep");
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_cmdline_parse_no_trailing_null() {
        const CMDLINE: &str = "sleep";
        let exe = parse_exe_from_cmdline(CMDLINE).unwrap();
        assert_eq!(exe, "sleep");
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_cmdline_parse_android_app_name() {
        const CMDLINE: &str = "com.example.myapp\x00";
        let exe = parse_exe_from_cmdline(CMDLINE).unwrap();
        assert_eq!(exe, "com.example.myapp");
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_cmdline_parse_android_app_name_with_suffix() {
        const CMDLINE: &str = "com.example.myapp:remote\x00";
        let exe = parse_exe_from_cmdline(CMDLINE).unwrap();
        assert_eq!(exe, "com.example.myapp:remote");
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_cmdline_parse_android_app_isolated() {
        const CMDLINE: &str = "com.example.myapp:isolated\x00";
        let exe = parse_exe_from_cmdline(CMDLINE).unwrap();
        assert_eq!(exe, "com.example.myapp:isolated");
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_cmdline_parse_apex() {
        const CMDLINE: &str =
            "/apex/com.android.art/bin/app_process64\x00--zygote\x00--socket-name=zygote64\x00";
        let exe = parse_exe_from_cmdline(CMDLINE).unwrap();
        assert_eq!(exe, "app_process64");
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_cmdline_parse_surfaceflinger() {
        const CMDLINE: &str = "/system/bin/surfaceflinger\x00";
        let exe = parse_exe_from_cmdline(CMDLINE).unwrap();
        assert_eq!(exe, "surfaceflinger");
    }

    /// Creates a mock policy factory for testing.
    ///
    /// This helper function creates a mock policy factory that can be configured to either
    /// create a policy or not based on the `should_create` parameter.
    ///
    /// # Arguments
    ///
    /// * `name` - The name to return when the factory's `name()` method is called
    /// * `should_create` - Whether the factory should create a policy when `create()` is called
    ///
    /// # Returns
    ///
    /// A configured `MockPolicyFactory` that will return a mock policy if `should_create` is true,
    /// or None if `should_create` is false.
    fn create_mock_factory(name: &'static str, should_create: bool) -> MockPolicyFactory {
        let mut policy_factory = MockPolicyFactory::new();

        policy_factory.expect_name().return_const(name);
        policy_factory
            .expect_create()
            .times(1)
            .returning(move |process: &ProcessInfo| {
                assert_eq!(process.pid, 1);
                assert_eq!(process.uid, 1000);

                let result = if should_create {
                    let mut mock_policy = MockPolicy::new();
                    mock_policy
                        .expect_tick_rate()
                        .return_const(Duration::from_millis(100));
                    mock_policy
                        .expect_tick()
                        .returning(|_| Box::pin(async move { Ok(()) }));
                    mock_policy
                        .expect_cleanup()
                        .times(1)
                        .returning(|| Box::pin(async move {}));
                    Ok(Some(Box::<dyn Policy>::from(Box::new(mock_policy))))
                } else {
                    Ok(None)
                };

                Box::pin(async move { result })
            });

        policy_factory
    }

    /// Creates a mock aggregate policy for testing
    ///
    /// This helper function creates a mock aggregate policy
    ///
    /// # Returns
    ///
    /// A configured `MockAggregatePolicy`
    fn create_aggregate_policy() -> MockAggregatePolicy {
        let mut agg_policy = MockAggregatePolicy::new();
        agg_policy
            .expect_tick_rate()
            .return_const(Duration::from_millis(1000));
        agg_policy
            .expect_tick()
            .returning(|_| Box::pin(async move { Ok(()) }));
        agg_policy
            .expect_process_create()
            .times(1)
            .returning(|process: &ProcessInfo| {
                assert_eq!(process.pid, 1);
                assert_eq!(process.uid, 1000);
                Box::pin(async move { Ok(true) })
            });
        agg_policy
            .expect_process_remove()
            .times(1)
            .returning(|pid: u32| {
                assert_eq!(pid, 1);
                Box::pin(async move { Ok(true) })
            });
        agg_policy
            .expect_cleanup()
            .times(1)
            .returning(|| Box::pin(async move {}));

        agg_policy
    }

    #[tokio::test]
    async fn test_process_monitor_enrolls_multiple_policies_for_exist() {
        let factory1 = create_mock_factory("TestFactory1", true);
        let factory2 = create_mock_factory("TestFactory2", true);
        let factory3 = create_mock_factory("TestFactory3", false);

        let agg_policy1 = create_aggregate_policy();
        let agg_policy2 = create_aggregate_policy();

        let mut process_monitor = ProcessMonitor::new(
            vec![Box::new(factory1), Box::new(factory2), Box::new(factory3)],
            vec![Box::new(agg_policy1), Box::new(agg_policy2)],
        );

        let (tx, rx) = mpsc::unbounded_channel();
        let cgroup_stream = UnboundedReceiverStream::new(rx);

        let mut process_monitor_task = process_monitor.run(cgroup_stream).await;

        // TODO(T237443064): This is a bit hacky. Currently we need to specify an actual pid
        // on the system because we do not have a way to mock attempt_to_read_process_info.
        // Currently we specify pid 1 (the init process), but we should use a mock instead.
        tx.send(CgroupEvent::Exists { uid: 1000, pid: 1 }).unwrap();
        tx.send(CgroupEvent::Remove { uid: 1000, pid: 1 }).unwrap();

        // Let the monitor process the event
        select! {
            _ = sleep(Duration::from_millis(100)) => {},
            process_monitor_result = &mut process_monitor_task => {
                panic!("ProcessMonitor.run() exited unexpectedly with result: {process_monitor_result:?}");
            }
        }

        process_monitor.cleanup().await;

        // The policy expectations will be verified when they're dropped
    }

    #[tokio::test]
    async fn test_process_monitor_enrolls_multiple_policies_for_create() {
        let factory1 = create_mock_factory("TestFactory1", true);
        let factory2 = create_mock_factory("TestFactory2", true);
        let factory3 = create_mock_factory("TestFactory3", false);

        let agg_policy1 = create_aggregate_policy();
        let agg_policy2 = create_aggregate_policy();

        let mut process_monitor = ProcessMonitor::new(
            vec![Box::new(factory1), Box::new(factory2), Box::new(factory3)],
            vec![Box::new(agg_policy1), Box::new(agg_policy2)],
        );

        let (tx, rx) = mpsc::unbounded_channel();
        let cgroup_stream = UnboundedReceiverStream::new(rx);

        let mut process_monitor_task = process_monitor.run(cgroup_stream).await;

        // TODO(T237443064): This is a bit hacky. Currently we need to specify an actual pid
        // on the system because we do not have a way to mock attempt_to_read_process_info.
        // Currently we specify pid 1 (the init process), but we should use a mock instead.
        tx.send(CgroupEvent::Create { uid: 1000, pid: 1 }).unwrap();
        tx.send(CgroupEvent::Remove { uid: 1000, pid: 1 }).unwrap();

        // Let the monitor process the event
        select! {
            _ = sleep(Duration::from_millis(100)) => {},
            process_monitor_result = &mut process_monitor_task => {
                panic!("ProcessMonitor.run() exited unexpectedly with result: {process_monitor_result:?}");
            }
        }

        process_monitor.cleanup().await;

        // The policy expectations will be verified when they're dropped
    }

    #[tokio::test]
    async fn test_two_policies_with_different_tick_rates() {
        let mut policy1 = MockPolicy::new();
        let mut policy2 = MockPolicy::new();
        let global_cancel_token = CancellationToken::new();

        // Set up expectations for tick rates
        policy1
            .expect_tick_rate()
            .return_const(Duration::from_millis(50));
        policy2
            .expect_tick_rate()
            .return_const(Duration::from_millis(100));

        // FastPolicy (50ms) - expect at least 4 calls in 250ms
        policy1
            .expect_tick()
            .times(4..=6)
            .returning(|_| Box::pin(async move { Ok(()) }));

        // SlowPolicy (100ms) - expect at least 2 calls in 250ms
        policy2
            .expect_tick()
            .times(2..=4)
            .returning(|_| Box::pin(async move { Ok(()) }));

        // Expect both polices to be cleaned up on exit
        policy1
            .expect_cleanup()
            .times(1)
            .returning(|| Box::pin(async move {}));
        policy2
            .expect_cleanup()
            .times(1)
            .returning(|| Box::pin(async move {}));

        let process_info = ProcessInfo {
            pid: 1234,
            uid: 1000,
            comm: "test".to_string(),
            exe: "test".to_string(),
            oom_score_adj: 0,
            cpu: "".to_string(),
        };

        // Spawn individual policy tasks
        let entry1 = ProcessMonitor::spawn_individual_policy_task(
            Box::new(policy1),
            global_cancel_token.clone(),
            process_info.clone(),
            "FastPolicy",
        );

        let entry2 = ProcessMonitor::spawn_individual_policy_task(
            Box::new(policy2),
            global_cancel_token.clone(),
            process_info,
            "SlowPolicy",
        );

        // Let the policies run for a sufficient time to observe multiple ticks
        sleep(Duration::from_millis(250)).await;

        // Cancel the tasks
        global_cancel_token.cancel();

        // Wait for tasks to complete - this will verify the expectations
        let _ = entry1.task.await;
        let _ = entry2.task.await;

        // MockPolicy will automatically verify that expectations were met when dropped
    }

    #[tokio::test]
    async fn test_two_aggregate_policies_with_different_tick_rates() {
        let mut policy1 = MockAggregatePolicy::new();
        let mut policy2 = MockAggregatePolicy::new();
        let global_cancel_token = CancellationToken::new();

        // Set up expectations for tick rates
        policy1
            .expect_tick_rate()
            .return_const(Duration::from_millis(40));
        policy2
            .expect_tick_rate()
            .return_const(Duration::from_millis(80));

        // FastAggregatePolicy (40ms) - expect at least 4 calls in 200ms
        policy1
            .expect_tick()
            .times(4..=7)
            .returning(|_| Box::pin(async move { Ok(()) }));

        // SlowAggregatePolicy (80ms) - expect at least 2 calls in 200ms
        policy2
            .expect_tick()
            .times(2..=4)
            .returning(|_| Box::pin(async move { Ok(()) }));

        // Expect both polices to be cleaned up on exit
        policy1
            .expect_cleanup()
            .times(1)
            .returning(|| Box::pin(async move {}));
        policy2
            .expect_cleanup()
            .times(1)
            .returning(|| Box::pin(async move {}));

        // Spawn aggregate policy tasks
        let entry1 = ProcessMonitor::spawn_aggregate_policy_task(
            Box::new(policy1),
            global_cancel_token.clone(),
        );
        let entry2 = ProcessMonitor::spawn_aggregate_policy_task(
            Box::new(policy2),
            global_cancel_token.clone(),
        );

        // Let the policies run for a sufficient time to observe multiple ticks
        sleep(Duration::from_millis(200)).await;

        // Cancel the tasks
        global_cancel_token.cancel();

        // Wait for tasks to complete - this will verify the expectations
        let _ = entry1.task.await;
        let _ = entry2.task.await;

        // MockAggregatePolicy will automatically verify that expectations were met when dropped
    }

    #[tokio::test]
    async fn test_policy_tick_called_with_correct_delta_time() {
        let mut policy = MockPolicy::new();
        let global_cancel_token = CancellationToken::new();

        policy
            .expect_tick_rate()
            .return_const(Duration::from_millis(100));

        // First tick happens immediately with small delta_time (close to 0)
        policy
            .expect_tick()
            .times(1)
            .withf(|delta| {
                // First tick should have very small delta_time
                *delta <= Duration::from_millis(15)
            })
            .returning(|_| Box::pin(async move { Ok(()) }));

        // Subsequent ticks should have proper intervals
        policy
            .expect_tick()
            .times(2..=3)
            .withf(|delta| {
                // Delta time should be roughly around the tick rate (allow for timing variance)
                *delta >= Duration::from_millis(90) && *delta <= Duration::from_millis(110)
            })
            .returning(|_| Box::pin(async move { Ok(()) }));

        // Expect policy to be cleaned up on exit
        policy
            .expect_cleanup()
            .times(1)
            .returning(|| Box::pin(async move {}));

        let process_info = ProcessInfo {
            pid: 1234,
            uid: 1000,
            comm: "test".to_string(),
            exe: "test".to_string(),
            oom_score_adj: 0,
            cpu: "".to_string(),
        };

        let entry = ProcessMonitor::spawn_individual_policy_task(
            Box::new(policy),
            global_cancel_token.clone(),
            process_info,
            "TestPolicy",
        );

        sleep(Duration::from_millis(250)).await;

        global_cancel_token.cancel();
        let _ = entry.task.await;
    }

    #[tokio::test]
    async fn test_aggregate_policy_tick_called_with_correct_delta_time() {
        let mut policy = MockAggregatePolicy::new();
        let global_cancel_token = CancellationToken::new();

        policy
            .expect_tick_rate()
            .return_const(Duration::from_millis(100));

        // First tick happens immediately with small delta_time (close to 0)
        policy
            .expect_tick()
            .times(1)
            .withf(|delta| {
                // First tick should have very small delta_time
                *delta <= Duration::from_millis(15)
            })
            .returning(|_| Box::pin(async move { Ok(()) }));

        // Subsequent ticks should have proper intervals
        policy
            .expect_tick()
            .times(2..=3)
            .withf(|delta| {
                // Delta time should be roughly around the tick rate (allow for timing variance)
                *delta >= Duration::from_millis(90) && *delta <= Duration::from_millis(110)
            })
            .returning(|_| Box::pin(async move { Ok(()) }));

        // Expect policy to be cleaned up on exit
        policy
            .expect_cleanup()
            .times(1)
            .returning(|| Box::pin(async move {}));

        let entry = ProcessMonitor::spawn_aggregate_policy_task(
            Box::new(policy),
            global_cancel_token.clone(),
        );

        sleep(Duration::from_millis(250)).await;

        global_cancel_token.cancel();
        let _ = entry.task.await;
    }
}
