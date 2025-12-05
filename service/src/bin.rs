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
use cpuflow::CpuFlow;
use futures_util::join;
use futures_util::FutureExt as _;
use gpuflow::GpuFlow;
use log::error;
use log::info;
use memflow::Memflow;
use orchestrator_common::setup_logging;
use orchestrator_common::Flow as _;
use tokio::runtime;
use tokio::select;
use tokio::signal::unix::signal;
use tokio::signal::unix::SignalKind;
use tokio_util::sync::CancellationToken;

const MAX_BLOCKING_THREADS: usize = 64;

// PANIC: If we can not build the runtime, we should panic since there is
// nothing we can do to recover from this.
#[allow(clippy::expect_used)]
fn build_orchestrator_runtime() -> runtime::Runtime {
    // NB: current-thread runtime for orchestrator. We are using it to do basic
    // setup and then monitor signals and futures from other runtimes.
    //
    // Truncate `orchestrator-` to `orch-` since max Linux thread name size is
    // 16 characters (including null terminator).
    runtime::Builder::new_current_thread()
        .thread_name("orch-")
        .enable_io()
        .enable_time()
        .build()
        .expect("Failed to create orchestrator runtime")
}

// PANIC: If we can not build the runtime, we should panic since there is
// nothing we can do to recover from this.
#[allow(clippy::expect_used)]
fn build_cpuflow_runtime() -> runtime::Runtime {
    runtime::Builder::new_multi_thread()
        .thread_name("cpuflow-")
        .enable_all()
        .max_blocking_threads(MAX_BLOCKING_THREADS)
        .build()
        .expect("Failed to create cpuflow runtime")
}

// PANIC: If we can not build the runtime, we should panic since there is
// nothing we can do to recover from this.
#[allow(clippy::expect_used)]
fn build_gpuflow_runtime() -> runtime::Runtime {
    runtime::Builder::new_multi_thread()
        .thread_name("gpuflow-")
        .enable_all()
        .max_blocking_threads(MAX_BLOCKING_THREADS)
        .build()
        .expect("Failed to create gpuflow runtime")
}

// PANIC: If we can not build the runtime, we should panic since there is
// nothing we can do to recover from this.
#[allow(clippy::expect_used)]
fn build_memflow_runtime() -> runtime::Runtime {
    runtime::Builder::new_multi_thread()
        .thread_name("memflow-")
        .enable_all()
        .max_blocking_threads(MAX_BLOCKING_THREADS)
        .build()
        .expect("Failed to create memflow runtime")
}

const LOG_TAG: &str = "orchestrator";

/// Represents the maximum amount of time we will wait for runtimes to exit
/// their dispatch loop, clean up any resources, and exit. If this timeout is
/// reached, the task running the runtime will be aborted and logic in the
/// runtime will no longer be executed.
///
/// This timeout is based on the amount of time that init will wait for us
/// to respond to a SIGTERM before sending a SIGKILL [1].
///
/// [1]: https://fburl.com/code/hqiei8tr
const MAX_SHUTDOWN_TIME: Duration = Duration::from_millis(190);

fn main() {
    setup_logging(LOG_TAG);
    binder::ProcessState::start_thread_pool();

    let cancellation_token = CancellationToken::new();
    let orchestrator_runtime = build_orchestrator_runtime();
    let cpuflow_runtime = build_cpuflow_runtime();
    let gpuflow_runtime = build_gpuflow_runtime();
    let memflow_runtime = build_memflow_runtime();

    let cpuflow_handle = cpuflow_runtime
        .spawn({
            let mut cpuflow = CpuFlow::new();
            let cpuflow_cancel_token = cancellation_token.clone();
            async move { cpuflow.run(cpuflow_cancel_token).await }
        })
        .map(|result| match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(format!("{e:?}")),
            Err(e) => Err(format!("{e:?}")),
        })
        .shared();

    let gpuflow_handle = gpuflow_runtime
        .spawn({
            let mut gpuflow = GpuFlow::new();
            let gpuflow_cancel_token = cancellation_token.clone();
            async move { gpuflow.run(gpuflow_cancel_token).await }
        })
        .map(|result| match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(format!("{e:?}")),
            Err(e) => Err(format!("{e:?}")),
        })
        .shared();

    let memflow_handle = memflow_runtime
        .spawn({
            let mut memflow = Memflow::new();
            let memflow_cancel_token = cancellation_token.clone();
            async move { memflow.run(memflow_cancel_token).await }
        })
        .map(|result| match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(format!("{e:?}")),
            Err(e) => Err(format!("{e:?}")),
        })
        .shared();

    let orchestrator_result: anyhow::Result<()> = orchestrator_runtime.block_on(async {
        let mut sigint = signal(SignalKind::interrupt())?;
        let mut sigterm = signal(SignalKind::terminate())?;

        let dispatch_result = select! {
            biased;
            _ = sigint.recv() => {
                info!("Received SIGINT, shutting down...");
                Ok(())
            },
            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down...");
                Ok(())
            },
            cpuflow_result = cpuflow_handle.clone() => {
                match cpuflow_result {
                    Ok(()) => Err(anyhow!("cpuflow exited prematurely")),
                    Err(e) => Err(anyhow!("cpuflow exited with an error: {e:?}")),
                }
            },
            gpuflow_result = gpuflow_handle.clone() => {
                match gpuflow_result {
                    Ok(()) => Err(anyhow!("gpuflow exited prematurely")),
                    Err(e) => Err(anyhow!("gpuflow exited with an error: {e:?}")),
                }
            },
            memflow_result = memflow_handle.clone() => {
                match memflow_result {
                    Ok(()) => Err(anyhow!("memflow exited prematurely")),
                    Err(e) => Err(anyhow!("memflow exited with an error: {e:?}")),
                }
            }
        };

        // Signal to all runtimes to shutdown
        cancellation_token.cancel();

        // Wait for all the runtimes to finish, or timeout after MAX_SHUTDOWN_TIME. That error
        // takes priority, then we check the runtime results if all flows exited cleanly.
        let shutdown_result = tokio::time::timeout(MAX_SHUTDOWN_TIME, async {
            join!(cpuflow_handle, gpuflow_handle, memflow_handle)
        })
        .await
        .map_err(|_| anyhow!("Shutdown timed out after {MAX_SHUTDOWN_TIME:?}"))
        .and_then(|(cpu_result, gpu_result, mem_result)| {
            if let Err(e) = &cpu_result {
                error!("cpuflow exited with an error during shutdown: {e:?}");
            }

            if let Err(e) = &gpu_result {
                error!("gpuflow exited with an error during shutdown: {e:?}");
            }

            if let Err(e) = &mem_result {
                error!("memflow exited with an error during shutdown: {e:?}");
            }

            match (cpu_result, gpu_result, mem_result) {
                (Ok(_), Ok(_), Ok(_)) => Ok(()),
                (Err(e), _, _) => Err(anyhow!(
                    "cpuflow exited with an error during shutdown: {e:?}"
                )),
                (_, Err(e), _) => Err(anyhow!(
                    "gpuflow exited with an error during shutdown: {e:?}"
                )),
                (_, _, Err(e)) => Err(anyhow!(
                    "memflow exited with an error during shutdown: {e:?}"
                )),
            }
        });

        // Dispatch results takes precedence over runtime results since the
        // error will be more descriptive then a generic runtime error.
        dispatch_result?;
        shutdown_result?;

        Ok(())
    });

    // PANIC: After all the runtimes have cleaned up, it is now safe to panic! if we received an error
    // in the main dispatch loop. Panicking here is intentional: we want the process to crash so that
    // the failure is visible in logview crash reports and can be investigated. This ensures that
    // unexpected errors are not silently ignored and are properly surfaced for debugging.
    #[allow(clippy::panic)]
    if let Err(e) = orchestrator_result {
        panic!("orchestrator exited with error: {e:?}");
    } else {
        info!("orchestrator exited successfully. Goodbye");
    }
}
