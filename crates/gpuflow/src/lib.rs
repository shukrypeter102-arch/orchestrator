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

use async_trait::async_trait;
use log::info;
use orchestrator_common::Flow;
use tokio::select;
use tokio_util::sync::CancellationToken;

pub struct GpuFlow {}

impl GpuFlow {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl Flow for GpuFlow {
    async fn run(&mut self, cancel_token: CancellationToken) -> anyhow::Result<()> {
        #[allow(clippy::never_loop)]
        let dispatch_loop_result = loop {
            select! {
                biased;
                _ = cancel_token.cancelled() => {
                    info!("gpuflow cancelled, shutting down...");
                    break Ok(());
                },
            }
        };

        // TODO: Clean up resources

        dispatch_loop_result
    }
}
