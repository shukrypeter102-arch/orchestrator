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

#[cfg(test)]
pub mod tests {
    use orchestrator_common::process_monitor::ProcessInfo;

    use crate::stats::Readout;
    use crate::stats::Stats;

    pub fn create_test_process_info() -> ProcessInfo {
        ProcessInfo {
            pid: 1234,
            uid: 2000, // Non-system user to avoid being skipped
            comm: "test_process".to_string(),
            exe: "/test/exe".to_string(),
            oom_score_adj: 1, // Non-zero to avoid being skipped as immersive app
            cpu: "".to_string(),
        }
    }

    pub fn create_psi_readout(total: u64) -> Readout {
        Readout {
            some: Stats {
                avg10: 0.0,
                avg60: 0.0,
                avg300: 0.0,
                total,
            },
            full: Stats {
                avg10: 0.0,
                avg60: 0.0,
                avg300: 0.0,
                total,
            },
        }
    }
}
