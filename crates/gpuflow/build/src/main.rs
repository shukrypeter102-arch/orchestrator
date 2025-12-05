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

use libbpf_cargo::SkeletonBuilder;

fn main() {
    SkeletonBuilder::new()
        .source("../bpf/credits.bpf.c")
        .clang("../../../../../../../prebuilts/clang/host/linux-x86/clang-r487747c/bin/clang")
        .clang_args([
            "-I../../../../../system/bpfprogs/include/vmlinux/android_5.10/arm64",
            "-I../../../../../system/bpfprogs/include/libbpf-tools",
        ])
        .build_and_generate("../src/gpu_skel.rs")
        .unwrap();
}
