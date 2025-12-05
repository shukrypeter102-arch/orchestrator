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

macro_rules! extract_heap_stats {
    ($heap_memory_stats:expr, $heap_type:expr) => {
        (
            $heap_memory_stats.get($heap_type).map_or(Ok(-1), |stats| {
                stats
                    .pss_kib
                    .try_into()
                    .context("Could not convert pss_kib to i64")
            })?,
            $heap_memory_stats.get($heap_type).map_or(Ok(-1), |stats| {
                stats
                    .rss_kib
                    .try_into()
                    .context("Could not convert rss_kib to i64")
            })?,
            $heap_memory_stats.get($heap_type).map_or(Ok(-1), |stats| {
                stats
                    .swapped_out_kib
                    .try_into()
                    .context("Could not convert swapped_out_kib to i64")
            })?,
            $heap_memory_stats.get($heap_type).map_or(Ok(-1), |stats| {
                stats
                    .swapped_out_pss_kib
                    .try_into()
                    .context("Could not convert swapped_out_pss_kib to i64")
            })?,
        )
    };
}
use hzos_memory::footprint::MemoryFootprint;
use hzos_memory::heap::get_heap_memory_stats;
use hzos_memory::heap::HeapType;
use hzos_system_native_sysprops::hzos_system_native;
use log::error;
use log::info;
use log::log_enabled;
use log::trace;
use log::Level;
use orchestrator_common::process_monitor::Policy;
use orchestrator_common::process_monitor::PolicyFactory;
use orchestrator_common::process_monitor::ProcessInfo;
use statslog_meta_memflow::process_heap_type_info;

use crate::FileSystemCgroup;
// List of process names to exclude from memory throttling
// TODO: T237325279 - Move excluded processes list to a config file
const INCLUDED_SUBSTRINGS: &[&str] = &[
    "/system/bin/",
    "/vendor/bin/",
    "/system_ext/bin/",
    "com.oculus",
    "com.facebook",
];

#[derive(Clone, Copy)]
pub struct HeapTelemetryConfig {
    pub tick_rate: Duration,
    pub threshold_kib: u64,
}

fn is_meta_owned_process(process_name: String) -> bool {
    for substring in INCLUDED_SUBSTRINGS {
        if process_name.contains(substring) {
            return true;
        }
    }
    false
}

impl HeapTelemetryConfig {
    pub fn from_sysprops() -> anyhow::Result<Self> {
        let tick_rate = Duration::from_millis(
            hzos_system_native::memflow_heap_telemetry_tick_rate()
                .context("Could not read 'memflow_telemetry_tick_rate' sysprop")?
                .context("Value not set for 'memflow_telemetry_tick_rate' sysprop")?
                .try_into()
                .context("'memflow_telemetry_tick_rate' must be non-negative")?,
        );

        let threshold_kib = hzos_system_native::memflow_heap_telemetry_threshold_kib()
            .context("Could not read 'memflow_heap_telemetry_threshold_kib' sysprop")?
            .context("Value not set for 'memflow_heap_telemetry_threshold_kib' sysprop")?
            .try_into()
            .context("'memflow_heap_telemetry_threshold_kib' must be non-negative")?;

        Ok(Self {
            tick_rate,
            threshold_kib,
        })
    }
}

pub struct HeapTelemetryPolicyFactory {
    config: HeapTelemetryConfig,
}

impl HeapTelemetryPolicyFactory {
    pub fn new(config: HeapTelemetryConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl PolicyFactory for HeapTelemetryPolicyFactory {
    fn name(&self) -> &'static str {
        "Heap Telemetry Controller"
    }

    async fn create(&self, process: &ProcessInfo) -> anyhow::Result<Option<Box<dyn Policy>>> {
        // Only collect heap type telemetry for Meta-owned processes
        if is_meta_owned_process(process.exe.clone()) {
            let policy = HeapTelemetryPolicy::new(process.clone(), self.config).await?;
            Ok(Some(Box::new(policy)))
        } else {
            Ok(None)
        }
    }
}

pub struct HeapTelemetryPolicy {
    process_info: ProcessInfo,
    config: HeapTelemetryConfig,
    cgroup: FileSystemCgroup,
}

impl HeapTelemetryPolicy {
    pub async fn new(
        process_info: ProcessInfo,
        config: HeapTelemetryConfig,
    ) -> anyhow::Result<Self> {
        let cgroup: FileSystemCgroup =
            FileSystemCgroup::from_uid_and_pid(process_info.uid, process_info.pid);

        Ok(Self {
            process_info,
            config,
            cgroup,
        })
    }
}

#[async_trait]
impl Policy for HeapTelemetryPolicy {
    fn tick_rate(&self) -> Duration {
        self.config.tick_rate
    }
    #[allow(unused_variables)]
    async fn tick(&mut self, delta_time: Duration) -> anyhow::Result<()> {
        let Self {
            process_info,
            config,
            cgroup,
        } = self;

        let footprint = match MemoryFootprint::new(process_info.pid as i32).await {
            Ok(footprint) => footprint,
            Err(e) => {
                error!(
                    "Failed to get memory footprint for process {}: {:?}",
                    process_info.pid, e
                );
                return Ok(());
            }
        };
        let pss_including_swap_kib = footprint
            .pss_including_swap_kib
            .try_into()
            .context("Could not convert pss_including_swap_kib to i64")?;

        let threshold_kib = match config.threshold_kib.try_into() {
            Ok(threshold) => threshold,
            Err(e) => {
                error!("Failed to convert threshold_kib to i64: {:?}", e);
                return Ok(());
            }
        };

        // Log heap memory stats if the process exceeds the threshold
        if pss_including_swap_kib >= threshold_kib {
            info!(
                "Process {} has exceeded the heap telemetry threshold, logging.",
                process_info.exe
            );
            let heap_memory_stats = get_heap_memory_stats(process_info.pid as i32).await?;

            let process_pid = process_info.pid as i32;
            let process_exe = &process_info.exe;

            let memtrack_graphics_pss_kib: i64 = footprint
                .memtrack_graphics_pss_kib
                .try_into()
                .context("Could not convert memtrack_graphics_pss_kib to i64")?;
            let memtrack_gl_pss_kib: i64 = footprint
                .memtrack_gl_pss_kib
                .try_into()
                .context("Could not convert memtrack_gl_pss_kib to i64")?;
            let memtrack_other_pss_kib: i64 = footprint
                .memtrack_other_pss_kib
                .try_into()
                .context("Could not convert memtrack_other_pss_kib to i64")?;

            let (unknown_pss_kib, unknown_rss_kib, unknown_swap_kib, unknown_swap_pss_kib) =
                extract_heap_stats!(heap_memory_stats, HeapType::Unknown);

            let (dalvik_pss_kib, dalvik_rss_kib, dalvik_swap_kib, dalvik_swap_pss_kib) =
                extract_heap_stats!(heap_memory_stats, HeapType::Dalvik);

            let (
                dalvik_other_pss_kib,
                dalvik_other_rss_kib,
                dalvik_other_swap_kib,
                dalvik_other_swap_pss_kib,
            ) = extract_heap_stats!(heap_memory_stats, HeapType::DalvikOther);

            let (stack_pss_kib, stack_rss_kib, stack_swap_kib, stack_swap_pss_kib) =
                extract_heap_stats!(heap_memory_stats, HeapType::Stack);

            let (cursor_pss_kib, _cursor_rss_kib, _cursor_swap_kib, cursor_swap_pss_kib) =
                extract_heap_stats!(heap_memory_stats, HeapType::Cursor);

            let (ashmem_pss_kib, ashmem_rss_kib, ashmem_swap_kib, ashmem_swap_pss_kib) =
                extract_heap_stats!(heap_memory_stats, HeapType::Ashmem);
            let (gl_dev_pss_kib, gl_dev_rss_kib, gl_dev_swap_kib, gl_dev_swap_pss_kib) =
                extract_heap_stats!(heap_memory_stats, HeapType::GlDev);

            let (
                unknown_dev_pss_kib,
                unknown_dev_rss_kib,
                unknown_dev_swap_kib,
                unknown_dev_swap_pss_kib,
            ) = extract_heap_stats!(heap_memory_stats, HeapType::UnknownDev);

            let (so_pss_kib, so_rss_kib, so_swap_kib, so_swap_pss_kib) =
                extract_heap_stats!(heap_memory_stats, HeapType::So);

            let (jar_pss_kib, jar_rss_kib, jar_swap_kib, jar_swap_pss_kib) =
                extract_heap_stats!(heap_memory_stats, HeapType::Jar);

            let (apk_pss_kib, apk_rss_kib, apk_swap_kib, apk_swap_pss_kib) =
                extract_heap_stats!(heap_memory_stats, HeapType::Apk);
            let (ttf_pss_kib, ttf_rss_kib, ttf_swap_kib, ttf_swap_pss_kib) =
                extract_heap_stats!(heap_memory_stats, HeapType::Ttf);

            let (dex_pss_kib, dex_rss_kib, dex_swap_kib, dex_swap_pss_kib) =
                extract_heap_stats!(heap_memory_stats, HeapType::Dex);

            let (oat_pss_kib, oat_rss_kib, oat_swap_kib, oat_swap_pss_kib) =
                extract_heap_stats!(heap_memory_stats, HeapType::Oat);

            let (art_pss_kib, art_rss_kib, art_swap_kib, art_swap_pss_kib) =
                extract_heap_stats!(heap_memory_stats, HeapType::Art);

            let (
                unknown_map_pss_kib,
                unknown_map_rss_kib,
                unknown_map_swap_kib,
                unknown_map_swap_pss_kib,
            ) = extract_heap_stats!(heap_memory_stats, HeapType::UnknownMap);
            let (
                dalvik_normal_pss_kib,
                dalvik_normal_rss_kib,
                dalvik_normal_swap_kib,
                dalvik_normal_swap_pss_kib,
            ) = extract_heap_stats!(heap_memory_stats, HeapType::DalvikNormal);

            let (
                dalvik_large_pss_kib,
                dalvik_large_rss_kib,
                dalvik_large_swap_kib,
                dalvik_large_swap_pss_kib,
            ) = extract_heap_stats!(heap_memory_stats, HeapType::DalvikLarge);

            let (
                dalvik_zygote_pss_kib,
                dalvik_zygote_rss_kib,
                dalvik_zygote_swap_kib,
                dalvik_zygote_swap_pss_kib,
            ) = extract_heap_stats!(heap_memory_stats, HeapType::DalvikZygote);

            let (
                dalvik_non_moving_pss_kib,
                dalvik_non_moving_rss_kib,
                dalvik_non_moving_swap_kib,
                dalvik_non_moving_swap_pss_kib,
            ) = extract_heap_stats!(heap_memory_stats, HeapType::DalvikNonMoving);

            let (
                dalvik_other_linearalloc_pss_kib,
                dalvik_other_linearalloc_rss_kib,
                dalvik_other_linearalloc_swap_kib,
                dalvik_other_linearalloc_swap_pss_kib,
            ) = extract_heap_stats!(heap_memory_stats, HeapType::DalvikOtherLinearalloc);

            let (
                dalvik_other_accounting_pss_kib,
                dalvik_other_accounting_rss_kib,
                dalvik_other_accounting_swap_kib,
                dalvik_other_accounting_swap_pss_kib,
            ) = extract_heap_stats!(heap_memory_stats, HeapType::DalvikOtherAccounting);

            let (
                dalvik_other_zygote_code_cache_pss_kib,
                dalvik_other_zygote_code_cache_rss_kib,
                dalvik_other_zygote_code_cache_swap_kib,
                dalvik_other_zygote_code_cache_swap_pss_kib,
            ) = extract_heap_stats!(heap_memory_stats, HeapType::DalvikOtherZygoteCodeCache);

            let (
                dalvik_other_app_code_cache_pss_kib,
                dalvik_other_app_code_cache_rss_kib,
                dalvik_other_app_code_cache_swap_kib,
                dalvik_other_app_code_cache_swap_pss_kib,
            ) = extract_heap_stats!(heap_memory_stats, HeapType::DalvikOtherAppCodeCache);

            let (
                dalvik_other_compiler_metadata_pss_kib,
                _dalvik_other_compiler_metadata_rss_kib,
                _dalvik_other_compiler_metadata_swap_kib,
                dalvik_other_compiler_metadata_swap_pss_kib,
            ) = extract_heap_stats!(heap_memory_stats, HeapType::DalvikOtherCompilerMetadata);

            let (
                dalvik_other_indirect_reference_table_pss_kib,
                dalvik_other_indirect_reference_table_rss_kib,
                dalvik_other_indirect_reference_table_swap_kib,
                dalvik_other_indirect_reference_table_swap_pss_kib,
            ) = extract_heap_stats!(
                heap_memory_stats,
                HeapType::DalvikOtherIndirectReferenceTable
            );

            let (
                dex_boot_vdex_pss_kib,
                dex_boot_vdex_rss_kib,
                dex_boot_vdex_swap_kib,
                dex_boot_vdex_swap_pss_kib,
            ) = extract_heap_stats!(heap_memory_stats, HeapType::DexBootVdex);

            let (
                dex_app_dex_pss_kib,
                dex_app_dex_rss_kib,
                dex_app_dex_swap_kib,
                dex_app_dex_swap_pss_kib,
            ) = extract_heap_stats!(heap_memory_stats, HeapType::DexAppDex);

            let (
                dex_app_vdex_pss_kib,
                dex_app_vdex_rss_kib,
                dex_app_vdex_swap_kib,
                dex_app_vdex_swap_pss_kib,
            ) = extract_heap_stats!(heap_memory_stats, HeapType::DexAppVdex);

            let (art_app_pss_kib, art_app_rss_kib, art_app_swap_kib, art_app_swap_pss_kib) =
                extract_heap_stats!(heap_memory_stats, HeapType::ArtApp);

            let (art_boot_pss_kib, art_boot_rss_kib, art_boot_swap_kib, art_boot_swap_pss_kib) =
                extract_heap_stats!(heap_memory_stats, HeapType::ArtBoot);

            if log_enabled!(Level::Trace) {
                trace!(
                    "{}", format!("Process ({process_pid}, {process_exe}, pss_including_swap_kib: {pss_including_swap_kib}): \
                    Heap memory - memtrack_graphics_pss: [{memtrack_graphics_pss_kib}], \
                    memtrack_gl_pss: [{memtrack_gl_pss_kib}], memtrack_other_pss: [{memtrack_other_pss_kib}], \
                    unknown: [{unknown_pss_kib}/{unknown_rss_kib}/{unknown_swap_kib}/{unknown_swap_pss_kib}], \
                    dalvik: [{dalvik_pss_kib}/{dalvik_rss_kib}/{dalvik_swap_kib}/{dalvik_swap_pss_kib}], \
                    dalvik_other: [{dalvik_other_pss_kib}/{dalvik_other_rss_kib}/{dalvik_other_swap_kib}/{dalvik_other_swap_pss_kib}], \
                    stack: [{stack_pss_kib}/{stack_rss_kib}/{stack_swap_kib}/{stack_swap_pss_kib}], \
                    cursor: [{cursor_pss_kib}/{cursor_swap_pss_kib}], \
                    ashmem: [{ashmem_pss_kib}/{ashmem_rss_kib}/{ashmem_swap_kib}/{ashmem_swap_pss_kib}], \
                    gl_dev: [{gl_dev_pss_kib}/{gl_dev_rss_kib}/{gl_dev_swap_kib}/{gl_dev_swap_pss_kib}], \
                    unknown_dev: [{unknown_dev_pss_kib}/{unknown_dev_rss_kib}/{unknown_dev_swap_kib}/{unknown_dev_swap_pss_kib}], \
                    so: [{so_pss_kib}/{so_rss_kib}/{so_swap_kib}/{so_swap_pss_kib}], \
                    jar: [{jar_pss_kib}/{jar_rss_kib}/{jar_swap_kib}/{jar_swap_pss_kib}], \
                    apk: [{apk_pss_kib}/{apk_rss_kib}/{apk_swap_kib}/{apk_swap_pss_kib}], \
                    ttf: [{ttf_pss_kib}/{ttf_rss_kib}/{ttf_swap_kib}/{ttf_swap_pss_kib}], \
                    dex: [{dex_pss_kib}/{dex_rss_kib}/{dex_swap_kib}/{dex_swap_pss_kib}], \
                    oat: [{oat_pss_kib}/{oat_rss_kib}/{oat_swap_kib}/{oat_swap_pss_kib}], \
                    art: [{art_pss_kib}/{art_rss_kib}/{art_swap_kib}/{art_swap_pss_kib}], \
                    unknown_map: [{unknown_map_pss_kib}/{unknown_map_rss_kib}/{unknown_map_swap_kib}/{unknown_map_swap_pss_kib}], \
                    dalvik_normal: [{dalvik_normal_pss_kib}/{dalvik_normal_rss_kib}/{dalvik_normal_swap_kib}/{dalvik_normal_swap_pss_kib}], \
                    dalvik_large: [{dalvik_large_pss_kib}/{dalvik_large_rss_kib}/{dalvik_large_swap_kib}/{dalvik_large_swap_pss_kib}], \
                    dalvik_zygote: [{dalvik_zygote_pss_kib}/{dalvik_zygote_rss_kib}/{dalvik_zygote_swap_kib}/{dalvik_zygote_swap_pss_kib}], \
                    dalvik_non_moving: [{dalvik_non_moving_pss_kib}/{dalvik_non_moving_rss_kib}/{dalvik_non_moving_swap_kib}/{dalvik_non_moving_swap_pss_kib}], \
                    dalvik_other_linearalloc: [{dalvik_other_linearalloc_pss_kib}/{dalvik_other_linearalloc_rss_kib}/{dalvik_other_linearalloc_swap_kib}/{dalvik_other_linearalloc_swap_pss_kib}], \
                    dalvik_other_accounting: [{dalvik_other_accounting_pss_kib}/{dalvik_other_accounting_rss_kib}/{dalvik_other_accounting_swap_kib}/{dalvik_other_accounting_swap_pss_kib}], \
                    dalvik_other_zygote_code_cache: [{dalvik_other_zygote_code_cache_pss_kib}/{dalvik_other_zygote_code_cache_rss_kib}/{dalvik_other_zygote_code_cache_swap_kib}/{dalvik_other_zygote_code_cache_swap_pss_kib}], \
                    dalvik_other_app_code_cache: [{dalvik_other_app_code_cache_pss_kib}/{dalvik_other_app_code_cache_rss_kib}/{dalvik_other_app_code_cache_swap_kib}/{dalvik_other_app_code_cache_swap_pss_kib}], \
                    dalvik_other_compiler_metadata: [{dalvik_other_compiler_metadata_pss_kib}/{dalvik_other_compiler_metadata_swap_pss_kib}], \
                    dalvik_other_indirect_reference_table: [{dalvik_other_indirect_reference_table_pss_kib}/{dalvik_other_indirect_reference_table_rss_kib}/{dalvik_other_indirect_reference_table_swap_kib}/{dalvik_other_indirect_reference_table_swap_pss_kib}], \
                    dex_boot_vdex: [{dex_boot_vdex_pss_kib}/{dex_boot_vdex_rss_kib}/{dex_boot_vdex_swap_kib}/{dex_boot_vdex_swap_pss_kib}], \
                    dex_app_dex: [{dex_app_dex_pss_kib}/{dex_app_dex_rss_kib}/{dex_app_dex_swap_kib}/{dex_app_dex_swap_pss_kib}], \
                    dex_app_vdex: [{dex_app_vdex_pss_kib}/{dex_app_vdex_rss_kib}/{dex_app_vdex_swap_kib}/{dex_app_vdex_swap_pss_kib}], \
                    art_app: [{art_app_pss_kib}/{art_app_rss_kib}/{art_app_swap_kib}/{art_app_swap_pss_kib}], \
                    art_boot: [{art_boot_pss_kib}/{art_boot_rss_kib}/{art_boot_swap_kib}/{art_boot_swap_pss_kib}]",
                ));
            }

            let process_heap_type_info = process_heap_type_info::ProcessHeapTypeInfo {
                process_name: &process_info.exe,
                pss_including_swap_kib,
                memtrack_graphics_kib: memtrack_graphics_pss_kib,
                memtrack_gl_kib: memtrack_gl_pss_kib,
                other_memtrack_kib: memtrack_other_pss_kib,

                // Unknown heap type with subfields
                unknown_pss_kib,
                unknown_rss_kib,
                unknown_swap_kib,
                unknown_swap_pss_kib,

                // Dalvik heap type with subfields
                dalvik_pss_kib,
                dalvik_rss_kib,
                dalvik_swap_kib,
                dalvik_swap_pss_kib,

                // Dalvik Other heap type with subfields
                dalvik_other_pss_kib,
                dalvik_other_rss_kib,
                dalvik_other_swap_kib,
                dalvik_other_swap_pss_kib,

                // Stack heap type with subfields
                stack_pss_kib,
                stack_rss_kib,
                stack_swap_kib,
                stack_swap_pss_kib,

                // Cursor heap type with subfields
                cursor_pss_kib,
                cursor_swap_pss_kib,

                // Ashmem heap type with subfields
                ashmem_pss_kib,
                ashmem_rss_kib,
                ashmem_swap_kib,
                ashmem_swap_pss_kib,

                // GL Dev heap type with subfields
                gl_dev_pss_kib,
                gl_dev_rss_kib,
                gl_dev_swap_kib,
                gl_dev_swap_pss_kib,

                // Unknown Dev heap type with subfields
                unknown_dev_pss_kib,
                unknown_dev_rss_kib,
                unknown_dev_swap_kib,
                unknown_dev_swap_pss_kib,

                // SO heap type with subfields
                so_pss_kib,
                so_rss_kib,
                so_swap_kib,
                so_swap_pss_kib,

                // JAR heap type with subfields
                jar_pss_kib,
                jar_rss_kib,
                jar_swap_kib,
                jar_swap_pss_kib,

                // APK heap type with subfields
                apk_pss_kib,
                apk_rss_kib,
                apk_swap_kib,
                apk_swap_pss_kib,

                // TTF heap type with subfields
                ttf_pss_kib,
                ttf_rss_kib,
                ttf_swap_kib,
                ttf_swap_pss_kib,

                // DEX heap type with subfields
                dex_pss_kib,
                dex_rss_kib,
                dex_swap_kib,
                dex_swap_pss_kib,

                // OAT heap type with subfields
                oat_pss_kib,
                oat_rss_kib,
                oat_swap_kib,
                oat_swap_pss_kib,

                // ART heap type with subfields
                art_pss_kib,
                art_rss_kib,
                art_swap_kib,
                art_swap_pss_kib,

                // Unknown Map heap type with subfields
                unknown_map_pss_kib,
                unknown_map_rss_kib,
                unknown_map_swap_kib,
                unknown_map_swap_pss_kib,

                // Dalvik Normal heap type with subfields
                dalvik_normal_pss_kib,
                dalvik_normal_rss_kib,
                dalvik_normal_swap_kib,
                dalvik_normal_swap_pss_kib,

                // Dalvik Large heap type with subfields
                dalvik_large_pss_kib,
                dalvik_large_rss_kib,
                dalvik_large_swap_kib,
                dalvik_large_swap_pss_kib,

                // Dalvik Zygote heap type with subfields
                dalvik_zygote_pss_kib,
                dalvik_zygote_rss_kib,
                dalvik_zygote_swap_kib,
                dalvik_zygote_swap_pss_kib,

                // Dalvik Non Moving heap type with subfields
                dalvik_non_moving_pss_kib,
                dalvik_non_moving_rss_kib,
                dalvik_non_moving_swap_kib,
                dalvik_non_moving_swap_pss_kib,

                // Dalvik Other Linear Alloc heap type with subfields
                dalvik_other_linearalloc_pss_kib,
                dalvik_other_linearalloc_rss_kib,
                dalvik_other_linearalloc_swap_kib,
                dalvik_other_linearalloc_swap_pss_kib,

                // Dalvik Other Accounting heap type with subfields
                dalvik_other_accounting_pss_kib,
                dalvik_other_accounting_rss_kib,
                dalvik_other_accounting_swap_kib,
                dalvik_other_accounting_swap_pss_kib,

                // Dalvik Other Zygote Code Cache heap type with subfields
                dalvik_other_zygote_code_cache_pss_kib,
                dalvik_other_zygote_code_cache_rss_kib,
                dalvik_other_zygote_code_cache_swap_kib,
                dalvik_other_zygote_code_cache_swap_pss_kib,

                // Dalvik Other App Code Cache heap type with subfields
                dalvik_other_app_code_cache_pss_kib,
                dalvik_other_app_code_cache_rss_kib,
                dalvik_other_app_code_cache_swap_kib,
                dalvik_other_app_code_cache_swap_pss_kib,

                // Dalvik Other Compiler Metadata heap type with subfields
                dalvik_other_compiler_metadata_pss_kib,
                dalvik_other_compiler_metadata_swap_pss_kib,

                // Dalvik Other Indirect Reference Table heap type with subfields
                dalvik_other_indirect_reference_table_pss_kib,
                dalvik_other_indirect_reference_table_rss_kib,
                dalvik_other_indirect_reference_table_swap_kib,
                dalvik_other_indirect_reference_table_swap_pss_kib,

                // DEX Boot VDEX heap type with subfields
                dex_boot_vdex_pss_kib,
                dex_boot_vdex_rss_kib,
                dex_boot_vdex_swap_kib,
                dex_boot_vdex_swap_pss_kib,

                // DEX App DEX heap type with subfields
                dex_app_dex_pss_kib,
                dex_app_dex_rss_kib,
                dex_app_dex_swap_kib,
                dex_app_dex_swap_pss_kib,

                // DEX App VDEX heap type with subfields
                dex_app_vdex_pss_kib,
                dex_app_vdex_rss_kib,
                dex_app_vdex_swap_kib,
                dex_app_vdex_swap_pss_kib,

                // ART App heap type with subfields
                art_app_pss_kib,
                art_app_rss_kib,
                art_app_swap_kib,
                art_app_swap_pss_kib,

                // ART Boot heap type with subfields
                art_boot_pss_kib,
                art_boot_rss_kib,
                art_boot_swap_kib,
                art_boot_swap_pss_kib,
            };

            let result = process_heap_type_info.stats_write();

            match result {
                Ok(()) => trace!("Memflow stats logged successfully"),
                Err(e) => error!("Failed to log memflow stats: {:?}", e),
            }
        }
        Ok(())
    }

    async fn cleanup(&mut self) {
        // No-op: No cleanup needed as heap telemetry policy doesn't modify cgroup nodes
    }
}
