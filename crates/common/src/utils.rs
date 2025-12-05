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

use anyhow::Context as _;
use hzos_memory::memtrack::MemTrackSessionAsync;
use log::trace;
use statslog_meta_memflow::process_memory_info;

use crate::cgroup::CgroupEntry;
use crate::process_monitor::ProcessInfo;

pub const KIB_TO_BYTES: u32 = 1024;
pub const MIB_TO_BYTES: u32 = KIB_TO_BYTES * KIB_TO_BYTES;
pub const PAGE_SIZE: u32 = 4096;

pub async fn build_memory_stats<'a, C: CgroupEntry>(
    cgroup: &C,
    process_info: &'a ProcessInfo,
    wss: i64,
) -> anyhow::Result<process_memory_info::ProcessMemoryInfo<'a>> {
    let cpu_pressure = cgroup.cpu_pressure().await?;
    let io_pressure = cgroup.io_pressure().await?;
    let memory_pressure = cgroup.memory_pressure().await?;
    let memory_stats = cgroup.memory_stats().await?;
    let memory_events = cgroup.memory_events().await?;
    let memory_swap_current = cgroup.memory_swap_current().await?;
    let memory_current = cgroup.memory_current().await?;

    let mut memtrack = MemTrackSessionAsync::connect()
        .await
        .context("Failed to retrieve memtrack")?;
    let record = memtrack.process_record(process_info.pid as i32).await?;

    let memtrack_graphics_pss_kib: i64 = (record.graphics_pss_bytes() / KIB_TO_BYTES as usize)
        .try_into()
        .context("Conversion error for graphics_pss_kib")?;

    let memtrack_gl_pss_kib: i64 = (record.gl_pss_bytes() / KIB_TO_BYTES as usize)
        .try_into()
        .context("Conversion error for gl_pss_kib")?;

    let memtrack_other_pss_kib: i64 = (record.other_pss_bytes() / KIB_TO_BYTES as usize)
        .try_into()
        .context("Conversion error for other_pss_kib")?;

    let memtrack_total_pss_kib: i64 = (record.total_pss_bytes() / KIB_TO_BYTES as usize)
        .try_into()
        .context("Conversion error for total_pss_kib")?;

    let memory_swap_current_kib: i64 = (memory_swap_current / KIB_TO_BYTES as u64)
        .try_into()
        .context("Conversion error for memory_swap_current_kib")?;

    let memory_current_kib: i64 = (memory_current / KIB_TO_BYTES as u64)
        .try_into()
        .context("Conversion error for memory_current_kib")?;

    trace!(
        "Process ({}, {}, oom_score_adj {}, cpu {}, wss: {}): CPU pressure: {:?} | IO pressure: {:?} | Memory pressure: {:?} | Memory stats: {:?} | Memtrack - graphics_pss_kib: {}, gl_pss_kib: {}, other_pss_kib: {}, total_pss_kib: {} | Memory events: {:?} | Memory swap current KiB: {:?} | Memory current KiB: {:?}",
        process_info.pid,
        &process_info.exe,
        process_info.oom_score_adj,
        process_info.cpu,
        wss,
        cpu_pressure,
        io_pressure,
        memory_pressure,
        memory_stats,
        memtrack_graphics_pss_kib,
        memtrack_gl_pss_kib,
        memtrack_other_pss_kib,
        memtrack_total_pss_kib,
        memory_events,
        memory_swap_current_kib,
        memory_current_kib,
    );

    Ok(process_memory_info::ProcessMemoryInfo {
        process_name: &process_info.exe,
        wss,
        cpu_pressure_some_avg10: cpu_pressure.some.avg10,
        cpu_pressure_some_avg60: cpu_pressure.some.avg60,
        cpu_pressure_some_avg300: cpu_pressure.some.avg300,
        cpu_pressure_some_total: cpu_pressure.some.total as i64,
        io_pressure_some_avg10: io_pressure.some.avg10,
        io_pressure_some_avg60: io_pressure.some.avg60,
        io_pressure_some_avg300: io_pressure.some.avg300,
        io_pressure_some_total: io_pressure.some.total as i64,
        io_pressure_full_avg10: io_pressure.full.avg10,
        io_pressure_full_avg60: io_pressure.full.avg60,
        io_pressure_full_avg300: io_pressure.full.avg300,
        io_pressure_full_total: io_pressure.full.total as i64,
        memory_pressure_some_avg10: memory_pressure.some.avg10,
        memory_pressure_some_avg60: memory_pressure.some.avg60,
        memory_pressure_some_avg300: memory_pressure.some.avg300,
        memory_pressure_some_total: memory_pressure.some.total as i64,
        memory_pressure_full_avg10: memory_pressure.full.avg10,
        memory_pressure_full_avg60: memory_pressure.full.avg60,
        memory_pressure_full_avg300: memory_pressure.full.avg300,
        memory_pressure_full_total: memory_pressure.full.total as i64,
        anon: memory_stats.anon,
        file: memory_stats.file,
        kernel_stack: memory_stats.kernel_stack,
        slab: memory_stats.slab,
        sock: memory_stats.sock,
        shmem: memory_stats.shmem,
        file_mapped: memory_stats.file_mapped,
        file_dirty: memory_stats.file_dirty,
        file_writeback: memory_stats.file_writeback,
        inactive_anon: memory_stats.inactive_anon,
        active_anon: memory_stats.active_anon,
        inactive_file: memory_stats.inactive_file,
        active_file: memory_stats.active_file,
        unevictable: memory_stats.unevictable,
        slab_reclaimable: memory_stats.slab_reclaimable,
        slab_unreclaimable: memory_stats.slab_unreclaimable,
        pgfault: memory_stats.pgfault,
        pgmajfault: memory_stats.pgmajfault,
        workingset_refault_anon: memory_stats.workingset_refault_anon,
        workingset_refault_file: memory_stats.workingset_refault_file,
        workingset_activate_anon: memory_stats.workingset_activate_anon,
        workingset_activate_file: memory_stats.workingset_activate_file,
        workingset_restore_anon: memory_stats.workingset_restore_anon,
        workingset_restore_file: memory_stats.workingset_restore_file,
        workingset_nodereclaim: memory_stats.workingset_nodereclaim,
        pgrefill: memory_stats.pgrefill,
        pgscan: memory_stats.pgscan,
        pgsteal: memory_stats.pgsteal,
        pgactivate: memory_stats.pgactivate,
        pgdeactivate: memory_stats.pgdeactivate,
        pglazyfree: memory_stats.pglazyfree,
        pglazyfreed: memory_stats.pglazyfreed,
        memtrack_graphics_pss_kib,
        memtrack_gl_pss_kib,
        memtrack_other_pss_kib,
        memtrack_total_pss_kib,
        memory_events_low: memory_events.low,
        memory_events_high: memory_events.high,
        memory_events_max: memory_events.max,
        memory_events_oom: memory_events.oom,
        memory_events_oom_kill: memory_events.oom_kill,
        memory_swap_current_kib,
        memory_current_kib,
    })
}
