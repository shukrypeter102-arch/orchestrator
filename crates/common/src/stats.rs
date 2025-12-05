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

// See https://docs.kernel.org/accounting/psi.html.
use std::ffi::CStr;
use std::io::Cursor;
use std::path::Path;
use std::time::Duration;

use log::debug;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::io::Ready;

#[derive(Debug, Clone, Copy)]
pub enum StallType {
    Some,
    Full,
}

impl std::fmt::Display for StallType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Some => "some",
            Self::Full => "full",
        };
        write!(f, "{s}")
    }
}

impl std::str::FromStr for StallType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "some" => Ok(Self::Some),
            "full" => Ok(Self::Full),
            _s => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Trigger {
    pub what: StallType,
    pub threshold: Duration,
    pub window: Duration,
}

impl std::fmt::Display for Trigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            what,
            threshold,
            window,
        } = self;
        let threshold_us = threshold.as_micros();
        let window_us = window.as_micros();
        write!(f, "{what} {threshold_us} {window_us}")
    }
}

fn set_once<T>(dest: &mut Option<T>, t: T) -> Result<(), ()> {
    if dest.replace(t).is_some() {
        Err(())
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Stats {
    pub avg10: f32,
    pub avg60: f32,
    pub avg300: f32,
    pub total: u64,
}

impl std::str::FromStr for Stats {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut avg10 = None;
        let mut avg60 = None;
        let mut avg300 = None;
        let mut total = None;

        for part in s.split_whitespace() {
            let (key, value) = part.split_once('=').ok_or(())?;
            fn parse_float(dest: &mut Option<f32>, s: &str) -> Result<(), ()> {
                let f = s.parse().map_err(|std::num::ParseFloatError { .. }| ())?;
                set_once(dest, f)
            }
            match key {
                "avg10" => parse_float(&mut avg10, value)?,
                "avg60" => parse_float(&mut avg60, value)?,
                "avg300" => parse_float(&mut avg300, value)?,
                "total" => {
                    let i = value.parse().map_err(|std::num::ParseIntError { .. }| ())?;
                    set_once(&mut total, i)?;
                }
                _key => return Err(()),
            }
        }
        Ok(Self {
            avg10: avg10.ok_or(())?,
            avg60: avg60.ok_or(())?,
            avg300: avg300.ok_or(())?,
            total: total.ok_or(())?,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Readout {
    pub some: Stats,
    pub full: Stats,
}

impl std::str::FromStr for Readout {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut some = None;
        let mut full = None;

        for line in s.lines() {
            let (what, parts) = line.split_once(char::is_whitespace).ok_or(())?;
            let dest = match what {
                "some" => &mut some,
                "full" => &mut full,
                _key => return Err(()),
            };
            set_once(dest, parts.parse()?)?;
        }
        Ok(Self {
            some: some.ok_or(())?,
            full: full.ok_or(())?,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PartialReadout {
    pub some: Stats,
}

impl std::str::FromStr for PartialReadout {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut some = None;

        for line in s.lines() {
            let (what, parts) = line.split_once(char::is_whitespace).ok_or(())?;
            let dest = match what {
                "some" => &mut some,
                "full" => continue,
                _key => return Err(()),
            };
            set_once(dest, parts.parse()?)?;
        }
        Ok(Self {
            some: some.ok_or(())?,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MemoryStats {
    pub anon: i64,
    pub file: i64,
    pub kernel_stack: i64,
    pub percpu: i64,
    pub sock: i64,
    pub shmem: i64,
    pub file_mapped: i64,
    pub file_dirty: i64,
    pub file_writeback: i64,
    pub inactive_anon: i64,
    pub active_anon: i64,
    pub inactive_file: i64,
    pub active_file: i64,
    pub unevictable: i64,
    pub slab_reclaimable: i64,
    pub slab_unreclaimable: i64,
    pub slab: i64,
    pub workingset_refault_anon: i64,
    pub workingset_refault_file: i64,
    pub workingset_activate_anon: i64,
    pub workingset_activate_file: i64,
    pub workingset_restore_anon: i64,
    pub workingset_restore_file: i64,
    pub workingset_nodereclaim: i64,
    pub pgfault: i64,
    pub pgmajfault: i64,
    pub pgrefill: i64,
    pub pgscan: i64,
    pub pgsteal: i64,
    pub pgactivate: i64,
    pub pgdeactivate: i64,
    pub pglazyfree: i64,
    pub pglazyfreed: i64,
}

impl std::str::FromStr for MemoryStats {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut anon = None;
        let mut file = None;
        let mut kernel_stack = None;
        let mut percpu = None;
        let mut sock = None;
        let mut shmem = None;
        let mut file_mapped = None;
        let mut file_dirty = None;
        let mut file_writeback = None;
        let mut inactive_anon = None;
        let mut active_anon = None;
        let mut inactive_file = None;
        let mut active_file = None;
        let mut unevictable = None;
        let mut slab_reclaimable = None;
        let mut slab_unreclaimable = None;
        let mut slab = None;
        let mut workingset_refault_anon = None;
        let mut workingset_refault_file = None;
        let mut workingset_activate_anon = None;
        let mut workingset_activate_file = None;
        let mut workingset_restore_anon = None;
        let mut workingset_restore_file = None;
        let mut workingset_nodereclaim = None;
        let mut pgfault = None;
        let mut pgmajfault = None;
        let mut pgrefill = None;
        let mut pgscan = None;
        let mut pgsteal = None;
        let mut pgactivate = None;
        let mut pgdeactivate = None;
        let mut pglazyfree = None;
        let mut pglazyfreed = None;

        for line in s.lines() {
            let (key, value) = line.split_once(char::is_whitespace).ok_or(())?;
            fn parse_int(dest: &mut Option<i64>, s: &str) -> Result<(), ()> {
                let i = s.parse().map_err(|std::num::ParseIntError { .. }| ())?;
                set_once(dest, i)
            }
            match key {
                "anon" => parse_int(&mut anon, value)?,
                "file" => parse_int(&mut file, value)?,
                "kernel_stack" => parse_int(&mut kernel_stack, value)?,
                "percpu" => parse_int(&mut percpu, value)?,
                "sock" => parse_int(&mut sock, value)?,
                "shmem" => parse_int(&mut shmem, value)?,
                "file_mapped" => parse_int(&mut file_mapped, value)?,
                "file_dirty" => parse_int(&mut file_dirty, value)?,
                "file_writeback" => parse_int(&mut file_writeback, value)?,
                "inactive_anon" => parse_int(&mut inactive_anon, value)?,
                "active_anon" => parse_int(&mut active_anon, value)?,
                "inactive_file" => parse_int(&mut inactive_file, value)?,
                "active_file" => parse_int(&mut active_file, value)?,
                "unevictable" => parse_int(&mut unevictable, value)?,
                "slab_reclaimable" => parse_int(&mut slab_reclaimable, value)?,
                "slab_unreclaimable" => parse_int(&mut slab_unreclaimable, value)?,
                "slab" => parse_int(&mut slab, value)?,
                "workingset_refault_anon" => parse_int(&mut workingset_refault_anon, value)?,
                "workingset_refault_file" => parse_int(&mut workingset_refault_file, value)?,
                "workingset_activate_anon" => parse_int(&mut workingset_activate_anon, value)?,
                "workingset_activate_file" => parse_int(&mut workingset_activate_file, value)?,
                "workingset_restore_anon" => parse_int(&mut workingset_restore_anon, value)?,
                "workingset_restore_file" => parse_int(&mut workingset_restore_file, value)?,
                "workingset_nodereclaim" => parse_int(&mut workingset_nodereclaim, value)?,
                "pgfault" => parse_int(&mut pgfault, value)?,
                "pgmajfault" => parse_int(&mut pgmajfault, value)?,
                "pgrefill" => parse_int(&mut pgrefill, value)?,
                "pgscan" => parse_int(&mut pgscan, value)?,
                "pgsteal" => parse_int(&mut pgsteal, value)?,
                "pgactivate" => parse_int(&mut pgactivate, value)?,
                "pgdeactivate" => parse_int(&mut pgdeactivate, value)?,
                "pglazyfree" => parse_int(&mut pglazyfree, value)?,
                "pglazyfreed" => parse_int(&mut pglazyfreed, value)?,
                _key => {} // Ignore unrecognized keys
            }
        }
        Ok(Self {
            anon: anon.unwrap_or(-1),
            file: file.unwrap_or(-1),
            kernel_stack: kernel_stack.unwrap_or(-1),
            percpu: percpu.unwrap_or(-1),
            sock: sock.unwrap_or(-1),
            shmem: shmem.unwrap_or(-1),
            file_mapped: file_mapped.unwrap_or(-1),
            file_dirty: file_dirty.unwrap_or(-1),
            file_writeback: file_writeback.unwrap_or(-1),
            inactive_anon: inactive_anon.unwrap_or(-1),
            active_anon: active_anon.unwrap_or(-1),
            inactive_file: inactive_file.unwrap_or(-1),
            active_file: active_file.unwrap_or(-1),
            unevictable: unevictable.unwrap_or(-1),
            slab_reclaimable: slab_reclaimable.unwrap_or(-1),
            slab_unreclaimable: slab_unreclaimable.unwrap_or(-1),
            slab: slab.unwrap_or(-1),
            workingset_refault_anon: workingset_refault_anon.unwrap_or(-1),
            workingset_refault_file: workingset_refault_file.unwrap_or(-1),
            workingset_activate_anon: workingset_activate_anon.unwrap_or(-1),
            workingset_activate_file: workingset_activate_file.unwrap_or(-1),
            workingset_restore_anon: workingset_restore_anon.unwrap_or(-1),
            workingset_restore_file: workingset_restore_file.unwrap_or(-1),
            workingset_nodereclaim: workingset_nodereclaim.unwrap_or(-1),
            pgfault: pgfault.unwrap_or(-1),
            pgmajfault: pgmajfault.unwrap_or(-1),
            pgrefill: pgrefill.unwrap_or(-1),
            pgscan: pgscan.unwrap_or(-1),
            pgsteal: pgsteal.unwrap_or(-1),
            pgactivate: pgactivate.unwrap_or(-1),
            pgdeactivate: pgdeactivate.unwrap_or(-1),
            pglazyfree: pglazyfree.unwrap_or(-1),
            pglazyfreed: pglazyfreed.unwrap_or(-1),
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MemoryEvents {
    pub low: i64,
    pub high: i64,
    pub max: i64,
    pub oom: i64,
    pub oom_kill: i64,
}

impl std::str::FromStr for MemoryEvents {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut low = None;
        let mut high = None;
        let mut max = None;
        let mut oom = None;
        let mut oom_kill = None;

        for line in s.lines() {
            let (key, value) = line.split_once(char::is_whitespace).ok_or(())?;
            fn parse_int(dest: &mut Option<i64>, s: &str) -> Result<(), ()> {
                let i = s.parse().map_err(|std::num::ParseIntError { .. }| ())?;
                set_once(dest, i)
            }
            match key {
                "low" => parse_int(&mut low, value)?,
                "high" => parse_int(&mut high, value)?,
                "max" => parse_int(&mut max, value)?,
                "oom" => parse_int(&mut oom, value)?,
                "oom_kill" => parse_int(&mut oom_kill, value)?,
                _key => {} // Ignore unrecognized keys
            }
        }
        Ok(Self {
            low: low.unwrap_or(-1),
            high: high.unwrap_or(-1),
            max: max.unwrap_or(-1),
            oom: oom.unwrap_or(-1),
            oom_kill: oom_kill.unwrap_or(-1),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ProcessCgroupInfo {
    pub cpuset: String,
    pub cpuacct: String,
    pub cpu: String,
    pub blkio: String,
}

impl std::str::FromStr for ProcessCgroupInfo {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut cpuset = None;
        let mut cpuacct = None;
        let mut cpu = None;
        let mut blkio = None;

        for line in s.lines() {
            if line.trim().is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.splitn(3, ':').collect();
            if parts.len() != 3 {
                continue; // Skip malformed lines
            }

            let controllers_str = parts.get(1).ok_or(())?;
            let value = parts
                .get(2)
                .ok_or(())?
                .strip_prefix('/')
                .unwrap_or(parts.get(2).ok_or(())?);

            // Skip lines with empty controllers
            if controllers_str.is_empty() {
                continue;
            }

            // Parse controllers (comma-separated)
            let controllers: Vec<&str> = controllers_str.split(',').map(|s| s.trim()).collect();

            // Check for our target controllers and set the value
            for controller in controllers {
                match controller {
                    "cpuset" => {
                        set_once(&mut cpuset, value.to_string())?;
                    }
                    "cpuacct" => {
                        set_once(&mut cpuacct, value.to_string())?;
                    }
                    "cpu" => {
                        set_once(&mut cpu, value.to_string())?;
                    }
                    "blkio" => {
                        set_once(&mut blkio, value.to_string())?;
                    }
                    _ => {} // Ignore other controllers
                }
            }
        }

        Ok(Self {
            cpuset: cpuset.unwrap_or("".to_string()),
            cpuacct: cpuacct.unwrap_or("".to_string()),
            cpu: cpu.unwrap_or("".to_string()),
            blkio: blkio.unwrap_or("".to_string()),
        })
    }
}

pub struct Pressure {
    file: std::fs::File,
}

impl Pressure {
    pub fn new(path: &Path) -> std::io::Result<(Self, Readout)> {
        use std::io::Read as _;
        use std::str;

        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        let mut buf = [0u8; 512];
        let n = file.read(&mut buf)?;
        let s = str::from_utf8(buf.get(..n).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to read buffer slice"),
            )
        })?)
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to parse output: {buf:?}"),
            )
        })?;
        let readout = s.parse().map_err(|()| {
            // TODO(sboss): Use std::io::Error::other() once we are back to a recent rustc
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to parse output: {s}"),
            )
        })?;
        Ok((Self { file }, readout))
    }
    pub fn watch(
        self,
        trigger: Trigger,
    ) -> std::io::Result<impl futures::Stream<Item = std::io::Result<()>>> {
        let Self { mut file } = self;

        // Must be a single write system call, and must have a null byte at the end!
        {
            use std::io::Write as _;

            let mut cursor = Cursor::new([0u8; 128]);
            write!(cursor, "{trigger}")?;
            let buf = cursor.into_inner();
            // Find the first null byte or use the buffer length
            let null_pos = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            // TODO(sboss): Use from_bytes_until_nul once we are back to a recent rustc
            let cstr = buf
                .get(..null_pos + 1)
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "buffer slice out of bounds",
                    )
                })
                .and_then(|slice| unsafe { Ok(CStr::from_bytes_with_nul_unchecked(slice)) })?;
            debug!("trigger={:?}", cstr);
            file.write_all(cstr.to_bytes_with_nul())?;
        }

        let fd = AsyncFd::with_interest(file, Interest::PRIORITY)?;
        Ok(futures::stream::try_unfold(fd, |fd| {
            Box::pin(async move {
                loop {
                    let mut guard = fd.ready(Interest::PRIORITY).await?;
                    if guard.ready().is_priority() {
                        guard.clear_ready_matching(Ready::PRIORITY);
                        break Ok(Some(((), fd)));
                    }
                }
            })
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use nativetestutils::*;

    use super::MemoryEvents;
    use super::MemoryStats;
    use super::PartialReadout;
    use super::ProcessCgroupInfo;
    use super::Stats;

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_stats_from_str_success() {
        // Test valid PSI format string
        let input = "avg10=1.23 avg60=4.56 avg300=7.89 total=12345";
        let stats = Stats::from_str(input).expect("Should parse valid PSI string");

        assert_eq!(stats.avg10, 1.23);
        assert_eq!(stats.avg60, 4.56);
        assert_eq!(stats.avg300, 7.89);
        assert_eq!(stats.total, 12345);
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_stats_from_str_different_order() {
        // Test that order doesn't matter
        let input = "total=98765 avg300=3.21 avg10=9.87 avg60=6.54";
        let stats = Stats::from_str(input).expect("Should parse regardless of order");

        assert_eq!(stats.avg10, 9.87);
        assert_eq!(stats.avg60, 6.54);
        assert_eq!(stats.avg300, 3.21);
        assert_eq!(stats.total, 98765);
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_stats_from_str_with_extra_whitespace() {
        // Test handling of extra whitespace
        let input = "  avg10=1.0   avg60=2.0  avg300=3.0   total=100  ";
        let stats = Stats::from_str(input).expect("Should handle extra whitespace");

        assert_eq!(stats.avg10, 1.0);
        assert_eq!(stats.avg60, 2.0);
        assert_eq!(stats.avg300, 3.0);
        assert_eq!(stats.total, 100);
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_stats_from_str_zero_values() {
        // Test with zero values
        let input = "avg10=0.0 avg60=0.0 avg300=0.0 total=0";
        let stats = Stats::from_str(input).expect("Should handle zero values");

        assert_eq!(stats.avg10, 0.0);
        assert_eq!(stats.avg60, 0.0);
        assert_eq!(stats.avg300, 0.0);
        assert_eq!(stats.total, 0);
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_stats_from_str_missing_key() {
        // Test missing avg10
        let input = "avg60=4.56 avg300=7.89 total=12345";
        assert!(Stats::from_str(input).is_err());

        // Test missing avg60
        let input = "avg10=1.23 avg300=7.89 total=12345";
        assert!(Stats::from_str(input).is_err());

        // Test missing avg300
        let input = "avg10=1.23 avg60=4.56 total=12345";
        assert!(Stats::from_str(input).is_err());

        // Test missing total
        let input = "avg10=1.23 avg60=4.56 avg300=7.89";
        assert!(Stats::from_str(input).is_err());
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_stats_from_str_duplicate_key() {
        // Test duplicate avg10
        let input = "avg10=1.23 avg60=4.56 avg300=7.89 total=12345 avg10=9.99";
        assert!(Stats::from_str(input).is_err());

        // Test duplicate total
        let input = "avg10=1.23 avg60=4.56 avg300=7.89 total=12345 total=99999";
        assert!(Stats::from_str(input).is_err());
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_stats_from_str_invalid_key() {
        // Test unknown key
        let input = "avg10=1.23 avg60=4.56 avg300=7.89 total=12345 unknown=42";
        assert!(Stats::from_str(input).is_err());

        // Test typo in key name
        let input = "avg10=1.23 avg60=4.56 avg30=7.89 total=12345";
        assert!(Stats::from_str(input).is_err());
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_stats_from_str_invalid_float_value() {
        // Test invalid float for avg10
        let input = "avg10=not_a_number avg60=4.56 avg300=7.89 total=12345";
        assert!(Stats::from_str(input).is_err());

        // Test invalid float for avg60
        let input = "avg10=1.23 avg60=invalid avg300=7.89 total=12345";
        assert!(Stats::from_str(input).is_err());

        // Test invalid float for avg300
        let input = "avg10=1.23 avg60=4.56 avg300=bad_float total=12345";
        assert!(Stats::from_str(input).is_err());
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_stats_from_str_invalid_int_value() {
        // Test invalid integer for total
        let input = "avg10=1.23 avg60=4.56 avg300=7.89 total=not_an_int";
        assert!(Stats::from_str(input).is_err());

        // Test float for total (should be integer)
        let input = "avg10=1.23 avg60=4.56 avg300=7.89 total=123.45";
        assert!(Stats::from_str(input).is_err());
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_stats_from_str_missing_equals() {
        // Test missing equals sign
        let input = "avg10 1.23 avg60=4.56 avg300=7.89 total=12345";
        assert!(Stats::from_str(input).is_err());

        // Test key without value
        let input = "avg10= avg60=4.56 avg300=7.89 total=12345";
        assert!(Stats::from_str(input).is_err());
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_stats_from_str_empty_string() {
        // Test empty string
        assert!(Stats::from_str("").is_err());

        // Test whitespace only
        assert!(Stats::from_str("   ").is_err());
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_stats_from_str_large_values() {
        // Test large values
        let input = "avg10=999.99 avg60=888.88 avg300=777.77 total=18446744073709551615";
        let stats = Stats::from_str(input).expect("Should handle large values");

        assert_eq!(stats.avg10, 999.99);
        assert_eq!(stats.avg60, 888.88);
        assert_eq!(stats.avg300, 777.77);
        assert_eq!(stats.total, 18446744073709551615); // u64::MAX
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_partial_readout_from_str_success() {
        // Test large values
        let input = "some avg10=0.00 avg60=0.26 avg300=0.70 total=15465353";
        let stats = PartialReadout::from_str(input).expect("Should parse valid partial PSI string");

        assert_eq!(stats.some.avg10, 0.0);
        assert_eq!(stats.some.avg60, 0.26);
        assert_eq!(stats.some.avg300, 0.70);
        assert_eq!(stats.some.total, 15465353);
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_partial_readout_from_str_additional_keys() {
        // Test large values
        let input = r#"some avg10=0.00 avg60=0.26 avg300=0.70 total=15465353
full avg10=0.00 avg60=0.00 avg300=0.00 total=5019"#;
        let stats = PartialReadout::from_str(input)
            .expect("Should parse partial PSI string with addiitional keys");

        assert_eq!(stats.some.avg10, 0.0);
        assert_eq!(stats.some.avg60, 0.26);
        assert_eq!(stats.some.avg300, 0.70);
        assert_eq!(stats.some.total, 15465353);
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_memory_stats_from_str_success() {
        // Test that parsing succeeds with valid memory stats string
        let input = r#"anon 675840
file 405504
kernel_stack 1
percpu 2
sock 3
shmem 4
file_mapped 405504
file_dirty 5
file_writeback 6
inactive_anon 675840
active_anon 7
inactive_file 405504
active_file 135168
unevictable 8
slab_reclaimable 9
slab_unreclaimable 10
slab 11
workingset_refault_anon 12
workingset_refault_file 13
workingset_activate_anon 14
workingset_activate_file 15
workingset_restore_anon 16
workingset_restore_file 17
workingset_nodereclaim 18
pgfault 693
pgmajfault 19
pgrefill 20
pgscan 21
pgsteal 22
pgactivate 33
pgdeactivate 23
pglazyfree 24
pglazyfreed 25"#;
        let stats = MemoryStats::from_str(input).expect("Should parse valid memory stats string");

        assert_eq!(stats.anon, 675840);
        assert_eq!(stats.file, 405504);
        assert_eq!(stats.kernel_stack, 1);
        assert_eq!(stats.percpu, 2);
        assert_eq!(stats.sock, 3);
        assert_eq!(stats.shmem, 4);
        assert_eq!(stats.file_mapped, 405504);
        assert_eq!(stats.file_dirty, 5);
        assert_eq!(stats.file_writeback, 6);
        assert_eq!(stats.inactive_anon, 675840);
        assert_eq!(stats.active_anon, 7);
        assert_eq!(stats.inactive_file, 405504);
        assert_eq!(stats.active_file, 135168);
        assert_eq!(stats.unevictable, 8);
        assert_eq!(stats.slab_reclaimable, 9);
        assert_eq!(stats.slab_unreclaimable, 10);
        assert_eq!(stats.slab, 11);
        assert_eq!(stats.workingset_refault_anon, 12);
        assert_eq!(stats.workingset_refault_file, 13);
        assert_eq!(stats.workingset_activate_anon, 14);
        assert_eq!(stats.workingset_activate_file, 15);
        assert_eq!(stats.workingset_restore_anon, 16);
        assert_eq!(stats.workingset_restore_file, 17);
        assert_eq!(stats.workingset_nodereclaim, 18);
        assert_eq!(stats.pgfault, 693);
        assert_eq!(stats.pgmajfault, 19);
        assert_eq!(stats.pgrefill, 20);
        assert_eq!(stats.pgscan, 21);
        assert_eq!(stats.pgsteal, 22);
        assert_eq!(stats.pgactivate, 33);
        assert_eq!(stats.pgdeactivate, 23);
        assert_eq!(stats.pglazyfree, 24);
        assert_eq!(stats.pglazyfreed, 25);
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_memory_stats_from_str_invalid_value() {
        // Test that parsing fails with invalid memory stats string
        let input = r#"anon not_a_number
file 405504
pglazyfreed 25"#;
        assert!(MemoryStats::from_str(input).is_err());
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_memory_stats_from_str_missing_values() {
        // Test that parsing succeeds even if some values are missing
        let input: &'static str = r#"anon 675840
file 405504
file_mapped 405504
inactive_anon 675840
inactive_file 405504
active_file 135168
pgfault 693"#;
        let stats = MemoryStats::from_str(input)
            .expect("Should parse memory stats and use -1 default if values are missing");
        assert_eq!(stats.anon, 675840);
        assert_eq!(stats.file, 405504);
        assert_eq!(stats.kernel_stack, -1);
        assert_eq!(stats.percpu, -1);
        assert_eq!(stats.sock, -1);
        assert_eq!(stats.shmem, -1);
        assert_eq!(stats.file_mapped, 405504);
        assert_eq!(stats.file_dirty, -1);
        assert_eq!(stats.file_writeback, -1);
        assert_eq!(stats.inactive_anon, 675840);
        assert_eq!(stats.active_anon, -1);
        assert_eq!(stats.inactive_file, 405504);
        assert_eq!(stats.active_file, 135168);
        assert_eq!(stats.unevictable, -1);
        assert_eq!(stats.slab_reclaimable, -1);
        assert_eq!(stats.slab_unreclaimable, -1);
        assert_eq!(stats.slab, -1);
        assert_eq!(stats.workingset_refault_anon, -1);
        assert_eq!(stats.workingset_refault_file, -1);
        assert_eq!(stats.workingset_activate_anon, -1);
        assert_eq!(stats.workingset_activate_file, -1);
        assert_eq!(stats.workingset_restore_anon, -1);
        assert_eq!(stats.workingset_restore_file, -1);
        assert_eq!(stats.workingset_nodereclaim, -1);
        assert_eq!(stats.pgfault, 693);
        assert_eq!(stats.pgmajfault, -1);
        assert_eq!(stats.pgrefill, -1);
        assert_eq!(stats.pgscan, -1);
        assert_eq!(stats.pgsteal, -1);
        assert_eq!(stats.pgactivate, -1);
        assert_eq!(stats.pgdeactivate, -1);
        assert_eq!(stats.pglazyfree, -1);
        assert_eq!(stats.pglazyfreed, -1);
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_memory_stats_from_str_extra_values() {
        // Test that extra unknown values are ignored
        let input: &'static str = r#"anon 675840
file 405504
file_mapped 405504
inactive_anon 675840
inactive_file 405504
active_file 135168
pgfault 693
extra_value 12345"#;
        let stats = MemoryStats::from_str(input).expect("Should parse and ignore extra values");
        assert_eq!(stats.anon, 675840);
        assert_eq!(stats.file, 405504);
        assert_eq!(stats.kernel_stack, -1);
        assert_eq!(stats.percpu, -1);
        assert_eq!(stats.sock, -1);
        assert_eq!(stats.shmem, -1);
        assert_eq!(stats.file_mapped, 405504);
        assert_eq!(stats.file_dirty, -1);
        assert_eq!(stats.file_writeback, -1);
        assert_eq!(stats.inactive_anon, 675840);
        assert_eq!(stats.active_anon, -1);
        assert_eq!(stats.inactive_file, 405504);
        assert_eq!(stats.active_file, 135168);
        assert_eq!(stats.unevictable, -1);
        assert_eq!(stats.slab_reclaimable, -1);
        assert_eq!(stats.slab_unreclaimable, -1);
        assert_eq!(stats.slab, -1);
        assert_eq!(stats.workingset_refault_anon, -1);
        assert_eq!(stats.workingset_refault_file, -1);
        assert_eq!(stats.workingset_activate_anon, -1);
        assert_eq!(stats.workingset_activate_file, -1);
        assert_eq!(stats.workingset_restore_anon, -1);
        assert_eq!(stats.workingset_restore_file, -1);
        assert_eq!(stats.workingset_nodereclaim, -1);
        assert_eq!(stats.pgfault, 693);
        assert_eq!(stats.pgmajfault, -1);
        assert_eq!(stats.pgrefill, -1);
        assert_eq!(stats.pgscan, -1);
        assert_eq!(stats.pgsteal, -1);
        assert_eq!(stats.pgactivate, -1);
        assert_eq!(stats.pgdeactivate, -1);
        assert_eq!(stats.pglazyfree, -1);
        assert_eq!(stats.pglazyfreed, -1);
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_memory_events_from_str_success() {
        // Test that parsing succeeds with valid memory stats string
        let input = r#"low 567
high 456
max 345
oom 234
oom_kill 123"#;
        let stats = MemoryEvents::from_str(input).expect("Should parse valid memory events string");

        assert_eq!(stats.low, 567);
        assert_eq!(stats.high, 456);
        assert_eq!(stats.oom, 234);
        assert_eq!(stats.oom_kill, 123);
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_memory_events_from_str_extra_values() {
        // Test that parsing succeeds with valid memory stats string
        let input = r#"low 567
high 456
max 345
oom 234
oom_kill 123
extra_value 123"#;
        let stats = MemoryEvents::from_str(input).expect("Should parse valid memory events string");

        assert_eq!(stats.low, 567);
        assert_eq!(stats.high, 456);
        assert_eq!(stats.oom, 234);
        assert_eq!(stats.oom_kill, 123);
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_memory_events_from_str_invalid_values() {
        // Test that parsing succeeds with valid memory stats string
        let input = r#"low 567
high abc
max 345
oom 234
oom_kill 123"#;
        assert!(MemoryEvents::from_str(input).is_err());
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_memory_from_str_success() {
        // Test valid PSI format string
        let input = "avg10=1.23 avg60=4.56 avg300=7.89 total=12345";
        let stats = Stats::from_str(input).expect("Should parse valid PSI string");

        assert_eq!(stats.avg10, 1.23);
        assert_eq!(stats.avg60, 4.56);
        assert_eq!(stats.avg300, 7.89);
        assert_eq!(stats.total, 12345);
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_cgroup_from_str_valid_success() {
        let input = r#"4:cpuset:/foreground
3:cpuacct:/
2:cpu:/xr
1:blkio:/
0::/uid_10083/pid_5200
"#;
        // Test empty string
        let process_cgroup_info =
            ProcessCgroupInfo::from_str(input).expect("Should parse all values");
        assert_eq!(process_cgroup_info.cpuset, "foreground");
        assert_eq!(process_cgroup_info.cpuacct, "");
        assert_eq!(process_cgroup_info.cpu, "xr");
        assert_eq!(process_cgroup_info.blkio, "");
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_cgroup_from_str_empty_string() {
        // Test empty string
        let process_cgroup_info =
            ProcessCgroupInfo::from_str("").expect("Should set all values to default");
        assert_eq!(process_cgroup_info.cpuset, "");
        assert_eq!(process_cgroup_info.cpuacct, "");
        assert_eq!(process_cgroup_info.cpu, "");
        assert_eq!(process_cgroup_info.blkio, "");
    }
}
