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
use std::time::Duration;

use anyhow::Context;
use hzos_soft_error::soft_error;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::RingBufferBuilder;
use log::debug;
use log::error;
use log::trace;
use log::warn;
use tokio::io::unix::AsyncFd;
use tokio::task::JoinSet;

use crate::cgroup_monitor::filesystem::discover_existing_cgroups;
use crate::cgroup_skel::CgroupSkelBuilder;
use crate::USERDEBUG;

/// BPF event handling module for cgroup monitoring.
///
/// This module provides the interface between BPF programs and Rust code for monitoring
/// cgroup events. It defines the data structures that match the C structures used in
/// the BPF program, and provides safe conversion from raw BPF events to typed Rust events.
mod bpf {
    use std::fmt::Debug;
    use std::os::raw::c_char;

    use anyhow::anyhow;
    use anyhow::Context as _;

    /// Maximum length of cgroup name path.
    /// Matches CG_NAME_LEN from cgroup.bpf.c
    const CG_NAME_LEN: usize = 25;

    /// Event type identifiers (matches C #define constants)
    const EVENT_CGROUP_MKDIR: u8 = 1;
    const EVENT_CGROUP_ATTACH: u8 = 2;
    const EVENT_CGROUP_RMDIR: u8 = 3;
    const EVENT_SCHED_EXEC: u8 = 4;
    const EVENT_SCHED_EXIT: u8 = 5;

    /// EVENT_CGROUP_MKDIR
    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    struct CgroupMkdir {
        path: [c_char; CG_NAME_LEN],
    }

    /// EVENT_CGROUP_ATTACH
    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    struct CgroupAttach {
        path: [c_char; CG_NAME_LEN],
        pid: u32,
    }

    /// EVENT_CGROUP_RMDIR.
    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    struct CgroupRmdir {
        path: [c_char; CG_NAME_LEN],
    }

    /// EVENT_SCHED_EXEC
    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    struct SchedExec {
        uid: u32,
        pid: u32,
    }

    /// EVENT_SCHED_EXIT
    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    struct SchedExit {
        uid: u32,
        pid: u32,
    }

    /// Union of all possible event data types.
    /// Must match the C union layout exactly.
    #[repr(C)]
    union RawEventData {
        cgroup_mkdir: CgroupMkdir,
        cgroup_attach: CgroupAttach,
        cgroup_rmdir: CgroupRmdir,
        sched_exec: SchedExec,
        sched_exit: SchedExit,
    }

    /// Main event structure that matches the C struct event.
    /// Contains an event_id discriminant and a union of event data.
    #[repr(C)]
    pub(crate) struct RawEvent {
        event_id: u8,
        data: RawEventData,
    }

    impl Debug for RawEvent {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self.event_id {
                EVENT_CGROUP_MKDIR => {
                    // SAFETY: We've verified the event_id matches the event struct
                    let data = unsafe { self.data.cgroup_mkdir };

                    // SAFETY: bpf_probe_read_kernel_str() guarantees the string is null-terminated
                    let path = unsafe { std::ffi::CStr::from_ptr(data.path.as_ptr()) }
                        .to_str()
                        .map_err(|_| std::fmt::Error)?;

                    f.debug_struct("CgroupMkdir").field("path", &path).finish()
                }
                EVENT_CGROUP_ATTACH => {
                    // SAFETY: We've verified the event_id matches the event struct
                    let data = unsafe { self.data.cgroup_attach };

                    // SAFETY: bpf_probe_read_kernel_str() guarantees the string is null-terminated
                    let path = unsafe { std::ffi::CStr::from_ptr(data.path.as_ptr()) }
                        .to_str()
                        .map_err(|_| std::fmt::Error)?;

                    f.debug_struct("CgroupAttach")
                        .field("path", &path)
                        .field("pid", &data.pid)
                        .finish()
                }
                EVENT_CGROUP_RMDIR => {
                    // SAFETY: We've verified the event_id matches the event struct
                    let data = unsafe { self.data.cgroup_rmdir };

                    // SAFETY: bpf_probe_read_kernel_str() guarantees the string is null-terminated
                    let path = unsafe { std::ffi::CStr::from_ptr(data.path.as_ptr()) }
                        .to_str()
                        .map_err(|_| std::fmt::Error)?;

                    f.debug_struct("CgroupRmdir").field("path", &path).finish()
                }
                EVENT_SCHED_EXEC => {
                    // SAFETY: We've verified the event_id matches the event struct
                    let data = unsafe { self.data.sched_exec };
                    f.debug_struct("SchedExec")
                        .field("uid", &data.uid)
                        .field("pid", &data.pid)
                        .finish()
                }
                EVENT_SCHED_EXIT => {
                    // SAFETY: We've verified the event_id matches the event struct
                    let data = unsafe { self.data.sched_exit };
                    f.debug_struct("SchedExit")
                        .field("uid", &data.uid)
                        .field("pid", &data.pid)
                        .finish()
                }
                _ => f.debug_struct("Unknown").finish(),
            }
        }
    }

    #[derive(Debug, Clone)]
    pub(crate) enum Event {
        CgroupMkdir { path: String },
        CgroupAttach { path: String, pid: u32 },
        CgroupRmdir { path: String },
        SchedExec { uid: u32, pid: u32 },
        SchedExit { uid: u32, pid: u32 },
    }

    impl TryFrom<&RawEvent> for Event {
        type Error = anyhow::Error;

        fn try_from(event: &RawEvent) -> Result<Self, Self::Error> {
            match event.event_id {
                EVENT_CGROUP_MKDIR => {
                    // SAFETY: We've verified the size matches the event struct
                    let data = unsafe { event.data.cgroup_mkdir };

                    // SAFETY: bpf_probe_read_kernel_str() guarantees the string is null-terminated
                    let path = unsafe { std::ffi::CStr::from_ptr(data.path.as_ptr()) }
                        .to_str()
                        .context("Invalid cgroup path")?;

                    Ok(Event::CgroupMkdir {
                        path: path.to_string(),
                    })
                }
                EVENT_CGROUP_ATTACH => {
                    // SAFETY: We've verified the size matches the event struct
                    let data = unsafe { event.data.cgroup_attach };

                    // SAFETY: bpf_probe_read_kernel_str() guarantees the string is null-terminated
                    let path = unsafe { std::ffi::CStr::from_ptr(data.path.as_ptr()) }
                        .to_str()
                        .context("Invalid cgroup path")?;

                    Ok(Event::CgroupAttach {
                        path: path.to_string(),
                        pid: data.pid,
                    })
                }
                EVENT_CGROUP_RMDIR => {
                    // SAFETY: We've verified the size matches the event struct
                    let data = unsafe { event.data.cgroup_rmdir };

                    // SAFETY: bpf_probe_read_kernel_str() guarantees the string is null-terminated
                    let path = unsafe { std::ffi::CStr::from_ptr(data.path.as_ptr()) }
                        .to_str()
                        .context("Invalid cgroup path")?;

                    Ok(Event::CgroupRmdir {
                        path: path.to_string(),
                    })
                }
                EVENT_SCHED_EXEC => {
                    // SAFETY: We've verified the size matches the event struct
                    let data = unsafe { event.data.sched_exec };
                    Ok(Event::SchedExec {
                        uid: data.uid,
                        pid: data.pid,
                    })
                }
                EVENT_SCHED_EXIT => {
                    // SAFETY: We've verified the size matches the event struct
                    let data = unsafe { event.data.sched_exit };
                    Ok(Event::SchedExit {
                        uid: data.uid,
                        pid: data.pid,
                    })
                }
                _ => Err(anyhow!("Invalid event type: {}", event.event_id)),
            }
        }
    }
}

/// File system event handling module for cgroup monitoring.
///
/// This module provides the interface between the sysfs filesystem and Rust code for monitoring
/// the cgroupv2 hierarchy.
mod filesystem {
    use std::path::Path;

    use walkdir::WalkDir;

    const CGROUPV2_ROOT: &str = "/sys/fs/cgroup";
    const CGROUPV2_PROCS_FILE: &str = "cgroup.procs";

    /// Discovers existing cgroups by walking the cgroup filesystem.
    ///
    /// This function traverses the cgroupv2 filesystem hierarchy starting from the root
    /// (`/sys/fs/cgroup`) and identifies active cgroups by examining `cgroup.procs` files.
    /// It extracts the UID and PID from the cgroup path structure and verifies that the
    /// PID is actually present in the cgroup before returning it.
    ///
    /// # Returns
    ///
    /// An iterator yielding tuples of `(cgroup_id, uid, pid)` where:
    /// - `cgroup_id`: The inode number of the cgroup directory
    /// - `uid`: User ID extracted from the cgroup path
    /// - `pid`: Process ID extracted from the cgroup path and verified to be in the cgroup
    pub(crate) fn discover_existing_cgroups() -> impl Iterator<Item = (u32, u32)> {
        WalkDir::new(CGROUPV2_ROOT)
            .into_iter()
            .filter_map(|entry_result| {
                let entry = entry_result.ok()?;

                // Only process cgroup.procs files
                if entry.file_name().to_string_lossy() != CGROUPV2_PROCS_FILE {
                    return None;
                }

                let (uid, pid) = parse_cgroup_path(entry.path())?;

                // Verify the PID is actually in the cgroup
                if is_pid_in_cgroup(entry.path(), pid) {
                    Some((uid, pid))
                } else {
                    None
                }
            })
    }

    /// Parses a cgroup path to extract UID and PID.
    ///
    /// Extracts the user ID and process ID from a cgroup filesystem path by examining
    /// the path components in reverse order.
    ///
    /// # Arguments
    ///
    /// * `path` - The filesystem path to parse
    ///
    /// # Returns
    ///
    /// `Some((uid, pid))` if both UID and PID can be successfully extracted and parsed,
    /// `None` otherwise.
    pub(crate) fn parse_cgroup_path(path: &Path) -> Option<(u32, u32)> {
        let components: Vec<_> = path.components().rev().collect();

        let pid = extract_id_from_component(&components, 1, "pid_")?;
        let uid = extract_id_from_component(&components, 2, "uid_")?;

        Some((uid, pid))
    }

    pub(crate) fn parse_cgroup_dir(path: &Path) -> Option<(u32, u32)> {
        let components: Vec<_> = path.components().rev().collect();

        let pid = extract_id_from_component(&components, 0, "pid_")?;
        let uid = extract_id_from_component(&components, 1, "uid_")?;

        Some((uid, pid))
    }

    /// Extracts an ID from a path component at the given index with the specified prefix.
    ///
    /// Looks up a path component at the specified index, converts it to a string,
    /// strips the given prefix, and parses the remaining string as a u32.
    ///
    /// # Arguments
    ///
    /// * `components` - Slice of path components to search
    /// * `index` - Index of the component to examine
    /// * `prefix` - String prefix to strip from the component
    ///
    /// # Returns
    ///
    /// `Some(id)` if the component exists, has the expected prefix, and the remaining
    /// part can be parsed as a u32, `None` otherwise.
    fn extract_id_from_component(
        components: &[std::path::Component],
        index: usize,
        prefix: &str,
    ) -> Option<u32> {
        let component = components.get(index)?;
        let component_str = component.as_os_str().to_str()?;
        let id_str = component_str.strip_prefix(prefix)?;
        id_str.parse().ok()
    }

    /// Checks if a specific PID is listed in the cgroup.procs file.
    ///
    /// Reads the contents of a `cgroup.procs` file and searches for the target PID
    /// among the listed process IDs.
    ///
    /// # Arguments
    ///
    /// * `cgroup_procs_path` - Path to the cgroup.procs file to read
    /// * `target_pid` - The process ID to search for
    ///
    /// # Returns
    ///
    /// `true` if the target PID is found in the file, `false` if not found or if
    /// the file cannot be read.
    fn is_pid_in_cgroup(cgroup_procs_path: &std::path::Path, target_pid: u32) -> bool {
        if let Ok(pids_content) = std::fs::read_to_string(cgroup_procs_path) {
            pids_content
                .lines()
                .filter_map(|line| line.parse::<u32>().ok())
                .any(|pid| pid == target_pid)
        } else {
            false
        }
    }

    #[derive(Debug, Copy, Clone)]
    pub(crate) enum Event {
        Exists { uid: u32, pid: u32 },
    }

    #[cfg(test)]
    mod tests {
        use std::fs;
        use std::path::PathBuf;

        use nativetestutils::frl_test;
        use tempfile::TempDir;

        use crate::cgroup_monitor::filesystem;

        #[frl_test(TestSuite = "MemflowTestSuite")]
        fn test_parse_cgroup_path_valid() {
            let path = PathBuf::from("/sys/fs/cgroup/uid_10000/pid_12345/cgroup.procs");
            let result = filesystem::parse_cgroup_path(&path);
            assert_eq!(result, Some((10000, 12345)));
        }

        #[frl_test(TestSuite = "MemflowTestSuite")]
        fn test_parse_cgroup_path_max_values() {
            let path = PathBuf::from("/sys/fs/cgroup/uid_4294967294/pid_32768/cgroup.procs");
            let result = filesystem::parse_cgroup_path(&path);
            assert_eq!(result, Some((4294967294, 32768)));
        }

        #[frl_test(TestSuite = "MemflowTestSuite")]
        fn test_parse_cgroup_path_min_values() {
            let path = PathBuf::from("/sys/fs/cgroup/uid_0/pid_1/cgroup.procs");
            let result = filesystem::parse_cgroup_path(&path);
            assert_eq!(result, Some((0, 1)));
        }

        #[frl_test(TestSuite = "MemflowTestSuite")]
        fn test_parse_cgroup_path_missing_uid() {
            let path = PathBuf::from("/sys/fs/cgroup/pid_12345/cgroup.procs");
            let result = filesystem::parse_cgroup_path(&path);
            assert_eq!(result, None);
        }

        #[frl_test(TestSuite = "MemflowTestSuite")]
        fn test_parse_cgroup_path_missing_pid() {
            let path = PathBuf::from("/sys/fs/cgroup/uid_10000/cgroup.procs");
            let result = filesystem::parse_cgroup_path(&path);
            assert_eq!(result, None);
        }

        #[frl_test(TestSuite = "MemflowTestSuite")]
        fn test_parse_cgroup_path_invalid_uid_format() {
            let path = PathBuf::from("/sys/fs/cgroup/uid_abc/pid_12345/cgroup.procs");
            let result = filesystem::parse_cgroup_path(&path);
            assert_eq!(result, None);
        }

        #[frl_test(TestSuite = "MemflowTestSuite")]
        fn test_parse_cgroup_path_invalid_pid_format() {
            let path = PathBuf::from("/sys/fs/cgroup/uid_10000/pid_xyz/cgroup.procs");
            let result = filesystem::parse_cgroup_path(&path);
            assert_eq!(result, None);
        }

        #[frl_test(TestSuite = "MemflowTestSuite")]
        fn test_parse_cgroup_dir_valid() {
            let path = PathBuf::from("uid_1000/pid_12345");
            let result = filesystem::parse_cgroup_dir(&path);
            assert_eq!(result, Some((1000, 12345)));
        }

        #[frl_test(TestSuite = "MemflowTestSuite")]
        fn test_parse_cgroup_dir_missing_pid() {
            let path = PathBuf::from("uid_1000");
            let result = filesystem::parse_cgroup_dir(&path);
            assert_eq!(result, None);
        }

        #[frl_test(TestSuite = "MemflowTestSuite")]
        fn test_parse_cgroup_dir_missing_uid() {
            let path = PathBuf::from("pid_12345");
            let result = filesystem::parse_cgroup_dir(&path);
            assert_eq!(result, None);
        }

        #[frl_test(TestSuite = "MemflowTestSuite")]
        fn test_parse_cgroup_dir_reordered() {
            let path = PathBuf::from("pid_12345/uid_1000");
            let result = filesystem::parse_cgroup_dir(&path);
            assert_eq!(result, None);
        }

        #[frl_test(TestSuite = "MemflowTestSuite")]
        fn test_extract_id_from_component_valid() {
            let path = PathBuf::from("/sys/fs/cgroup/uid_10000/pid_12345");
            let components: Vec<_> = path.components().rev().collect();

            let pid = filesystem::extract_id_from_component(&components, 0, "pid_");
            assert_eq!(pid, Some(12345));

            let uid = filesystem::extract_id_from_component(&components, 1, "uid_");
            assert_eq!(uid, Some(10000));
        }

        #[frl_test(TestSuite = "MemflowTestSuite")]
        fn test_is_pid_in_cgroup() {
            let temp_dir = TempDir::new().expect("Creating a temp dir failed");
            let cgroup_procs = temp_dir.path().join("cgroup.procs");

            // Write test PIDs to file
            fs::write(&cgroup_procs, "100\n200\n300\n")
                .expect("Writing to mock cgroup.procs failed");

            assert!(filesystem::is_pid_in_cgroup(&cgroup_procs, 100));
            assert!(filesystem::is_pid_in_cgroup(&cgroup_procs, 200));
            assert!(filesystem::is_pid_in_cgroup(&cgroup_procs, 300));
            assert!(!filesystem::is_pid_in_cgroup(&cgroup_procs, 400));
        }

        #[frl_test(TestSuite = "MemflowTestSuite")]
        fn test_is_pid_in_cgroup_empty_file() {
            let temp_dir = TempDir::new().expect("Creating a temp dir failed");
            let cgroup_procs = temp_dir.path().join("cgroup.procs");
            fs::write(&cgroup_procs, "").expect("Writing to mock cgroup.procs failed");

            assert!(!filesystem::is_pid_in_cgroup(&cgroup_procs, 100));
        }

        #[frl_test(TestSuite = "MemflowTestSuite")]
        fn test_is_pid_in_cgroup_file_not_found() {
            let path = PathBuf::from("/nonexistent/cgroup.procs");
            assert!(!filesystem::is_pid_in_cgroup(&path, 100));
        }
    }
}

/// State Machine Events
#[derive(Debug, Clone)]
enum StateMachineEvent {
    /// BPF Variant
    Bpf(bpf::Event),

    /// Filesystem Variant
    Filesystem(filesystem::Event),
}

#[allow(dead_code)]
struct CgroupEntry {
    uid: u32,
    pid: u32,
    is_attached: bool,
}

/// State machine for tracking cgroup and process relationships.
///
/// This struct maintains bidirectional mappings between cgroups and processes to efficiently
/// track process lifecycle events. It stores which processes belong to which cgroups and
/// allows quick lookups in both directions for event processing.
struct StateMachine {
    pid_to_entry: HashMap<u32, CgroupEntry>,
}

impl StateMachine {
    fn new() -> Self {
        Self {
            pid_to_entry: HashMap::new(),
        }
    }

    /// Processes internal events and maintains state consistency across the cgroup monitoring system.
    ///
    /// This method serves as the central state machine that ensures proper sequencing of cgroup
    /// lifecycle events and prevents race conditions by processing all state changes sequentially.
    /// It transforms low-level BPF and filesystem events into high-level application events,
    /// applying business logic and state validation.
    ///
    /// # Arguments
    ///
    /// * `event` - An internal event from either BPF probes or filesystem discovery
    ///
    /// # Returns
    ///
    /// * `Ok(Some(CgroupEvent))` - When the event should be propagated to consumers
    /// * `Ok(None)` - When the event is handled internally but doesn't generate output
    /// * `Err(anyhow::Error)` - When the event represents an invalid state transition
    ///
    /// # Examples
    ///
    /// ```rust
    /// use crate::cgroup_monitor::bpf;
    /// use crate::cgroup_monitor::StateMachine;
    /// use crate::cgroup_monitor::StateMachineEvent;
    ///
    /// let mut state_machine = StateMachine::new(MockReporterFactory::default());
    ///
    /// // Process a cgroup creation event
    /// let mkdir_event = StateMachineEvent::Bpf(bpf::Event::CgroupMkdir {
    ///     cgroup_id: 12345,
    ///     path: "uid_10000/pid_5678".to_string(),
    /// });
    ///
    /// // This creates internal state but doesn't emit an external event
    /// assert!(matches!(state_machine.process_event(mkdir_event), Ok(None)));
    ///
    /// // Process a process attachment event
    /// let attach_event = StateMachineEvent::Bpf(bpf::Event::CgroupAttach {
    ///     cgroup_id: 12345,
    ///     uid: 10000,
    ///     pid: 5678,
    /// });
    ///
    /// // This emits a Create event for Android applications (uid >= 10000)
    /// assert!(matches!(
    ///     state_machine.process_event(attach_event),
    ///     Ok(Some(CgroupEvent::Create {
    ///         uid: 10000,
    ///         pid: 5678
    ///     }))
    /// ));
    /// ```
    fn process_event(&mut self, event: StateMachineEvent) -> anyhow::Result<Option<CgroupEvent>> {
        match event {
            StateMachineEvent::Bpf(event) => {
                match event {
                    bpf::Event::CgroupMkdir { path } => {
                        let (uid, pid) = match filesystem::parse_cgroup_dir(&Path::new(&path)) {
                            Some((uid, pid)) => (uid, pid),
                            None => {
                                trace!("Could not parse cgroup path: {path:?}");
                                return Ok(None);
                            }
                        };

                        if self.add_cgroup(uid, pid) {
                            debug!("Created cgroup (uid: {uid}, pid: {pid}): {path:?}");
                        } else {
                            soft_error!("Could not create cgroup as one already exists");
                        }

                        Ok(None)
                    }
                    bpf::Event::CgroupAttach { path, pid } => {
                        let (uid, cgroup_pid) =
                            match filesystem::parse_cgroup_dir(&Path::new(&path)) {
                                Some((uid, pid)) => (uid, pid),
                                None => {
                                    trace!("Could not parse cgroup path: {path:?}");
                                    return Ok(None);
                                }
                            };

                        // It is possible for some `uid_{uid}/pid_{pid}` directories contain more than one
                        // process (I'm looking at you zygote). So only attach the process if the pid that
                        // joined the cgroup actually matches the one encoded in the path.
                        if pid != cgroup_pid {
                            debug!(
                                "Mismatched pid ({pid}) and cgroup pid ({cgroup_pid}) for {path:?}. Ignoring attach"
                            );
                            return Ok(None);
                        }

                        if self.attach_process(pid) {
                            debug!("Attached process (uid: {uid}, pid: {pid}) to cgroup: {path:?}");
                            if uid >= 10000 {
                                Ok(Some(CgroupEvent::Create { uid, pid }))
                            } else {
                                Ok(None)
                            }
                        } else {
                            soft_error!(
                                "Attempted to attach process to cgroup that was not created or already attached"
                            );
                            Ok(None)
                        }
                    }
                    bpf::Event::CgroupRmdir { path } => {
                        let (uid, pid) = match filesystem::parse_cgroup_dir(&Path::new(&path)) {
                            Some((uid, pid)) => (uid, pid),
                            None => {
                                trace!("Could not parse cgroup path: {path:?}");
                                return Ok(None);
                            }
                        };

                        match self.remove_cgroup(pid) {
                            Some(true) => {
                                debug!("Removed cgroup (uid: {uid}, pid: {pid}): {path:?}");
                                Ok(Some(CgroupEvent::Remove { uid, pid }))
                            }
                            Some(false) => {
                                debug!("Removed cgroup (uid: {uid}, pid: {pid}): {path:?}");
                                Ok(None)
                            }
                            None => {
                                soft_error!("Attempted to remove cgroup that was not created");
                                Ok(None)
                            }
                        }
                    }
                    bpf::Event::SchedExec { uid, pid } => {
                        if self.is_pid_attached(pid) {
                            if uid < 10000 {
                                Ok(Some(CgroupEvent::Create { uid, pid }))
                            } else {
                                Ok(None)
                            }
                        } else {
                            Ok(None)
                        }
                    }
                    bpf::Event::SchedExit { uid, pid } => {
                        if self.remove_process(pid) {
                            debug!("Removed process (uid: {uid} pid: {pid})");
                            Ok(Some(CgroupEvent::Remove { uid, pid }))
                        } else {
                            Ok(None)
                        }
                    }
                }
            }
            StateMachineEvent::Filesystem(event) => match event {
                filesystem::Event::Exists { uid, pid } => {
                    if !self.add_cgroup(uid, pid) {
                        warn!("Could not add cgroup since one alreay existed for (uid: {uid}, pid: {pid})");
                        return Ok(None);
                    }

                    if !self.attach_process(pid) {
                        warn!("Attempted to attach process to cgroup that was already attached (uid: {uid}, pid: {pid})");
                        return Ok(None);
                    }

                    Ok(Some(CgroupEvent::Exists { uid, pid }))
                }
            },
        }
    }

    fn add_cgroup(&mut self, uid: u32, pid: u32) -> bool {
        self.pid_to_entry
            .insert(
                pid,
                CgroupEntry {
                    uid,
                    pid,
                    is_attached: false,
                },
            )
            .is_none()
    }

    fn attach_process(&mut self, pid: u32) -> bool {
        let result = match self.pid_to_entry.get_mut(&pid) {
            Some(entry) => {
                if entry.is_attached {
                    false
                } else {
                    entry.is_attached = true;
                    true
                }
            }
            None => false,
        };

        result
    }

    fn remove_process(&mut self, pid: u32) -> bool {
        if let Some(entry) = self.pid_to_entry.get_mut(&pid) {
            if !entry.is_attached {
                return false;
            }

            entry.is_attached = false;
            true
        } else {
            false
        }
    }

    fn remove_cgroup(&mut self, pid: u32) -> Option<bool> {
        if let Some(entry) = self.pid_to_entry.remove(&pid) {
            if !entry.is_attached {
                Some(false)
            } else {
                Some(true)
            }
        } else {
            None
        }
    }

    fn is_pid_attached(&self, pid: u32) -> bool {
        self.pid_to_entry
            .get(&pid)
            .map_or(false, |entry| entry.is_attached)
    }
}

/// Events emitted by the cgroup monitor for process lifecycle tracking.
///
/// This enum represents the different types of events that can occur during cgroup monitoring.
/// Events are generated both from real-time BPF probes and from filesystem discovery of
/// pre-existing cgroups.
///
/// # Event Flow
///
/// - [`CgroupEvent::Exists`]: Emitted during initial discovery for processes that were already
///   running when monitoring started
/// - [`CgroupEvent::Create`]: Emitted when a new process is attached to a monitored cgroup or
///   when a monitored process is executed
/// - [`CgroupEvent::Remove`]: Emitted when a monitored process exits
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CgroupEvent {
    /// A process that already existed when monitoring started.
    ///
    /// This event is generated during the initial filesystem scan that occurs when
    /// the monitor is first attached. It represents processes that were already running
    /// in monitored cgroups before BPF monitoring began.
    ///
    /// # Fields
    ///
    /// * `uid` - User ID of the process owner
    /// * `pid` - Process ID of the existing process
    Exists { uid: u32, pid: u32 },

    /// A new process was created and attached to a monitored cgroup.
    ///
    /// # Fields
    ///
    /// * `uid` - User ID of the process owner
    /// * `pid` - Process ID of the newly created or attached process
    Create { uid: u32, pid: u32 },

    /// A monitored process has exited.
    ///
    /// This event is generated when a previously tracked process terminates. Only processes
    /// that were previously reported via [`CgroupEvent::Exists`] or [`CgroupEvent::Create`]
    /// will generate this event.
    ///
    /// # Fields
    ///
    /// * `uid` - User ID of the process owner
    /// * `pid` - Process ID of the exited process
    Remove { uid: u32, pid: u32 },
}

pub struct CgroupMonitor<'a> {
    skel: crate::cgroup_skel::CgroupSkel<'a>,
}

impl<'a> CgroupMonitor<'a> {
    /// Creates a new cgroup monitor instance.
    ///
    /// This function initializes a new BPF-based cgroup monitor by loading and preparing
    /// the BPF skeleton program. The monitor uses BPF programs to intercept kernel events
    /// related to cgroup operations and process lifecycle management.
    ///
    /// # Arguments
    ///
    /// * `open_object` - A mutable reference to an uninitialized `OpenObject` that will be
    ///   populated with the loaded BPF object. This object must remain valid for the lifetime
    ///   of the returned `CgroupMonitor`.
    ///
    /// # Returns
    ///
    /// Returns `Ok(CgroupMonitor)` if the BPF program was successfully loaded and initialized.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::mem::MaybeUninit;
    ///
    /// use memflow::CgroupMonitor;
    ///
    /// let mut open_object = MaybeUninit::uninit();
    /// let monitor = CgroupMonitor::new(&mut open_object).expect("Failed to create cgroup monitor");
    /// ```
    ///
    /// # Notes
    ///
    /// - The monitor is not actively watching events until [`watch`](Self::watch) is called
    /// - The debug mode for BPF programs is controlled by the `USERDEBUG` global variable
    pub fn new(
        open_object: &'a mut std::mem::MaybeUninit<libbpf_rs::OpenObject>,
    ) -> anyhow::Result<Self> {
        let mut builder = CgroupSkelBuilder::default();
        builder.obj_builder.debug(USERDEBUG);
        let open = builder.open(open_object)?;
        let skel = open.load().context("Failed to load BPF program")?;

        Ok(Self { skel })
    }

    /// Starts monitoring cgroup events and returns a stream of process lifecycle events.
    ///
    /// This function attaches BPF programs to kernel tracepoints and begins monitoring cgroup
    /// operations and process events. It performs both real-time monitoring via eBPF and an
    /// initial filesystem scan to discover pre-existing processes.
    ///
    /// # Returns
    ///
    /// Returns a tuple containing:
    /// - A stream of [`CgroupEvent`]s that can be consumed asynchronously. The stream yields
    ///   three types of events:
    ///   - [`CgroupEvent::Exists`]: For processes discovered during initial filesystem scan
    ///   - [`CgroupEvent::Create`]: For newly created or attached processes
    ///   - [`CgroupEvent::Remove`]: For processes that have exited
    /// - A [`JoinSet`] of support tasks that maintain the monitoring infrastructure. These tasks
    ///   include the BPF ring buffer poller, the filesystem discovery task, and the state machine
    ///   processor. If any task in the JoinSet returns either `Ok` prematurely or `Err`, this
    ///   indicates an unrecoverable error condition and the monitoring system should be considered
    ///   failed. All tasks are expected to run indefinitely until explicitly cancelled
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::mem::MaybeUninit;
    ///
    /// use anyhow::anyhow;
    /// use futures::StreamExt;
    /// use memflow::CgroupEvent;
    /// use memflow::CgroupMonitor;
    /// use tokio::select;
    ///
    /// # async fn example() -> anyhow::Result<()> {
    /// let mut open_object = MaybeUninit::uninit();
    /// let mut monitor = CgroupMonitor::new(&mut open_object)?;
    ///
    /// // Start watching for cgroup events
    /// let (mut event_stream, mut support_tasks) = monitor.watch()?;
    ///
    /// // Process events as they arrive, monitoring support tasks for failures
    /// loop {
    ///     select! {
    ///         Some(event) = event_stream.next() => {
    ///             match event {
    ///                 CgroupEvent::Exists { uid, pid } => {
    ///                     println!("Found existing process: uid={}, pid={}", uid, pid);
    ///                 }
    ///                 CgroupEvent::Create { uid, pid } => {
    ///                     println!("New process created: uid={}, pid={}", uid, pid);
    ///                 }
    ///                 CgroupEvent::Remove { uid, pid } => {
    ///                     println!("Process exited: uid={}, pid={}", uid, pid);
    ///                 }
    ///             }
    ///         }
    ///         result = support_tasks.join_next() => {
    ///             // Any task completing (Ok or Err) indicates an unrecoverable error
    ///             match result {
    ///                 Some(Ok(_)) | None => {
    ///                     return Err(anyhow!("Monitor support tasks exited unexpectedly"));
    ///                 }
    ///                 Some(Err(e)) => {
    ///                     return Err(anyhow!("Monitor support tasks failed: {e:?}"));
    ///                 }
    ///             }
    ///         }
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn watch(
        &mut self,
    ) -> anyhow::Result<(
        impl futures::Stream<Item = CgroupEvent>,
        JoinSet<anyhow::Result<()>>,
    )> {
        let (event_sender, event_receiver) = tokio::sync::mpsc::channel(2048);
        let mut tasks = JoinSet::new();

        let (internal_event_sender, mut internal_event_receiver) = tokio::sync::mpsc::channel(2048);

        let internal_event_sender_ring_buffer = internal_event_sender.clone();
        let mut ring_buffer_builder = RingBufferBuilder::new();
        ring_buffer_builder
            .add(&self.skel.maps.events, move |data: &[u8]| -> i32 {
                if data.len() != std::mem::size_of::<bpf::RawEvent>() {
                    soft_error!(
                        "Invalid event size: expected {}, got {}",
                        std::mem::size_of::<bpf::RawEvent>(),
                        data.len()
                    );
                    return 1;
                }

                // SAFETY: We've verified the size matches the event struct
                let raw_event = unsafe { &*(data.as_ptr() as *const bpf::RawEvent) };

                let event: bpf::Event = match bpf::Event::try_from(raw_event) {
                    Ok(event) => {
                        trace!("Received cgroup event: {event:?} from BPF");
                        event
                    }
                    Err(e) => {
                        soft_error!("Failed to parse bpf event {raw_event:?}: {e:?}");
                        return 1;
                    }
                };

                if let Err(e) =
                    internal_event_sender_ring_buffer.try_send(StateMachineEvent::Bpf(event))
                {
                    error!("Failed to send internal event: {e:?}");
                }

                1
            })
            .context("Failed to create ring buffer")?;

        tasks.spawn({
            // The ring buffer must be manually polled for the callback to be invoked. However, it provides a file
            // descriptor specifically for epoll. Spawn a task that registers a readable interest on the fd and calls
            // poll once ready.
            let ring_buffer = ring_buffer_builder
                .build()
                .context("Failed to build ring buffer")?;
            let fd = ring_buffer.epoll_fd();
            let async_fd = AsyncFd::new(fd)?;
            async move {
                loop {
                    let mut guard = async_fd
                        .readable()
                        .await
                        .context("Failed to wait for readable event")?;

                    // Poll the ring buffer (non-blocking)
                    match ring_buffer.poll(Duration::from_millis(0)) {
                        Ok(_) => {
                            guard.clear_ready();
                        }
                        Err(e) => {
                            soft_error!("Error polling ring buffer: {e:?}");
                            return Err(e.into());
                        }
                    }
                }
            }
        });

        self.skel
            .attach()
            .context("Failed to attach BPF programs")?;

        // Discover existing cgroups that existed prior to attaching the BPF program
        tokio::task::spawn_blocking(move || {
            for (uid, pid) in discover_existing_cgroups() {
                let message = filesystem::Event::Exists { uid, pid };

                if let Err(e) =
                    internal_event_sender.try_send(StateMachineEvent::Filesystem(message))
                {
                    error!("Failed to send existing cgroup event: {e:?}");
                } else {
                    trace!("Sent existing cgroup event: {message:?} from filesystem");
                }
            }
        });

        // Spawn a task that acts as a state machine to avoid race conditions and synchronization overhead.
        // By processing all state changes sequentially in a single task, we eliminate the need for mutexes
        // or other synchronization primitives that would be required if multiple threads were modifying
        // the cgroup tracking state concurrently.
        tasks.spawn(async move {
            let mut state_machine = StateMachine::new();

            while let Some(state_machine_event) = internal_event_receiver.recv().await {
                match state_machine.process_event(state_machine_event) {
                    Ok(Some(cgroup_event)) => {
                        if let Err(e) = event_sender.send(cgroup_event).await {
                            error!("Failed to send cgroup event {cgroup_event:?}: {e:?}");
                        } else {
                            debug!("Sent cgroup event: {cgroup_event:?} from state machine");
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        error!("Failed to process cgroup event: {e:?}");
                        return Err(e);
                    }
                }
            }

            Ok(())
        });

        Ok((
            tokio_stream::wrappers::ReceiverStream::new(event_receiver),
            tasks,
        ))
    }
}

#[cfg(test)]
mod tests {
    use nativetestutils::frl_test;

    use super::*;

    const PID: u32 = 12345;
    const SYSTEM_UID: u32 = 1000;
    const APPLICATION_UID: u32 = 10000;

    fn cgroup_dir(uid: u32, pid: u32) -> String {
        format!("uid_{uid}/pid_{pid}")
    }

    /// Test the normal workflow of a system process being created, attached, and removed.
    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_system_process_workflow() {
        let mut state_machine = StateMachine::new();

        assert!(matches!(
            state_machine.process_event(StateMachineEvent::Bpf(bpf::Event::CgroupMkdir {
                path: cgroup_dir(SYSTEM_UID, PID),
            })),
            Ok(None)
        ));

        assert!(matches!(
            state_machine.process_event(StateMachineEvent::Bpf(bpf::Event::CgroupAttach {
                path: cgroup_dir(SYSTEM_UID, PID),
                pid: PID,
            })),
            Ok(None)
        ));

        assert!(matches!(
            state_machine.process_event(StateMachineEvent::Bpf(bpf::Event::SchedExec {
                uid: SYSTEM_UID,
                pid: PID,
            })),
            Ok(Some(CgroupEvent::Create {
                uid: SYSTEM_UID,
                pid: PID
            }))
        ));

        assert!(matches!(
            state_machine.process_event(StateMachineEvent::Bpf(bpf::Event::SchedExit {
                uid: SYSTEM_UID,
                pid: PID,
            })),
            Ok(Some(CgroupEvent::Remove {
                uid: SYSTEM_UID,
                pid: PID
            }))
        ));

        assert!(matches!(
            state_machine.process_event(StateMachineEvent::Bpf(bpf::Event::CgroupRmdir {
                path: cgroup_dir(SYSTEM_UID, PID),
            })),
            Ok(None)
        ));
    }

    /// Test the normal workflow of an application process being created, attached, and removed.
    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_android_application_workflow() {
        let mut state_machine = StateMachine::new();

        assert!(matches!(
            state_machine.process_event(StateMachineEvent::Bpf(bpf::Event::CgroupMkdir {
                path: cgroup_dir(APPLICATION_UID, PID),
            })),
            Ok(None)
        ));

        assert!(matches!(
            state_machine.process_event(StateMachineEvent::Bpf(bpf::Event::CgroupAttach {
                path: cgroup_dir(APPLICATION_UID, PID),
                pid: PID,
            })),
            Ok(Some(CgroupEvent::Create {
                uid: APPLICATION_UID,
                pid: PID
            }))
        ));

        assert!(matches!(
            state_machine.process_event(StateMachineEvent::Bpf(bpf::Event::SchedExit {
                uid: APPLICATION_UID,
                pid: PID,
            })),
            Ok(Some(CgroupEvent::Remove {
                uid: APPLICATION_UID,
                pid: PID
            }))
        ));

        assert!(matches!(
            state_machine.process_event(StateMachineEvent::Bpf(bpf::Event::CgroupRmdir {
                path: cgroup_dir(APPLICATION_UID, PID),
            })),
            Ok(None)
        ));
    }

    /// Test that attempting to create two cgroups with the same uid and pid combination is idempotent
    #[tokio::test]
    async fn test_multiple_same_cgroup_id() {
        let mut state_machine = StateMachine::new();

        assert!(matches!(
            state_machine.process_event(StateMachineEvent::Bpf(bpf::Event::CgroupMkdir {
                path: cgroup_dir(APPLICATION_UID, PID),
            })),
            Ok(None)
        ));

        assert!(matches!(
            state_machine.process_event(StateMachineEvent::Bpf(bpf::Event::CgroupMkdir {
                path: cgroup_dir(APPLICATION_UID, PID),
            })),
            Ok(None)
        ));
    }

    /// Test that attempting to attach the process to the same cgroup is idempotent
    #[tokio::test]
    async fn test_multiple_same_pid() {
        let mut state_machine = StateMachine::new();

        assert!(matches!(
            state_machine.process_event(StateMachineEvent::Bpf(bpf::Event::CgroupMkdir {
                path: cgroup_dir(SYSTEM_UID, PID),
            })),
            Ok(None)
        ));

        assert!(matches!(
            state_machine.process_event(StateMachineEvent::Bpf(bpf::Event::CgroupAttach {
                path: cgroup_dir(SYSTEM_UID, PID),
                pid: PID,
            })),
            Ok(None)
        ));

        assert!(matches!(
            state_machine.process_event(StateMachineEvent::Bpf(bpf::Event::CgroupAttach {
                path: cgroup_dir(SYSTEM_UID, PID),
                pid: PID,
            })),
            Ok(None)
        ));
    }

    /// Test that attempting to attach the process to an non-existent cgroup passes (for cgroupv1 events)
    #[tokio::test]
    async fn test_attach_to_non_existent_cgroup() {
        let mut state_machine = StateMachine::new();

        assert!(matches!(
            state_machine.process_event(StateMachineEvent::Bpf(bpf::Event::CgroupAttach {
                path: cgroup_dir(SYSTEM_UID, PID),
                pid: PID,
            })),
            Ok(None)
        ));
    }

    /// Test that removing a cgroup with an attach process generate the remove event
    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_remove_cgroup_with_attached_processes() {
        let mut state_machine = StateMachine::new();

        assert!(matches!(
            state_machine.process_event(StateMachineEvent::Bpf(bpf::Event::CgroupMkdir {
                path: cgroup_dir(APPLICATION_UID, PID),
            })),
            Ok(None)
        ));

        assert!(matches!(
            state_machine.process_event(StateMachineEvent::Bpf(bpf::Event::CgroupAttach {
                path: cgroup_dir(APPLICATION_UID, PID),
                pid: PID,
            })),
            Ok(Some(CgroupEvent::Create {
                uid: APPLICATION_UID,
                pid: PID
            }))
        ));

        assert!(matches!(
            state_machine.process_event(StateMachineEvent::Bpf(bpf::Event::CgroupRmdir {
                path: cgroup_dir(APPLICATION_UID, PID),
            })),
            Ok(Some(CgroupEvent::Remove {
                uid: APPLICATION_UID,
                pid: PID
            }))
        ));

        assert!(matches!(
            state_machine.process_event(StateMachineEvent::Bpf(bpf::Event::SchedExit {
                uid: APPLICATION_UID,
                pid: PID
            })),
            Ok(None)
        ));
    }

    /// Test that exec process with without a cgroup generates no event
    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_exec_process_with_non_existent_cgroup() {
        let mut state_machine = StateMachine::new();

        assert!(matches!(
            state_machine.process_event(StateMachineEvent::Bpf(bpf::Event::SchedExec {
                uid: APPLICATION_UID,
                pid: PID,
            })),
            Ok(None)
        ));
    }

    /// Test that removing a process with no cgroup generates no event
    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_remove_non_existent_process() {
        let mut state_machine = StateMachine::new();

        assert!(matches!(
            state_machine.process_event(StateMachineEvent::Bpf(bpf::Event::SchedExit {
                uid: APPLICATION_UID,
                pid: PID,
            })),
            Ok(None)
        ));
    }
}
