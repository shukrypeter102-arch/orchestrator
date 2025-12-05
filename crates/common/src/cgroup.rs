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

use std::borrow::Cow;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Ok;
use async_trait::async_trait;
use log::warn;
use tokio::fs::File;
use tokio::fs::OpenOptions;
use tokio::io::AsyncReadExt as _;
use tokio::io::AsyncSeekExt as _;
use tokio::io::AsyncWriteExt as _;
use tokio::io::SeekFrom;
use tokio::sync::Mutex;

use crate::stats;

/// The maximum value for memory limits in cgroup v2
const MAX_MEMORY: &str = "max";

/// Represents the different cgroup v2 controller types that can be enabled in a cgroup hierarchy.
///
/// Each controller provides specific resource management capabilities:
/// - **CPU**: Manages CPU time distribution and limits
/// - **CPUSet**: Controls which CPUs and memory nodes are available to processes
/// - **Memory**: Manages memory usage, limits, and reclaim behavior
/// - **IO**: Controls block device I/O bandwidth and IOPS limits
/// - **PIDs**: Limits the number of processes and threads in a cgroup
/// - **RDMA**: Manages Remote Direct Memory Access resources
/// - **HugeTLB**: Controls huge page memory allocation
///
/// For more information about cgroup v2 controllers, see the
/// [Linux kernel documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html).
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum CgroupControllerType {
    /// CPU controller for managing CPU time distribution and limits
    Cpu,
    /// CPUSet controller for managing CPU and memory node affinity
    Cpuset,
    /// Memory controller for managing memory usage and limits
    Memory,
    /// IO controller for managing block device I/O bandwidth and IOPS
    Io,
    /// PIDs controller for limiting the number of processes and threads
    Pids,
    /// RDMA controller for managing Remote Direct Memory Access resources
    Rdma,
    /// HugeTLB controller for managing huge page memory allocation
    HugeTlb,
}

/// A trait that provides an interface to interact with a cgroup
///
/// This trait mirrors the cgroupv2 memory controller interface, which allows for
/// reading and writing memory limits and statistics. For more information, see
/// the [cgroup-v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html).
///
/// The memory controller provides the following files:
/// - `memory.max`: Hard memory usage limit
/// - `memory.high`: Soft memory usage limit (triggers reclaim)
/// - `memory.min`: Memory protection (not reclaimed under memory pressure)
/// - `memory.low`: Best-effort memory protection
/// - `memory.pressure`: Memory pressure information
/// - `memory.current`: Current memory usage
#[async_trait]
#[mockall::automock]
pub trait CgroupEntry {
    /// Returns an array of controllers that are supported by this cgroup.
    ///
    /// This function reads the available cgroup controllers from the `cgroup.controllers` file
    /// and returns them as a fixed-size array to reduce memory allocations compared to using Vec.
    /// The array has a fixed size of 7 elements to accommodate all known controller types.
    ///
    /// # Returns
    ///
    /// A `Result` containing an array of `Option<CgroupControllerType>`. Each element is:
    /// - `Some(controller)` if the corresponding controller is available
    /// - `None` if no controller is available at that position
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use your_crate::{CgroupEntry, FileSystemCgroup, CgroupControllerType};
    /// # #[tokio::main]
    /// # async fn main() -> anyhow::Result<()> {
    /// let cgroup = FileSystemCgroup::base_path();
    /// let controllers = cgroup.controllers().await?;
    ///
    /// // Check if memory controller is available
    /// if controllers
    ///     .iter()
    ///     .any(|c| c == &Some(CgroupControllerType::Memory))
    /// {
    ///     println!("Memory controller is available");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    async fn controllers(&self) -> anyhow::Result<[Option<CgroupControllerType>; 7]>;
    /// Reads memory stats (memory.stats)
    async fn memory_stats(&self) -> anyhow::Result<stats::MemoryStats>;
    /// Reads memory events (memory.events)
    async fn memory_events(&self) -> anyhow::Result<stats::MemoryEvents>;
    /// Reads the hard memory usage limit (memory.max)
    async fn memory_max(&self) -> anyhow::Result<u64>;
    /// Reads the soft memory usage limit (memory.high)
    async fn memory_high(&self) -> anyhow::Result<u64>;
    /// Reads the guaranteed memory protection limit (memory.min)
    async fn memory_min(&self) -> anyhow::Result<u64>;
    /// Reads the best-effort memory protection limit (memory.low)
    async fn memory_low(&self) -> anyhow::Result<u64>;
    /// Reads memory pressure information
    async fn memory_pressure(&self) -> anyhow::Result<stats::Readout>;
    /// Reads the current memory usage
    async fn memory_current(&self) -> anyhow::Result<u64>;
    /// Reads the current swap memory usage
    async fn memory_swap_current(&self) -> anyhow::Result<u64>;
    /// Reads cpu pressure information
    async fn cpu_pressure(&self) -> anyhow::Result<stats::PartialReadout>;
    /// Reads io pressure information
    async fn io_pressure(&self) -> anyhow::Result<stats::Readout>;
    /// Sets the hard memory usage limit (memory.max)
    async fn write_memory_max(&self, value: u64) -> anyhow::Result<()>;
    /// Sets the soft memory usage limit (memory.high)
    async fn write_memory_high(&self, value: u64) -> anyhow::Result<()>;
    /// Sets the memory protection limit (memory.min)
    async fn write_memory_min(&self, value: u64) -> anyhow::Result<()>;
    /// Sets the best-effort memory protection limit (memory.low)
    async fn write_memory_low(&self, value: u64) -> anyhow::Result<()>;
}

/// A macro that retrieves or opens a file with read-only permissions from a cache.
///
/// This macro implements lazy file opening - it first checks if a file descriptor already
/// exists in the cache for the specified field. If it exists, it returns the cached file
/// descriptor. If not, it opens the file at the given path with read permissions,
/// caches it, and returns the file descriptor.
///
/// The path expression is only evaluated when the file needs to be opened for the first time,
/// providing performance benefits when the file is already cached.
///
/// # Arguments
/// * `$cache_field` - A mutable reference to the cache field containing optional file descriptor
/// * `$path` - The file path expression (only evaluated if file needs to be opened)
///
/// # Returns
/// A mutable reference to the file descriptor
///
/// # Errors
/// Returns an error if the file cannot be opened with read-write permissions
macro_rules! get_or_open_ro_file {
    ($cache_field:expr, $path:expr) => {
        match &mut $cache_field {
            Some(file_descriptor) => {
                file_descriptor.seek(SeekFrom::Start(0)).await?;
                file_descriptor
            }
            None => {
                let file_descriptor = File::open($path).await?;
                $cache_field = Some(file_descriptor);
                $cache_field.as_mut().unwrap()
            }
        }
    };
}

/// A macro that retrieves or opens a file with read-write permissions from a cache.
///
/// This macro implements lazy file opening - it first checks if a file descriptor already
/// exists in the cache for the specified field. If it exists, it returns the cached file
/// descriptor. If not, it opens the file at the given path with read and write permissions,
/// caches it, and returns the file descriptor.
///
/// The path expression is only evaluated when the file needs to be opened for the first time,
/// providing performance benefits when the file is already cached.
///
/// # Arguments
/// * `$cache_field` - A mutable reference to the cache field containing optional file descriptor
/// * `$path` - The file path expression (only evaluated if file needs to be opened)
/// * `$reclaim_type` - Optional ReclaimType parameter to control O_NONBLOCK flag usage
///
/// # Returns
/// A mutable reference to the file descriptor
///
/// # Errors
/// Returns an error if the file cannot be opened with read-write permissions
macro_rules! get_or_open_rw_file {
    ($cache_field:expr, $path:expr) => {
        match &mut $cache_field {
            Some(file_descriptor) => {
                file_descriptor.seek(SeekFrom::Start(0)).await?;
                file_descriptor
            }
            None => {
                let file_descriptor = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open($path)
                    .await?;
                $cache_field = Some(file_descriptor);
                $cache_field.as_mut().unwrap()
            }
        }
    };
    ($cache_field:expr, $path:expr, $reclaim_type:expr) => {
        match &mut $cache_field {
            Some(file_descriptor) => {
                file_descriptor.seek(SeekFrom::Start(0)).await?;
                file_descriptor
            }
            None => {
                let mut options = OpenOptions::new();
                options.read(true).write(true);

                if matches!($reclaim_type, ReclaimType::Asynchronous) {
                    options.custom_flags(libc::O_NONBLOCK);
                }

                let file_descriptor = options.open($path).await?;
                $cache_field = Some(file_descriptor);
                $cache_field.as_mut().unwrap()
            }
        }
    };
}

#[derive(Default)]
struct FileCache {
    memory_stats: Option<File>,
    memory_events: Option<File>,
    memory_max: Option<File>,
    memory_high: Option<File>,
    memory_min: Option<File>,
    memory_low: Option<File>,
    cpu_pressure: Option<File>,
    io_pressure: Option<File>,
    memory_pressure: Option<File>,
    memory_current: Option<File>,
    memory_swap_current: Option<File>,
}

/// Specifies the reclaim behavior for the cgroup when writing to memory limit files.
///
/// This enum controls whether `memory.high` and `memory.max` files are opened with the
/// `O_NONBLOCK` flag, which fundamentally changes how memory reclaim and OOM handling behave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReclaimType {
    /// The cgroup will open `memory.high` and `memory.max` files without the `O_NONBLOCK` flag.
    ///
    /// **Behavior:**
    /// - Memory reclaim operations are performed synchronously when limits are exceeded
    /// - CPU time spent on reclaim is attributed to the current process making the limit change
    /// - For `memory.max`: OOM killer may be invoked if memory usage cannot be reduced
    /// - For `memory.high`: processes are throttled and put under heavy reclaim pressure
    ///
    /// **Use case:** Suitable for direct memory management where the calling process can
    /// afford to spend CPU cycles on immediate reclaim operations.
    Synchronous,

    /// The cgroup will open `memory.high` and `memory.max` files with the `O_NONBLOCK` flag.
    ///
    /// **Behavior:**
    /// - Synchronous reclaim and OOM-kill are bypassed during the limit setting operation
    /// - The target cgroup will handle reclaim/OOM on its next memory charge request
    /// - CPU time for reclaim is attributed to the processes in the target cgroup, not the caller
    ///
    /// **Benefits:**
    /// - Useful for admin processes that need to dynamically adjust memory limits without
    ///   expending their own CPU resources on memory reclamation
    /// - Allows for non-blocking limit adjustments in monitoring/control scenarios
    ///
    /// **Caveats:**
    /// - The target cgroup may take an indefinite amount of time to reduce usage below
    ///   the new limit due to delayed charge requests or memory access patterns
    /// - No immediate guarantee that the limit will be enforced right away
    Asynchronous,
}

/// A filesystem-based implementation of the CgroupEntry trait. Used in production for writing to
/// the sysfs cgroupv2 hierarchy.
pub struct FileSystemCgroup {
    path: PathBuf,
    file_cache: Arc<Mutex<FileCache>>,
    reclaim: ReclaimType,
}

impl FileSystemCgroup {
    /// Creates a new FileSystemCgroup instance for a specific user ID and process ID.
    ///
    /// This constructs a path to the cgroup in the cgroupv2 hierarchy for the given UID and PID.
    /// Note: This function does not verify if the cgroup actually exists on the system.
    ///
    /// # Arguments
    /// * `uid` - User ID
    /// * `pid` - Process ID
    ///
    /// # Returns
    /// A new FileSystemCgroup instance with the path set to `/sys/fs/cgroup/uid_{uid}/pid_{pid}`
    pub fn from_uid_and_pid(uid: u32, pid: u32) -> Self {
        Self {
            path: PathBuf::from(format!("/sys/fs/cgroup/uid_{uid}/pid_{pid}")),
            file_cache: Arc::new(Mutex::new(FileCache::default())),
            reclaim: ReclaimType::Synchronous,
        }
    }

    /// Creates a new FileSystemCgroup instance for a specific user ID and process ID and reclaim type.
    ///
    /// This constructs a path to the cgroup in the cgroupv2 hierarchy for the given UID and PID.
    /// Note: This function does not verify if the cgroup actually exists on the system.
    ///
    /// # Arguments
    /// * `uid` - User ID
    /// * `pid` - Process ID
    /// * `reclaim` - The type of reclaim behavior to use for the cgroup.
    ///
    /// # Returns
    /// A new FileSystemCgroup instance with the path set to `/sys/fs/cgroup/uid_{uid}/pid_{pid}`
    pub fn from_uid_and_pid_with_reclaim(uid: u32, pid: u32, reclaim: ReclaimType) -> Self {
        Self {
            path: PathBuf::from(format!("/sys/fs/cgroup/uid_{uid}/pid_{pid}")),
            file_cache: Arc::new(Mutex::new(FileCache::default())),
            reclaim,
        }
    }

    /// Creates a new FileSystemCgroup instance for a specific user ID.
    ///
    /// This constructs a path to the cgroup in the cgroupv2 hierarchy for the given UID.
    /// Note: This function does not verify if the cgroup actually exists on the system.
    ///
    /// # Arguments
    /// * `uid` - User ID
    ///
    /// # Returns
    /// A new FileSystemCgroup instance with the path set to `/sys/fs/cgroup/uid_{uid}`
    pub fn from_uid(uid: u32) -> Self {
        Self {
            path: PathBuf::from(format!("/sys/fs/cgroup/uid_{uid}")),
            file_cache: Arc::new(Mutex::new(FileCache::default())),
            reclaim: ReclaimType::Synchronous,
        }
    }

    // Creates a new FileSystemCgroup instance for the base cgroup
    // # Returns
    // A new FileSystemCgroup instance with the path set to `/sys/fs/cgroup`
    pub fn base_path() -> Self {
        Self {
            path: PathBuf::from("/sys/fs/cgroup"),
            file_cache: Arc::new(Mutex::new(FileCache::default())),
            reclaim: ReclaimType::Synchronous,
        }
    }

    #[cfg(test)]
    pub fn from_path(path: &std::path::Path) -> Self {
        Self {
            path: PathBuf::from(path),
            file_cache: Arc::new(Mutex::new(FileCache::default())),
            reclaim: ReclaimType::Synchronous,
        }
    }
}

#[async_trait]
impl CgroupEntry for FileSystemCgroup {
    async fn controllers(&self) -> anyhow::Result<[Option<CgroupControllerType>; 7]> {
        let content = tokio::fs::read_to_string(self.path.join("cgroup.controllers")).await?;
        let mut result = [None; 7];
        let mut index = 0;

        for controller_name in content.split_whitespace() {
            let controller = match controller_name {
                "cpu" => Some(CgroupControllerType::Cpu),
                "cpuset" => Some(CgroupControllerType::Cpuset),
                "memory" => Some(CgroupControllerType::Memory),
                "io" => Some(CgroupControllerType::Io),
                "pids" => Some(CgroupControllerType::Pids),
                "rdma" => Some(CgroupControllerType::Rdma),
                "hugetlb" => Some(CgroupControllerType::HugeTlb),
                _ => {
                    warn!("Unknown controller: {controller_name}");
                    None
                }
            };

            if controller.is_some() {
                match result.get_mut(index) {
                    Some(slot) => *slot = controller,
                    None => break,
                }
                index += 1;
            }
        }

        Ok(result)
    }

    async fn memory_stats(&self) -> anyhow::Result<stats::MemoryStats> {
        let mut cache = self.file_cache.lock().await;

        let file_descriptor =
            get_or_open_ro_file!(cache.memory_stats, self.path.join("memory.stat"));

        let mut content = String::new();
        file_descriptor.read_to_string(&mut content).await?;

        let memory_stats = content
            .parse::<stats::MemoryStats>()
            .map_err(|_| anyhow::anyhow!("Failed to parse memory stat data"))?;
        Ok(memory_stats)
    }

    async fn memory_events(&self) -> anyhow::Result<stats::MemoryEvents> {
        let mut cache = self.file_cache.lock().await;

        let file_descriptor =
            get_or_open_ro_file!(cache.memory_events, self.path.join("memory.events"));

        let mut content = String::new();
        file_descriptor.read_to_string(&mut content).await?;

        let memory_events = content
            .parse::<stats::MemoryEvents>()
            .map_err(|_| anyhow::anyhow!("Failed to parse memory events data"))?;
        Ok(memory_events)
    }

    async fn memory_max(&self) -> anyhow::Result<u64> {
        let mut cache = self.file_cache.lock().await;

        let file_descriptor =
            get_or_open_rw_file!(cache.memory_max, self.path.join("memory.max"), self.reclaim);

        let mut content = String::new();
        file_descriptor.read_to_string(&mut content).await?;

        let value = content.trim();
        if value == MAX_MEMORY {
            return Ok(u64::MAX);
        } else {
            Ok(value.parse::<u64>()?)
        }
    }

    async fn memory_high(&self) -> anyhow::Result<u64> {
        let mut cache = self.file_cache.lock().await;

        let file_descriptor = get_or_open_rw_file!(
            cache.memory_high,
            self.path.join("memory.high"),
            self.reclaim
        );

        let mut content = String::new();
        file_descriptor.read_to_string(&mut content).await?;

        let value = content.trim();
        if value == MAX_MEMORY {
            return Ok(u64::MAX);
        } else {
            Ok(value.parse::<u64>()?)
        }
    }

    async fn memory_min(&self) -> anyhow::Result<u64> {
        let mut cache = self.file_cache.lock().await;

        let file_descriptor = get_or_open_rw_file!(cache.memory_min, self.path.join("memory.min"));

        let mut content = String::new();
        file_descriptor.read_to_string(&mut content).await?;

        let value = content.trim().parse::<u64>()?;
        Ok(value)
    }

    async fn memory_low(&self) -> anyhow::Result<u64> {
        let mut cache = self.file_cache.lock().await;

        let file_descriptor = get_or_open_rw_file!(cache.memory_low, self.path.join("memory.low"));

        let mut content = String::new();
        file_descriptor.read_to_string(&mut content).await?;

        let value = content.trim().parse::<u64>()?;
        Ok(value)
    }

    async fn cpu_pressure(&self) -> anyhow::Result<stats::PartialReadout> {
        let mut cache = self.file_cache.lock().await;

        let file_descriptor =
            get_or_open_ro_file!(cache.cpu_pressure, self.path.join("cpu.pressure"));

        let mut content = String::new();
        file_descriptor.read_to_string(&mut content).await?;

        let readout = content
            .parse::<stats::PartialReadout>()
            .map_err(|_| anyhow::anyhow!("Failed to parse cpu pressure data"))?;
        Ok(readout)
    }

    async fn io_pressure(&self) -> anyhow::Result<stats::Readout> {
        let mut cache = self.file_cache.lock().await;

        let file_descriptor =
            get_or_open_ro_file!(cache.io_pressure, self.path.join("io.pressure"));

        let mut content = String::new();
        file_descriptor.read_to_string(&mut content).await?;

        let readout = content
            .parse::<stats::Readout>()
            .map_err(|_| anyhow::anyhow!("Failed to parse io pressure data"))?;
        Ok(readout)
    }

    async fn memory_pressure(&self) -> anyhow::Result<stats::Readout> {
        let mut cache = self.file_cache.lock().await;

        let file_descriptor =
            get_or_open_ro_file!(cache.memory_pressure, self.path.join("memory.pressure"));

        let mut content = String::new();
        file_descriptor.read_to_string(&mut content).await?;

        let readout = content
            .parse::<stats::Readout>()
            .map_err(|_| anyhow::anyhow!("Failed to parse memory pressure data"))?;
        Ok(readout)
    }

    async fn memory_current(&self) -> anyhow::Result<u64> {
        let mut cache = self.file_cache.lock().await;

        let file_descriptor =
            get_or_open_ro_file!(cache.memory_current, self.path.join("memory.current"));

        let mut content = String::new();
        file_descriptor.read_to_string(&mut content).await?;

        let value = content.trim().parse::<u64>()?;
        Ok(value)
    }

    async fn memory_swap_current(&self) -> anyhow::Result<u64> {
        let mut cache = self.file_cache.lock().await;

        let file_descriptor = get_or_open_ro_file!(
            cache.memory_swap_current,
            self.path.join("memory.swap.current")
        );

        let mut content = String::new();
        file_descriptor.read_to_string(&mut content).await?;

        let value = content.trim().parse::<u64>()?;
        Ok(value)
    }

    async fn write_memory_max(&self, value: u64) -> anyhow::Result<()> {
        let serialize_value = if value == u64::MAX {
            Cow::Borrowed(MAX_MEMORY)
        } else {
            Cow::Owned(value.to_string())
        };

        let mut cache = self.file_cache.lock().await;

        let file_descriptor =
            get_or_open_rw_file!(cache.memory_max, self.path.join("memory.max"), self.reclaim);

        file_descriptor
            .write_all(serialize_value.as_bytes())
            .await?;

        Ok(())
    }

    async fn write_memory_high(&self, value: u64) -> anyhow::Result<()> {
        let serialize_value = if value == u64::MAX {
            Cow::Borrowed(MAX_MEMORY)
        } else {
            Cow::Owned(value.to_string())
        };

        let mut cache = self.file_cache.lock().await;

        let file_descriptor = get_or_open_rw_file!(
            cache.memory_high,
            self.path.join("memory.high"),
            self.reclaim
        );

        file_descriptor
            .write_all(serialize_value.as_bytes())
            .await?;

        Ok(())
    }

    async fn write_memory_min(&self, value: u64) -> anyhow::Result<()> {
        let mut cache = self.file_cache.lock().await;

        let serialize_value = value.to_string();

        let file_descriptor = get_or_open_rw_file!(cache.memory_min, self.path.join("memory.min"));

        file_descriptor
            .write_all(serialize_value.as_bytes())
            .await?;

        Ok(())
    }

    async fn write_memory_low(&self, value: u64) -> anyhow::Result<()> {
        let mut cache = self.file_cache.lock().await;

        let serialize_value = value.to_string();

        let file_descriptor = get_or_open_rw_file!(cache.memory_low, self.path.join("memory.low"));

        file_descriptor
            .write_all(serialize_value.as_bytes())
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use nativetestutils::frl_test;

    use super::CgroupControllerType;
    use super::CgroupEntry;
    use super::FileSystemCgroup;
    use super::MAX_MEMORY;

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_from_uid_and_pid() {
        let uid = 1000;
        let pid = 12345;
        let cgroup = FileSystemCgroup::from_uid_and_pid(uid, pid);
        let expected_path = PathBuf::from(format!("/sys/fs/cgroup/uid_1000/pid_12345"));
        assert_eq!(cgroup.path, expected_path);
    }

    #[frl_test(TestSuite = "MemflowTestSuite")]
    fn test_from_uid() {
        let uid = 1000;
        let cgroup = FileSystemCgroup::from_uid(uid);
        let expected_path = PathBuf::from(format!("/sys/fs/cgroup/uid_1000"));
        assert_eq!(cgroup.path, expected_path);
    }

    // Tests that the controllers() function correctly reads and parses the cgroup.controllers file
    #[tokio::test]
    async fn test_controllers() {
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path();

        // Create cgroup.controllers file with all controller types
        std::fs::write(
            temp_path.join("cgroup.controllers"),
            "cpu cpuset memory io pids rdma hugetlb",
        )
        .expect("Could not write to mock cgroup.controllers file");

        let cgroup = FileSystemCgroup::from_path(temp_path);
        let controllers = cgroup.controllers().await.unwrap();

        assert_eq!(controllers[0], Some(CgroupControllerType::Cpu));
        assert_eq!(controllers[1], Some(CgroupControllerType::Cpuset));
        assert_eq!(controllers[2], Some(CgroupControllerType::Memory));
        assert_eq!(controllers[3], Some(CgroupControllerType::Io));
        assert_eq!(controllers[4], Some(CgroupControllerType::Pids));
        assert_eq!(controllers[5], Some(CgroupControllerType::Rdma));
        assert_eq!(controllers[6], Some(CgroupControllerType::HugeTlb));
    }

    // Tests that the controllers() function handles partial controller lists
    #[tokio::test]
    async fn test_controllers_partial() {
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path();

        // Create cgroup.controllers file with only some controllers
        std::fs::write(temp_path.join("cgroup.controllers"), "cpu memory")
            .expect("Could not write to mock cgroup.controllers file");

        let cgroup = FileSystemCgroup::from_path(temp_path);
        let controllers = cgroup.controllers().await.unwrap();

        assert_eq!(controllers[0], Some(CgroupControllerType::Cpu));
        assert_eq!(controllers[1], Some(CgroupControllerType::Memory));
        assert_eq!(controllers[2], None);
        assert_eq!(controllers[3], None);
    }

    // Tests that memory_current() correctly reads the current memory usage
    #[tokio::test]
    async fn test_memory_current() {
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path();

        std::fs::write(temp_path.join("memory.current"), "1234567890")
            .expect("Could not write to mock memory.current file");

        let cgroup = FileSystemCgroup::from_path(temp_path);
        let memory_current = cgroup.memory_current().await.unwrap();

        assert_eq!(memory_current, 1234567890);

        // Update the file content
        std::fs::write(temp_dir.path().join("memory.current"), "2000000")
            .expect("Could not write to mock memory.current file");

        // Second read should see the updated value (cache seeks to start)
        let second_read = cgroup.memory_current().await.unwrap();
        assert_eq!(second_read, 2000000);
    }

    // Tests that memory_min() correctly reads the memory protection limit
    #[tokio::test]
    async fn test_memory_min_read() {
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path();

        std::fs::write(temp_path.join("memory.min"), "1073741824")
            .expect("Could not write to mock memory.min file");

        let cgroup = FileSystemCgroup::from_path(temp_path);
        let memory_min = cgroup.memory_min().await.unwrap();

        assert_eq!(memory_min, 1073741824);

        // Update the file content
        std::fs::write(temp_path.join("memory.min"), "2342342")
            .expect("Could not write to mock memory.min file");

        // Second read should see the updated value (cache seeks to start)
        let second_read = cgroup.memory_min().await.unwrap();
        assert_eq!(second_read, 2342342);
    }

    // Tests that write_memory_min() correctly writes numeric values
    #[tokio::test]
    async fn test_write_memory_min() {
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path();

        std::fs::write(temp_path.join("memory.min"), "0")
            .expect("Could not write to mock memory.min file");

        let cgroup = FileSystemCgroup::from_path(temp_path);

        cgroup.write_memory_min(134217728).await.unwrap();

        // Sleep to allow the file to be written to disk. In production we write to
        // sysfs so we do not need the flush().
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let content = std::fs::read_to_string(temp_path.join("memory.min"))
            .expect("Could not read memory.min file");
        assert_eq!(content.trim(), "134217728");

        cgroup.write_memory_min(268435456).await.unwrap();

        // Sleep to allow the file to be written to disk. In production we write to
        // sysfs so we do not need the flush().
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let content = std::fs::read_to_string(temp_path.join("memory.min"))
            .expect("Could not read memory.min file");
        assert_eq!(content.trim(), "268435456");
    }

    // Tests that memory_low() correctly reads the best-effort memory protection limit
    #[tokio::test]
    async fn test_memory_low_read() {
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path();

        std::fs::write(temp_path.join("memory.low"), "2147483648")
            .expect("Could not write to mock memory.low file");

        let cgroup = FileSystemCgroup::from_path(temp_path);
        let memory_low = cgroup.memory_low().await.unwrap();

        assert_eq!(memory_low, 2147483648);

        // Update the file content
        std::fs::write(temp_path.join("memory.low"), "98243590")
            .expect("Could not write to mock memory.low file");

        // Second read should see the updated value (cache seeks to start)
        let second_read = cgroup.memory_low().await.unwrap();
        assert_eq!(second_read, 98243590);
    }

    // Tests that write_memory_low() correctly writes numeric values
    #[tokio::test]
    async fn test_write_memory_low() {
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path();

        std::fs::write(temp_path.join("memory.low"), "0")
            .expect("Could not write to mock memory.low file");

        let cgroup = FileSystemCgroup::from_path(temp_path);

        cgroup.write_memory_low(268435456).await.unwrap();

        // Sleep to allow the file to be written to disk. In production we write to
        // sysfs so we do not need the flush().
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let content = std::fs::read_to_string(temp_path.join("memory.low"))
            .expect("Could not read memory.low file");
        assert_eq!(content.trim(), "268435456");

        cgroup.write_memory_low(536870912).await.unwrap();

        // Sleep to allow the file to be written to disk. In production we write to
        // sysfs so we do not need the flush().
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let content = std::fs::read_to_string(temp_path.join("memory.low"))
            .expect("Could not read memory.low file");
        assert_eq!(content.trim(), "536870912");
    }

    // Tests that memory_high() correctly reads MAX_MEMORY value
    #[tokio::test]
    async fn test_memory_high_read_max() {
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path();

        std::fs::write(temp_path.join("memory.high"), MAX_MEMORY)
            .expect("Could not write to mock memory.max file");

        let cgroup = FileSystemCgroup::from_path(temp_path);
        let memory_high = cgroup.memory_high().await.unwrap();

        assert_eq!(memory_high, u64::MAX);
    }

    // Tests that memory_high() correctly reads numeric values
    #[tokio::test]
    async fn test_memory_high_read_numeric() {
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path();

        std::fs::write(temp_path.join("memory.high"), "4294967296")
            .expect("Could not write to mock memory.high file");

        let cgroup = FileSystemCgroup::from_path(temp_path);
        let memory_high = cgroup.memory_high().await.unwrap();

        assert_eq!(memory_high, 4294967296);

        // Update the file content
        std::fs::write(temp_path.join("memory.high"), "2394802304")
            .expect("Could not write to mock memory.high file");

        // Second read should see the updated value (cache seeks to start)
        let second_read = cgroup.memory_high().await.unwrap();
        assert_eq!(second_read, 2394802304);
    }

    // Tests that write_memory_high() correctly writes numeric values
    #[tokio::test]
    async fn test_write_memory_high_numeric() {
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path();

        std::fs::write(temp_path.join("memory.high"), "0")
            .expect("Could not write to mock memory.high file");

        let cgroup = FileSystemCgroup::from_path(temp_path);

        cgroup.write_memory_high(536870912).await.unwrap();

        // Sleep to allow the file to be written to disk. In production we write to
        // sysfs so we do not need the flush().
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let content = std::fs::read_to_string(temp_path.join("memory.high"))
            .expect("Could not read memory.high file");
        assert_eq!(content.trim(), "536870912");

        cgroup.write_memory_high(1073741824).await.unwrap();

        // Sleep to allow the file to be written to disk. In production we write to
        // sysfs so we do not need the flush().
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Sleep to allow the file to be written to disk. In production we write to
        // sysfs so we do not need the flush().
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let content = std::fs::read_to_string(temp_path.join("memory.high"))
            .expect("Could not read memory.high file");
        assert_eq!(content.trim(), "1073741824");
    }

    // Tests that write_memory_high() correctly writes MAX_MEMORY
    #[tokio::test]
    async fn test_write_memory_high_max() {
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path();

        std::fs::write(temp_path.join("memory.high"), "0")
            .expect("Could not write to mock memory.high file");

        let cgroup = FileSystemCgroup::from_path(temp_path);

        cgroup.write_memory_high(u64::MAX).await.unwrap();

        // Sleep to allow the file to be written to disk. In production we write to
        // sysfs so we do not need the flush().
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let content = std::fs::read_to_string(temp_path.join("memory.high"))
            .expect("Could not read memory.high file");
        assert_eq!(content.trim(), MAX_MEMORY);
    }

    // Tests that memory_max() correctly reads MAX_MEMORY value
    #[tokio::test]
    async fn test_memory_max_read_max() {
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path();

        std::fs::write(temp_path.join("memory.max"), MAX_MEMORY)
            .expect("Could not write to mock memory.max file");

        let cgroup = FileSystemCgroup::from_path(temp_path);
        let memory_max = cgroup.memory_max().await.unwrap();

        assert_eq!(memory_max, u64::MAX);
    }

    // Tests that memory_max() correctly reads numeric values
    #[tokio::test]
    async fn test_memory_max_read_numeric() {
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path();

        std::fs::write(temp_path.join("memory.max"), "79823423")
            .expect("Could not write to mock memory.max file");

        let cgroup = FileSystemCgroup::from_path(temp_path);
        let memory_max = cgroup.memory_max().await.unwrap();

        assert_eq!(memory_max, 79823423);

        // Update the file content
        std::fs::write(temp_path.join("memory.max"), "23098423")
            .expect("Could not write to mock memory.max file");

        // Second read should see the updated value (cache seeks to start)
        let second_read = cgroup.memory_max().await.unwrap();
        assert_eq!(second_read, 23098423);
    }

    // Tests that write_memory_max() correctly writes numeric values
    #[tokio::test]
    async fn test_write_memory_max_numeric() {
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path();

        std::fs::write(temp_path.join("memory.max"), "0")
            .expect("Could not write to mock memory.max file");

        let cgroup = FileSystemCgroup::from_path(temp_path);

        cgroup.write_memory_max(1073741824).await.unwrap();

        // Sleep to allow the file to be written to disk. In production we write to
        // sysfs so we do not need the flush().
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let content = std::fs::read_to_string(temp_path.join("memory.max"))
            .expect("Could not read memory.max file");
        assert_eq!(content.trim(), "1073741824");

        cgroup.write_memory_max(2147483648).await.unwrap();

        // Sleep to allow the file to be written to disk. In production we write to
        // sysfs so we do not need the flush().
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let content = std::fs::read_to_string(temp_path.join("memory.max"))
            .expect("Could not read memory.max file");
        assert_eq!(content.trim(), "2147483648");
    }

    // Tests that write_memory_max() correctly writes MAX_MEMORY
    #[tokio::test]
    async fn test_write_memory_max_max() {
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path();

        std::fs::write(temp_path.join("memory.max"), "0")
            .expect("Could not write to mock memory.max file");

        let cgroup = FileSystemCgroup::from_path(temp_path);

        cgroup.write_memory_max(u64::MAX).await.unwrap();

        // Sleep to allow the file to be written to disk. In production we write to
        // sysfs so we do not need the flush().
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let content = std::fs::read_to_string(temp_path.join("memory.max"))
            .expect("Could not read memory.max file");
        assert_eq!(content.trim(), MAX_MEMORY);
    }

    // Tests that memory_swap_current() correctly reads the current swap usage
    #[tokio::test]
    async fn test_memory_swap_current() {
        let temp_dir = tempfile::tempdir().unwrap();
        let temp_path = temp_dir.path();

        let cgroup = FileSystemCgroup::from_path(temp_path);

        std::fs::write(temp_path.join("memory.swap.current"), "9876543210")
            .expect("Could not write to mock memory.swap.current file");

        let memory_swap = cgroup.memory_swap_current().await.unwrap();
        assert_eq!(memory_swap, 9876543210);

        std::fs::write(temp_path.join("memory.swap.current"), "234234")
            .expect("Could not write to mock memory.swap.current file");

        let memory_swap = cgroup.memory_swap_current().await.unwrap();
        assert_eq!(memory_swap, 234234);
    }
}
