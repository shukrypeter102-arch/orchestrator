# eBPF Skeleton Generator for Memflow

## Project Overview

This build tool generates Rust skeleton code from eBPF C programs, specifically for the Memflow service's cgroup monitoring functionality. The primary goal is to enable seamless integration between eBPF kernel programs and Rust userspace applications by automatically generating type-safe Rust bindings.

## What This Project Does

### Core Functionality
- **eBPF Program Compilation**: Compiles `cgroup.bpf.c` into eBPF bytecode using the Android toolchain
- **Skeleton Generation**: Creates Rust bindings (`cgroup_skel.rs`) that provide type-safe access to eBPF maps, programs, and events
- **Cgroup Monitoring**: The generated skeleton enables monitoring of cgroup filesystem events (creation/deletion) in real-time

### Build Process Architecture
1. **Source Input**: Takes `../bpf/cgroup.bpf.c` as the eBPF source
2. **Compilation**: Uses Android's prebuilt clang compiler with specific vmlinux headers
3. **Skeleton Generation**: Leverages `libbpf-cargo` to create Rust bindings
4. **Output**: Generates `../src/cgroup_skel.rs` with type-safe Rust interfaces

## How to Use

### Prerequisites
Ensure you have the correct Rust toolchain that matches the soong build system:

```bash
$ rustup install 1.75.0
$ rustup default 1.75.0
```

### Regenerating Skeleton Code
Whenever the `bpf/cgroup.bpf.c` file is updated, regenerate the skeleton:

```bash
$ cargo run
```

This will:
1. Compile the eBPF C code using the Android clang toolchain
2. Generate updated Rust bindings in `../src/cgroup_skel.rs`
3. Ensure compatibility with the Android 5.10 kernel and ARM64 architecture

### Version Control
After regeneration, commit the updated `cgroup_skel.rs` file to version control to ensure all developers have consistent bindings.

## Technical Details

### Compiler Configuration
- **Clang Path**: Uses Android's prebuilt clang compiler (`clang-r487747c`)
- **Include Path**: References Android 5.10 ARM64 vmlinux headers

## Long-term Vision

### Soong Integration
The ultimate goal is to eliminate this manual build process by:
- Building `libbpf-cargo` as a host tool in the Android build system
- Creating soong build rules that automatically regenerate skeletons
- Implementing proper dependency tracking between eBPF and Rust code

### Crate Vendoring
Once Meta has streamlined crate vendoring processes, this workaround can be replaced with a more integrated solution that:
- Automatically manages eBPF compilation dependencies
- Provides consistent toolchain management across projects
- Enables seamless integration with existing Android build infrastructure

This temporary solution effectively bridges the gap between eBPF kernel programming and Rust userspace development while maintaining compatibility with Meta's Android build environment.
