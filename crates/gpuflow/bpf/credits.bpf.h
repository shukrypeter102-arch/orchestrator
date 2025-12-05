// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
// Copyright (C) 2025 Meta Platforms, Inc. and affiliates. All rights reserved.
#pragma once

/* constants and struct definitions that readers and writers of
 * eattribution bpf maps may need */

#ifdef __cplusplus
namespace android::bpf {
#endif

/* maps will be named after components in this set */
#define BPF_COMPONENT_GPU_NAME "gpu"

enum { PWRLEVELS = 16 };

/* provides fields necessary to provide PowerStats residency
providers, but be mindful of units */
typedef struct {
    uint64_t totalTimeInStateNs;
    uint64_t totalStateEntryCount;
    uint64_t lastEntryTimestampNs;
} BpfStateResidency;

#define kMaxPids 32768

typedef struct {
    uint32_t gpu_id;
    uint32_t uid;
    uint32_t pid;
} PidGpuIdUid;

typedef struct {
    uint64_t nsAtLevel[PWRLEVELS + 1];  // pwr -> accrued in ns
} NsPerPwrLevel;

#ifdef __cplusplus
}
#endif
