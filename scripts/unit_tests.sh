#!/bin/bash
# Copyright (C) 2025 Meta Platforms, Inc. and affiliates. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

if [ -z "$ANDROID_PRODUCT_OUT" ]; then
  echo "Must run from lunch-ed enviroment"
  exit 1
fi

echo "[orchestrator] - Pushing unit tests to device"
adb push $ANDROID_PRODUCT_OUT/data/nativetest/orchestrator_common_tests/orchestrator_common_tests /data/local/tmp/
adb push $ANDROID_PRODUCT_OUT/data/nativetest/cpuflow_tests/cpuflow_tests /data/local/tmp/
adb push $ANDROID_PRODUCT_OUT/data/nativetest/gpuflow_tests/gpuflow_tests /data/local/tmp/
adb push $ANDROID_PRODUCT_OUT/data/nativetest/memflow_tests/memflow_tests /data/local/tmp/

echo "[orchestrator] - Running unit tests on device"
adb shell /data/local/tmp/orchestrator_common_tests "$@"; rc1=$?
adb shell /data/local/tmp/cpuflow_tests "$@"; rc2=$?
adb shell /data/local/tmp/gpuflow_tests "$@"; rc3=$?
adb shell /data/local/tmp/memflow_tests "$@"; rc4=$?
echo "[orchestrator] - Testing completed"

if [ $rc1 -ne 0 ] || [ $rc2 -ne 0 ] || [ $rc3 -ne 0 ] || [ $rc4 -ne 0 ]; then
  echo "ONE OR MORE FAILURES DETECTED"
else
  echo "ALL TESTS PASSED"
fi
