# Cross toolchain: aarch64 (ARM64) embedded-Linux tester targets.
#
# Usage (portability check — no target sysroot needed):
#   cmake -S . -B build-aarch64 \
#         -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/aarch64-linux-gnu.cmake \
#         -DTC8_PORTABILITY_CHECK=ON
#   cmake --build build-aarch64
#
# Full tc8-harness / tc8-dut cross builds additionally need an arm64
# sysroot carrying libpcap, libtins, boost, vsomeip, and CommonAPI —
# point CMAKE_SYSROOT / CMAKE_FIND_ROOT_PATH at it and drop the
# portability-check flag. See README "Cross-building for embedded
# testers".

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(CMAKE_C_COMPILER   aarch64-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER aarch64-linux-gnu-g++)

# Search programs on the host, libraries/headers only in the target
# root — the standard cross-compilation find policy.
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
