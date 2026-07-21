# Shared IPv4-family wire math — the single build-level home for src/wire
# (RFC 1071 Internet checksum, RFC 792 ICMP echo body). Linked by the harness,
# tc8-dut, the testability server library and the unit tests so no target names
# the source by path (the former pattern left ip_checksum.cpp listed in four
# CMakeLists and tempted in-tree checksum copies). Pure byte math — no syscalls,
# no third-party deps — so it cross-compiles and the lwIP DUT port can link it.
#
# The install/EXPORT interface (INSTALL_INTERFACE include root + install(TARGETS))
# is wired once in the top-level TC8_UTM_INSTALL block, which owns the whole
# exported SDK surface; this file owns only the build.
add_library(tc8_wire STATIC
    ip_checksum.cpp
    icmp_echo.cpp
)
# Every header tc8_wire exposes, and every header its .cpp compile against, lives
# under include/tc8/wire/ (RFC 1071 checksum, RFC 792 echo body, the read/format
# helpers) — all namespaced. So include/ is the sole PUBLIC include root; this
# target reaches nothing through the flat src/ tree.
target_include_directories(tc8_wire PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
)
tc8_enable_strict_warnings(tc8_wire)
