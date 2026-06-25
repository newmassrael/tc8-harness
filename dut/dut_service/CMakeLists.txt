# The AUTOSAR testability endpoint. Ports & adapters, split into two archives so
# a non-POSIX consumer (an out-of-tree lwIP UTM) can link the protocol core
# WITHOUT the POSIX adapter — the core has no socket syscalls, only the
# SocketBackend seam:
#
#   tc8_testability_core   — the platform-agnostic protocol core
#                            (src/testability/protocol_server.cpp). Depends only
#                            on tc8_wire + Threads and the SocketBackend seam.
#   tc8_posix_backend      — the POSIX SocketBackend adapter (posix_socket_backend).
#   tc8_testability_server — INTERFACE convenience alias = core + POSIX backend,
#                            preserving the historical target name so existing
#                            consumers (tc8-dut, tc8-utm, the unit tests, and the
#                            utm-sdk export) link one name and still get both.
#
# Built once as libraries so the DUT service, the standalone tc8-utm, and the
# unit tests all link the same translation units. The lwIP DUT fixture compiles
# the SAME core (protocol_server.cpp) against its own adapter
# (dut/lwip_dut/lwip_socket_backend) — one source of truth for the protocol
# logic across both platforms.
find_package(Threads REQUIRED)

add_library(tc8_testability_core STATIC
    ${PROJECT_SOURCE_DIR}/src/testability/protocol_server.cpp
)
target_include_directories(tc8_testability_core PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)
# The ICMP ECHO_REQUEST primitive frames its packet via the shared wire layer
# (RFC 1071 checksum + RFC 792 echo body); PUBLIC so consumers inherit tc8_wire
# transitively rather than each naming the source. Threads is PUBLIC too: the
# ProtocolServer and the MiddlewareModule executors use std::thread, so an
# out-of-tree consumer linking the core gets -pthread.
target_link_libraries(tc8_testability_core PUBLIC tc8_wire Threads::Threads)

# The POSIX adapter implements the seam declared by the core's headers and frames
# ICMP via tc8_wire; it does not call into the ProtocolServer. Link the core so
# the seam's typeinfo/headers resolve and a consumer linking only the backend
# still gets the core transitively.
add_library(tc8_posix_backend STATIC
    posix_socket_backend.cpp
)
target_include_directories(tc8_posix_backend PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)
target_link_libraries(tc8_posix_backend PUBLIC tc8_testability_core)

add_library(tc8_testability_server INTERFACE)
target_link_libraries(tc8_testability_server INTERFACE
    tc8_testability_core tc8_posix_backend)

# The TC8 Upper Tester server, built once as a library so the DUT service and
# the unit test link the same translation units. Ports & adapters: the
# platform-agnostic core (src/upper_tester/) plus the POSIX StackProbe adapter.
# The socket primitives come from tc8::net::SocketBackend (PosixSocketBackend in
# tc8_posix_backend), so consumers link that too. The lwIP DUT fixture
# compiles the same core against its own adapters — a single source of truth for
# the UT protocol logic across both platforms.
add_library(tc8_upper_tester_server STATIC
    ${PROJECT_SOURCE_DIR}/src/upper_tester/ut_server.cpp
    posix_stack_probe.cpp
)
target_include_directories(tc8_upper_tester_server PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}
)

add_executable(tc8-dut
    client_mode.cpp
    client_mode_proxy.cpp
    dhcpv4_client.cpp
    dut_main.cpp
    ets_impl.cpp
    ets_impl_2.cpp
    linklocal_autoconf.cpp
    posix_ut_extensions.cpp
)
target_include_directories(tc8-dut PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src
)
# tc8-dut is excluded from the full strict-warning set (its vsomeip /
# CommonAPI generated sources trip -Wall noise), but the firmware
# fault-injection dispatch relies on switch-no-default exhaustiveness to
# force every new Dhcpv4ClientFlavor / LinklocalAutoconfFlavor to declare
# its per-builder disposition. Promote ONLY -Wswitch to an error so a
# missing flavor branch fails the build (a silently-ignored flavor is a
# Phase F coverage hole) without pulling in the broader -Wall cascade.
target_compile_options(tc8-dut PRIVATE -Werror=switch)
target_link_options(tc8-dut PRIVATE -Wl,--no-as-needed)
target_link_libraries(tc8-dut PRIVATE ets ets2 ets3 tc8_testability_server tc8_upper_tester_server)
