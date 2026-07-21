# The AUTOSAR testability endpoint, structured as ports & adapters so a non-POSIX
# consumer (an out-of-tree lwIP UTM) links the protocol core WITHOUT the POSIX
# adapter, and neither adapter depends on the application:
#
#   tc8_testability_ports  — header-only INTERFACE: the interfaces the core owns
#                            and adapters implement (net::SocketBackend +
#                            testability::SocketBackend + the Reactor's
#                            IoMultiplexer/Waker). No archive, just the seam.
#   tc8_testability_core   — the platform-agnostic protocol core
#                            (src/testability/protocol_server.cpp). Depends on the
#                            ports + tc8_wire + Threads. No socket syscalls.
#   tc8_posix_backend      — the POSIX adapter (posix_socket_backend). Depends on
#                            the ports + tc8_wire — NOT on the core.
#   tc8_testability_server — INTERFACE convenience union = core + POSIX adapter,
#                            under one name (consumers may equally link the two).
#
# Built once as libraries so the DUT service, the standalone tc8-utm, and the
# unit tests all link the same translation units. The lwIP DUT fixture compiles
# the SAME core (protocol_server.cpp) against its own adapter
# (dut/lwip_dut/lwip_socket_backend) — one source of truth for the protocol
# logic across both platforms.
find_package(Threads REQUIRED)

# The ports (the seam). Both the core and every adapter depend on THIS, never on
# each other's implementation — that is the ports-and-adapters direction.
add_library(tc8_testability_ports INTERFACE)
target_include_directories(tc8_testability_ports INTERFACE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
)
# The POSIX adapter's posix_socket_backend.cpp includes tc8/net/raw_packet_socket.h
# and the DUT firmware includes tc8/someip/...; both are now namespaced under the
# public include/tc8/ root the ports target already exposes, so no extra seam.

add_library(tc8_testability_core STATIC
    ${PROJECT_SOURCE_DIR}/src/testability/protocol_server.cpp
)
# tc8_wire: the ICMP ECHO_REQUEST primitive frames via the shared wire layer
# (RFC 1071 checksum + RFC 792 echo body). Threads: the ProtocolServer and the
# MiddlewareModule executors use std::thread, so a consumer linking the core gets
# -pthread. All PUBLIC so an out-of-tree consumer inherits them transitively.
target_link_libraries(tc8_testability_core PUBLIC
    tc8_testability_ports tc8_wire Threads::Threads)
# vsomeip-free first-party core — gets the full strict set (unlike tc8-dut, whose
# CommonAPI/vsomeip generated sources force its exclusion). The ports & adapters
# split exists precisely so this protocol logic carries no third-party noise.
tc8_enable_strict_warnings(tc8_testability_core)

# The POSIX adapter implements the testability port and frames ICMP via tc8_wire;
# it does NOT call into the ProtocolServer, so it depends on the ports + tc8_wire,
# never on the core. Its own dir is PUBLIC so consumers find posix_socket_backend.h.
add_library(tc8_posix_backend STATIC
    posix_socket_backend.cpp
)
# Its header is public API and lives at include/tc8/posix_socket_backend.h, so the
# public root is what consumers need; this dir no longer carries a public header.
target_include_directories(tc8_posix_backend PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
)
target_link_libraries(tc8_posix_backend PUBLIC tc8_testability_ports tc8_wire)
tc8_enable_strict_warnings(tc8_posix_backend)

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
    # This lib owns the upper_tester/ core headers (ut_server.h, stack_probe.h),
    # moved out of the flat src/ tree; consumers (tc8-dut, ut_server_test) inherit
    # this root by linking, so upper_tester/*.h resolves only through the owner.
    ${PROJECT_SOURCE_DIR}/src/upper_tester/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)
tc8_enable_strict_warnings(tc8_upper_tester_server)

# ─────────────────────────────────────────────────────────────────────────────
# Everything ABOVE is the vendor-neutral UTM: no vsomeip, no CommonAPI, no ETS.
# It is what the tc8-utm SDK exports, so it builds unconditionally — see dut/
# CMakeLists.txt for why the layers are split.
#
# Everything BELOW is the ETS mock DUT executable, which links the ets/ targets
# (CommonAPI-generated, vsomeip-backed) and therefore only exists when
# TC8_BUILD_MOCK_DUT is on. The guard sits here rather than around this whole file
# precisely because the file spans both layers.
# ─────────────────────────────────────────────────────────────────────────────
if(NOT TC8_BUILD_MOCK_DUT)
    return()
endif()

# OEM override seams (compile-time source-selection — same idiom as
# TC8_ETS_FIDL / TC8_CASE_OVERRIDE_DIRS, so the repo has ONE injection
# philosophy, no link-time weak-symbol tricks). An OEM points these at its own
# translation units: TC8_ETS_FACTORY_SRC must define createEtsStub() (returning
# its EtsImpl subclass); TC8_ETS_EXTENSION_SRC must define createEtsExtension().
# Its two optional companions for an out-of-tree extension that needs more than a
# lone source — TC8_ETS_EXTENSION_LIBS (extra link libraries) and
# TC8_ETS_EXTENSION_INCLUDE_DIRS (extra include paths) — are applied to tc8-dut
# below; both unset by default, leaving the public DUT byte-identical.
# `if(NOT DEFINED)` guards a superproject's plain set() under CMP0126 OLD.
if(NOT DEFINED TC8_ETS_FACTORY_SRC)
    set(TC8_ETS_FACTORY_SRC "${CMAKE_CURRENT_SOURCE_DIR}/ets_factory.cpp")
endif()
if(NOT DEFINED TC8_ETS_EXTENSION_SRC)
    set(TC8_ETS_EXTENSION_SRC "${CMAKE_CURRENT_SOURCE_DIR}/ets_extension.cpp")
endif()
foreach(_src TC8_ETS_FACTORY_SRC TC8_ETS_EXTENSION_SRC)
    if(NOT EXISTS "${${_src}}")
        message(FATAL_ERROR "${_src} points at a missing file: ${${_src}}")
    endif()
endforeach()

add_executable(tc8-dut
    client_mode.cpp
    client_mode_proxy.cpp
    client_only_app.cpp
    dhcpv4_client.cpp
    dut_main.cpp
    ets2_impl.cpp
    ets_client_control.cpp
    ets_control_channel.cpp
    ets_emission.cpp
    ets_event_sink.cpp
    ets_impl.cpp
    linklocal_autoconf.cpp
    posix_ut_extensions.cpp
    server_role.cpp
    ${TC8_ETS_FACTORY_SRC}
    ${TC8_ETS_EXTENSION_SRC}
)
target_include_directories(tc8-dut PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    # The DUT's own dir, so an out-of-directory TC8_ETS_EXTENSION_SRC /
    # TC8_ETS_FACTORY_SRC slot file (e.g. examples/demo_ets_extension) can
    # #include "ets_extension.h" / "ets_event_sink.h" / "ets_factory.h". The
    # in-tree default sources resolve these via the same-directory rule; an
    # out-of-dir OEM slot file needs this path on -I.
    ${CMAKE_CURRENT_SOURCE_DIR}
)
# OEM extension include-path companion of TC8_ETS_EXTENSION_SRC: lets the
# extension TU reach a shared OEM header tree (e.g. conformance/) so the DUT and
# tester can include ONE constants header instead of hand-mirroring it across the
# cross-build boundary. Unset => no extra path => the public DUT include set is
# byte-identical.
if(TC8_ETS_EXTENSION_INCLUDE_DIRS)
    target_include_directories(tc8-dut PRIVATE ${TC8_ETS_EXTENSION_INCLUDE_DIRS})
endif()
# Firmware fault-injection coverage guarantee, kept UNCONDITIONAL (independent of
# TC8_WARNINGS_AS_ERRORS): switch-no-default exhaustiveness forces every new
# Dhcpv4ClientFlavor / LinklocalAutoconfFlavor to declare its per-builder
# disposition, since a silently-ignored flavor is a Phase F coverage hole. This
# must fail the build even in a warnings-only configuration.
target_compile_options(tc8-dut PRIVATE -Werror=switch)
# Full strict first-party set (flag-gated -Werror). vsomeip / CommonAPI / generated
# CommonAPI sources are -isystem (demoted at find_package), so only the DUT's OWN
# translation units are gated — no third-party -Wall noise. The DUT was formerly
# excluded entirely; the -isystem demotion is what makes the gate possible here.
tc8_enable_strict_warnings(tc8-dut)
target_link_options(tc8-dut PRIVATE -Wl,--no-as-needed)
target_link_libraries(tc8-dut PRIVATE ets ets2 ets3 tc8_testability_server tc8_upper_tester_server)
# OEM extension link companion of TC8_ETS_EXTENSION_SRC: lets the extension TU
# declare its own link dependencies (e.g. tc8_e2e for an AUTOSAR E2E Profile 5/11
# checker) without baking an extension-only library into the public DUT target.
# Each entry is a normal CMake target / archive, so it contributes nothing unless
# the extension references it. Unset => the link set is byte-identical to the
# public DUT.
if(TC8_ETS_EXTENSION_LIBS)
    target_link_libraries(tc8-dut PRIVATE ${TC8_ETS_EXTENSION_LIBS})
endif()
