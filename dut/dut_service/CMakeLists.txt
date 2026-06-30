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
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
)

add_library(tc8_testability_core STATIC
    ${PROJECT_SOURCE_DIR}/src/testability/protocol_server.cpp
)
# tc8_wire: the ICMP ECHO_REQUEST primitive frames via the shared wire layer
# (RFC 1071 checksum + RFC 792 echo body). Threads: the ProtocolServer and the
# MiddlewareModule executors use std::thread, so a consumer linking the core gets
# -pthread. All PUBLIC so an out-of-tree consumer inherits them transitively.
target_link_libraries(tc8_testability_core PUBLIC
    tc8_testability_ports tc8_wire Threads::Threads)

# The POSIX adapter implements the testability port and frames ICMP via tc8_wire;
# it does NOT call into the ProtocolServer, so it depends on the ports + tc8_wire,
# never on the core. Its own dir is PUBLIC so consumers find posix_socket_backend.h.
add_library(tc8_posix_backend STATIC
    posix_socket_backend.cpp
)
target_include_directories(tc8_posix_backend PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)
target_link_libraries(tc8_posix_backend PUBLIC tc8_testability_ports tc8_wire)

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

# OEM override seams (compile-time source-selection — same idiom as
# TC8_ETS_FIDL / TC8_CASE_OVERRIDE_DIRS, so the repo has ONE injection
# philosophy, no link-time weak-symbol tricks). An OEM points these at its own
# translation units: TC8_ETS_FACTORY_SRC must define createEtsStub() (returning
# its EtsImpl subclass); TC8_ETS_EXTENSION_SRC must define createEtsExtension().
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
    dhcpv4_client.cpp
    dut_main.cpp
    ets2_impl.cpp
    ets_client_control.cpp
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
    ${PROJECT_SOURCE_DIR}/src
    # The DUT's own dir, so an out-of-directory TC8_ETS_EXTENSION_SRC /
    # TC8_ETS_FACTORY_SRC slot file (e.g. examples/demo_ets_extension) can
    # #include "ets_extension.h" / "ets_event_sink.h" / "ets_factory.h". The
    # in-tree default sources resolve these via the same-directory rule; an
    # out-of-dir OEM slot file needs this path on -I.
    ${CMAKE_CURRENT_SOURCE_DIR}
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
