# tc8-lwip-dut / tc8-lwip-utm — lwIP unix-port binaries for the fixture.
#
# Builds two executables against an lwIP checkout (master or any release with
# the unix contrib port):
#   * tc8-lwip-dut — the conformance DUT fixture for --topology external
#     (stack + opcode Upper Tester + AUTOSAR Testability endpoint).
#   * tc8-lwip-utm — the standalone, OEM-deployable AUTOSAR Testability UTM
#     (stack + testability endpoint only). The lwIP analog of dut/utm (tc8-utm).
#
#   cmake -S dut/lwip_dut -B build-lwip-dut -DLWIP_DIR=/path/to/lwip
#   cmake --build build-lwip-dut -j4
#
# The lwIP core is compiled HERE, against dut/lwip_dut/lwipopts.h, so
# the stack configuration is owned by this directory and cannot drift
# from what the binary links (compiling the app against one lwipopts.h
# while linking a core built under another silently breaks struct
# layouts).
cmake_minimum_required(VERSION 3.16)
project(tc8-lwip-dut C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT LWIP_DIR)
    set(LWIP_DIR "$ENV{LWIP_DIR}")
endif()
if(NOT LWIP_DIR OR NOT EXISTS "${LWIP_DIR}/src/Filelists.cmake")
    message(FATAL_ERROR
        "LWIP_DIR must point at an lwIP checkout (src/ + contrib/). "
        "Example: git clone https://github.com/lwip-tcpip/lwip.git && "
        "cmake -DLWIP_DIR=/path/to/lwip ...")
endif()
set(LWIP_CONTRIB_DIR "${LWIP_DIR}/contrib")

include(${LWIP_CONTRIB_DIR}/ports/CMakeCommon.cmake)
# Upstream HEAD periodically trips its own -Werror (e.g. unused-parameter
# in sockets.c); this fixture builds a pristine checkout, so warnings
# must stay warnings.
list(REMOVE_ITEM LWIP_COMPILER_FLAGS "-Werror")

# This directory comes first so the fixture's lwipopts.h wins the
# bare-name include for every lwIP translation unit.
set(LWIP_INCLUDE_DIRS
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${LWIP_DIR}/src/include"
    "${LWIP_CONTRIB_DIR}/"
    "${LWIP_CONTRIB_DIR}/ports/unix/port/include"
    # tc8_lwip_hooks.h pulls tcp_isn.h into every core TU via
    # LWIP_HOOK_FILENAME, so the core build needs this path too.
    "${LWIP_CONTRIB_DIR}/addons/tcp_isn"
)

include(${LWIP_DIR}/src/Filelists.cmake)
include(${LWIP_CONTRIB_DIR}/ports/unix/Filelists.cmake)

# Sources shared by every lwIP app binary built here: the platform-agnostic
# AUTOSAR Testability protocol core (shared verbatim with the Linux tc8-dut) +
# this fixture's lwIP SocketBackend adapter, the shared stack bring-up, the
# syscall-free tc8::wire helpers, and the lwIP C addons the unix port needs.
# Compiled straight into each executable — they cannot reach the main tree's
# library targets. Each binary's main() owns its tc8::testability::ProtocolServer
# directly (exactly as the Linux dut_main / utm_main do), so there is no façade
# translation unit. The opcode Upper Tester core (src/upper_tester/ut_server.cpp)
# is deliberately NOT here: it is the conformance fixture's harness-specific
# channel, carried only by tc8-lwip-dut (with its lwIP StackProbe + ARP
# extension), not by the UTM.
set(_tc8_lwip_common_srcs
    lwip_stack_bringup.cpp
    lwip_socket_backend.cpp
    # Fixture fault seams installed by lwip_stack_bringup (inert until armed): the
    # generic egress field-fault hook (OpSetEgressFlavor) and the ingress
    # reaction-fault hook (OpSetIngressFlavor — ARP emission §4.2.4.2 + UDP acceptance
    # §4.6.5.4). Both link into both binaries via the bring-up TU.
    lwip_egress_fault.cpp
    lwip_ingress_fault.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/testability/protocol_server.cpp
    # tc8::wire (icmp echo body + ip checksum): syscall-free, shared with the
    # harness/Linux tc8-dut.
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/wire/ip_checksum.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/wire/icmp_echo.cpp
    ${LWIP_CONTRIB_DIR}/ports/unix/example_app/default_netif.c
    # RFC 6528 ISN generator wired through LWIP_HOOK_TCP_ISN (lwipopts.h).
    ${LWIP_CONTRIB_DIR}/addons/tcp_isn/tcp_isn.c
    ${LWIP_DIR}/src/netif/ppp/polarssl/md5.c
)

# tcp_isn.c hashes with the PPP-bundled polarssl MD5, whose implementation is
# guarded by `#if PPP_SUPPORT && LWIP_INCLUDED_POLARSSL_MD5`
# (src/netif/ppp/polarssl/md5.c). Force both guards on for that single TU — via
# per-file COMPILE_DEFINITIONS, so the define is confined to md5.c and never
# reaches the lwipopts.h every other TU consumes (PPP stays off everywhere else;
# no PPP source is in the build). This is lwIP's documented idiom for using the
# tcp_isn addon without PPP: the proper long-term fix is decoupling tcp_isn's
# MD5 from the PPP tree upstream, deferred with the rest of the lwIP upstream
# work (P5). The alternative — vendoring a standalone MD5 here — is more
# invasive and would diverge the DUT crypto from the shipped stack, so the
# scoped define is the deliberate choice, not an unexamined hack. Source-file
# properties are directory-scoped, so this applies to md5.c in both binaries.
set_source_files_properties(${LWIP_DIR}/src/netif/ppp/polarssl/md5.c
    PROPERTIES COMPILE_DEFINITIONS "PPP_SUPPORT=1;LWIP_INCLUDED_POLARSSL_MD5=1")

# The unix-port flag set (LWIP_COMPILER_FLAGS) is C-oriented and applies three
# diagnostics ungated that are invalid — or pure noise — on these executables'
# C++ TUs (the apps, the shared testability + Upper Tester cores, the lwIP
# adapters and the bring-up). A trailing -Wno-* cannot fix -Wmissing-prototypes:
# GCC warns the moment it parses the positive flag ("valid for C/ObjC but not for
# C++"), before any later -Wno-. So strip the three ungated entries and re-add the two
# without a surviving C-guarded form, scoped to the C TUs — the lwIP .c sources
# compiled into these executables (default_netif.c, tcp_isn.c, md5.c) stay
# strict while the C++ TUs build clean. The lwIP core/contrib libraries are
# built by their own Filelists targets and are unaffected.
#   * -Waggregate-return — fires on every value-returned std::vector / map
#     operator[] / pair; GCC documents it as not useful for C++.
#   * -Wmissing-prototypes — the set lists it both ungated and C-guarded; only
#     the ungated entry reaches C++. Dropping it leaves the C-guarded form.
#   * -Wswitch-default — conflicts with the deliberate no-default,
#     -Wswitch-exhaustive enum switch (wireTcpState) that surfaces an upstream
#     state addition instead of masking it with a default.
set(_tc8_lwip_flags ${LWIP_COMPILER_FLAGS})
list(REMOVE_ITEM _tc8_lwip_flags
    -Wmissing-prototypes -Waggregate-return -Wswitch-default)

# Define one lwIP app executable: the shared core above plus the binary-specific
# sources in ARGN, with the include dirs / compile flags / definitions / link
# libraries every lwIP unix-port binary in this fixture needs.
function(tc8_lwip_app name)
    add_executable(${name} ${ARGN} ${_tc8_lwip_common_srcs})
    target_include_directories(${name} PRIVATE
        ${LWIP_INCLUDE_DIRS}
        # tc8/upper_tester_protocol.h + tc8/testability_protocol.h — single
        # source of truth for the UT + testability wire protocols, shared with
        # the harness and the Linux tc8-dut.
        "${CMAKE_CURRENT_SOURCE_DIR}/../../include"
        # wire/icmp_echo.h + wire/ip_checksum.h (tc8::wire), included as
        # "wire/...": the source root is the include root.
        "${CMAKE_CURRENT_SOURCE_DIR}/../../src"
    )
    target_compile_options(${name} PRIVATE
        ${_tc8_lwip_flags}
        $<$<COMPILE_LANGUAGE:C>:-Waggregate-return>
        $<$<COMPILE_LANGUAGE:C>:-Wswitch-default>
    )
    target_compile_definitions(${name} PRIVATE ${LWIP_DEFINITIONS})
    target_link_libraries(${name} ${LWIP_SANITIZER_LIBS} lwipcontribportunix lwipcore)
endfunction()

# The conformance DUT fixture: stack + opcode Upper Tester + testability. The
# Upper Tester runs on the platform-agnostic core (src/upper_tester/ut_server.cpp,
# shared verbatim with the Linux tc8-dut) paired with this fixture's lwIP adapters
# (lwip_stack_probe = TCP-info / original-dst introspection) and the lwIP-only ARP
# cache-conditioning opcode (lwip_ut_extensions). lwip_socket_backend (in the
# common srcs) supplies the socket primitives for both the UT and testability.
tc8_lwip_app(tc8-lwip-dut
    tc8_lwip_dut.cpp
    lwip_stack_probe.cpp
    lwip_ut_extensions.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/upper_tester/ut_server.cpp)

# The vendor-neutral AUTOSAR engines (src/autosar/) — pure byte math, the same
# sources the POSIX build compiles via tc8_add_engine. Globbed (CONFIGURE_DEPENDS)
# so a new engine joins the lwIP build with no second source list to keep in sync,
# and compiled into the UTM (not the conformance DUT) because they are the
# mechanisms an OEM middleware module on the lwIP UTM composes. Building them here
# proves the engines compile under the embedded lwIP toolchain, not only the host.
file(GLOB _tc8_autosar_engine_srcs CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/autosar/*.cpp)

# The standalone, OEM-deployable AUTOSAR Testability UTM: stack + testability
# endpoint only (no opcode UT). The lwIP analog of dut/utm (tc8-utm).
tc8_lwip_app(tc8-lwip-utm lwip_utm_main.cpp ${_tc8_autosar_engine_srcs})

# In-process runtime test for the middleware rx reactor on the lwIP backend (the
# lwIP IoMultiplexer: lwip_select poll() + the 127.0.0.1 socket-pair Waker). Runs
# entirely over the loopback netif — no tap/netns/root — so it exercises the one
# lwIP-specific path the host POSIX tests cannot. Registered as a CTest with a
# hard timeout so a regression that hangs the reactor fails fast. Needs no AUTOSAR
# engines (it tests the reactor, not the engines).
enable_testing()
tc8_lwip_app(tc8-lwip-reactor-test lwip_reactor_test.cpp)
add_test(NAME lwip_reactor_test COMMAND tc8-lwip-reactor-test)
set_tests_properties(lwip_reactor_test PROPERTIES TIMEOUT 30)
