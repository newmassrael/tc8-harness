# tc8-lwip-dut — lwIP unix-port DUT fixture for --topology external.
#
# Standalone build against an lwIP checkout (master or any release with
# the unix contrib port):
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

add_executable(tc8-lwip-dut
    tc8_lwip_dut.cpp
    lwip_ut_server.cpp
    lwip_testability_server.cpp
    # AUTOSAR Testability endpoint wire-math, syscall-free and shared with the
    # harness/Linux tc8-dut (tc8::wire). Compiled straight into this standalone
    # fixture build — it cannot reach the main tree's tc8_wire CMake target.
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/wire/ip_checksum.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/wire/icmp_echo.cpp
    ${LWIP_CONTRIB_DIR}/ports/unix/example_app/default_netif.c
    # RFC 6528 ISN generator wired through LWIP_HOOK_TCP_ISN (lwipopts.h).
    ${LWIP_CONTRIB_DIR}/addons/tcp_isn/tcp_isn.c
    ${LWIP_DIR}/src/netif/ppp/polarssl/md5.c
)
# tcp_isn.c hashes with the PPP-bundled polarssl MD5, whose
# implementation is guarded by `#if PPP_SUPPORT && LWIP_INCLUDED_POLARSSL_MD5`
# (src/netif/ppp/polarssl/md5.c). Force both guards on for that single
# TU — via per-file COMPILE_DEFINITIONS, so the define is confined to
# md5.c and never reaches the lwipopts.h every other TU consumes (PPP
# stays off everywhere else; no PPP source is in the build). This is
# lwIP's documented idiom for using the tcp_isn addon without PPP: the
# proper long-term fix is decoupling tcp_isn's MD5 from the PPP tree
# upstream, deferred with the rest of the lwIP upstream work (P5). The
# alternative — vendoring a standalone MD5 here — is more invasive and
# would diverge the DUT crypto from the shipped stack, so the scoped
# define is the deliberate choice, not an unexamined hack.
set_source_files_properties(${LWIP_DIR}/src/netif/ppp/polarssl/md5.c
    PROPERTIES COMPILE_DEFINITIONS "PPP_SUPPORT=1;LWIP_INCLUDED_POLARSSL_MD5=1")
target_include_directories(tc8-lwip-dut PRIVATE
    ${LWIP_INCLUDE_DIRS}
    # tc8/upper_tester_protocol.h + tc8/testability_protocol.h — single
    # source of truth for the UT + testability wire protocols, shared with
    # the harness and the Linux tc8-dut.
    "${CMAKE_CURRENT_SOURCE_DIR}/../../include"
    # wire/icmp_echo.h + wire/ip_checksum.h (tc8::wire), included as
    # "wire/...": the source root is the include root.
    "${CMAKE_CURRENT_SOURCE_DIR}/../../src"
)
# The unix-port flag set (LWIP_COMPILER_FLAGS) is C-oriented and applies three
# diagnostics ungated that are invalid — or pure noise — on this executable's
# C++ TUs (the application + the lwip_ut_server / lwip_testability_server
# mirrors). A trailing -Wno-* cannot fix -Wmissing-prototypes: GCC warns the
# moment it parses the positive flag ("valid for C/ObjC but not for C++"),
# before any later -Wno-. So strip the three ungated entries and re-add the two
# without a surviving C-guarded form, scoped to the C TUs — the lwIP .c sources
# compiled into this executable (default_netif.c, tcp_isn.c, md5.c) stay strict
# while the C++ TUs build clean. The lwIP core/contrib libraries are built by
# their own Filelists targets and are unaffected.
#   * -Waggregate-return — fires on every value-returned std::vector / map
#     operator[] / pair; GCC documents it as not useful for C++.
#   * -Wmissing-prototypes — the set lists it both ungated and C-guarded; only
#     the ungated entry reaches C++. Dropping it leaves the C-guarded form.
#   * -Wswitch-default — conflicts with the deliberate no-default,
#     -Wswitch-exhaustive enum switch (wireTcpState) that surfaces an upstream
#     state addition instead of masking it with a default.
set(_tc8_lwip_dut_flags ${LWIP_COMPILER_FLAGS})
list(REMOVE_ITEM _tc8_lwip_dut_flags
    -Wmissing-prototypes -Waggregate-return -Wswitch-default)
target_compile_options(tc8-lwip-dut PRIVATE
    ${_tc8_lwip_dut_flags}
    $<$<COMPILE_LANGUAGE:C>:-Waggregate-return>
    $<$<COMPILE_LANGUAGE:C>:-Wswitch-default>
)
target_compile_definitions(tc8-lwip-dut PRIVATE ${LWIP_DEFINITIONS})
target_link_libraries(tc8-lwip-dut ${LWIP_SANITIZER_LIBS} lwipcontribportunix lwipcore)
