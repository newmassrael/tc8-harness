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
    # The conformance DUT's tc8_lwip_hooks.h pulls the contrib tcp_isn.h into the DUT
    # core's TUs via LWIP_HOOK_FILENAME, so the DUT core build needs this path. The
    # UTM core uses tc8_lwip_utm_hooks.h (tc8 AES-CMAC) and does not need it — the
    # path is harmless on the UTM core's include list and absent from the SDK export.
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
    # The fixture fault seams (lwip_egress_fault / lwip_ingress_fault) are NOT
    # here: they are conformance-DUT only and are carried by tc8-lwip-dut's own
    # SRCS, not by the bring-up TU. Keeping them out of the shared set is what
    # makes the UTM (and the exported utm-sdk-lwip bring-up) genuinely fault-free
    # — tc8-lwip-utm building without them proves the bring-up has no fault dep.
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/testability/protocol_server.cpp
    # tc8::wire (icmp echo body + ip checksum): syscall-free, shared with the
    # harness/Linux tc8-dut.
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/wire/ip_checksum.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/wire/icmp_echo.cpp
    ${LWIP_CONTRIB_DIR}/ports/unix/example_app/default_netif.c
    # The RFC 6528 ISN generator is NOT shared here: it is a per-product concern. The
    # conformance DUT links the lwIP-contrib tcp_isn addon (below); the UTM-core
    # binaries link the tc8-owned AES-CMAC generator (_tc8_lwip_utm_isn_srcs). The
    # bring-up reaches whichever one through the tc8_lwip_isn.h seam.
)

# The conformance DUT's RFC 6528 ISN: the lwIP-contrib tcp_isn addon, hashing with
# the PPP-bundled polarssl MD5. DUT-only — keeping it off the shared set is what lets
# the UTM (and the exported utm-sdk-lwip config) build without any lwIP-contrib / PPP
# / MD5 dependency. The DUT's tc8_lwip_isn.h seam impl (tc8_lwip_dut.cpp) drives it.
set(_tc8_lwip_dut_isn_srcs
    ${LWIP_CONTRIB_DIR}/addons/tcp_isn/tcp_isn.c
    ${LWIP_DIR}/src/netif/ppp/polarssl/md5.c
)

# The UTM's RFC 6528 ISN: the tc8-owned AES-CMAC generator (tc8_lwip_tcp_isn.cpp),
# reusing the vendor-neutral AES-CMAC engine. Linked by every binary built on the UTM
# core (the UTM itself and the two UTM-core in-process tests), since the UTM core's
# LWIP_HOOK_TCP_ISN names it. The UTM binary already pulls aes_cmac.cpp via the engine
# glob below, so it adds only the generator; the test binaries (no engine glob) also
# add the AES-CMAC source.
set(_tc8_lwip_utm_isn_src   ${CMAKE_CURRENT_SOURCE_DIR}/tc8_lwip_tcp_isn.cpp)
set(_tc8_aes_cmac_src       ${CMAKE_CURRENT_SOURCE_DIR}/../../src/autosar/aes_cmac.cpp)

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
# scoped define is the deliberate choice, not an unexamined hack. This quirk is now
# confined to the conformance DUT (the only binary that compiles md5.c): the UTM and
# the exported SDK use the tc8 AES-CMAC generator and never pull MD5 / PPP at all.
set_source_files_properties(${LWIP_DIR}/src/netif/ppp/polarssl/md5.c
    PROPERTIES COMPILE_DEFINITIONS "PPP_SUPPORT=1;LWIP_INCLUDED_POLARSSL_MD5=1")

# The unix-port flag set (LWIP_COMPILER_FLAGS) is C-oriented and applies three
# diagnostics ungated that are invalid — or pure noise — on these executables'
# C++ TUs (the apps, the shared testability + Upper Tester cores, the lwIP
# adapters and the bring-up). A trailing -Wno-* cannot fix -Wmissing-prototypes:
# GCC warns the moment it parses the positive flag ("valid for C/ObjC but not for
# C++"), before any later -Wno-. So strip the three ungated entries and re-add the two
# without a surviving C-guarded form, scoped to the C TUs — the lwIP .c sources
# compiled into these executables (default_netif.c everywhere; tcp_isn.c + md5.c in
# the conformance DUT) stay strict while the C++ TUs build clean. The lwIP
# core/contrib libraries are built by their own Filelists targets and are unaffected.
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

# Define one lwIP app executable: the shared core (_tc8_lwip_common_srcs) plus
# the binary-specific SRCS, with the include dirs / compile flags / definitions /
# link libraries every lwIP unix-port binary in this fixture needs.
#
#   tc8_lwip_app(<name> [LWIPOPTS_DIR <dir>] [LWIP_LIBS <lib>...] SRCS <src>...)
#
# By default the binary links the conformance lwIP core (lwipcore /
# lwipcontribportunix, built against this directory's lwipopts.h). Pass
# LWIPOPTS_DIR to compile the binary's own translation units against an alternate
# lwipopts.h (prepended to the include path so its bare-name include wins) and
# LWIP_LIBS to link a matching alternate core. The two go together: struct
# layouts (e.g. struct netif under LWIP_IGMP) differ between configs, so every TU
# in one link image must see the same lwipopts.h.
function(tc8_lwip_app name)
    cmake_parse_arguments(APP "" "LWIPOPTS_DIR" "LWIP_LIBS;SRCS" ${ARGN})
    if(NOT APP_LWIP_LIBS)
        set(APP_LWIP_LIBS lwipcontribportunix lwipcore)
    endif()
    add_executable(${name} ${APP_SRCS} ${_tc8_lwip_common_srcs})
    target_include_directories(${name} PRIVATE
        # Empty for the conformance config; the UTM's utm/ dir, prepended here,
        # wins the bare "lwipopts.h" include over the conformance base below.
        ${APP_LWIPOPTS_DIR}
        ${LWIP_INCLUDE_DIRS}
        # tc8/upper_tester_protocol.h + tc8/testability_protocol.h — single
        # source of truth for the UT + testability wire protocols, shared with
        # the harness and the Linux tc8-dut.
        "${CMAKE_CURRENT_SOURCE_DIR}/../../include"
        # wire/icmp_echo.h + wire/ip_checksum.h (tc8::wire), included as
        # "wire/...": the source root is the include root.
        "${CMAKE_CURRENT_SOURCE_DIR}/../../src"
    )
    # DELIBERATE strict-gate exclusion (not an omission). The harness's
    # tc8_enable_strict_warnings set (-Wold-style-cast / -Wconversion / -Werror,
    # applied to EVERY first-party target in the main build) is NOT applied to
    # these first-party lwIP adapters, because: (1) this is a SEPARATE CMake
    # project (project(tc8-lwip-dut) above) that does not see that function; (2) the
    # adapters interleave with lwIP's C API, whose headers (LWIP_INCLUDE_DIRS, on a
    # normal -I path here, not -isystem) are full of C-style-cast macros that would
    # drown -Wold-style-cast in third-party noise — the same blocker tc8-dut had,
    # resolved there by an -isystem demotion. The shared protocol logic
    # (ut_server.cpp, tc8::wire) IS strict-gated via the main build. Full coverage =
    # demote LWIP_INCLUDE_DIRS to -isystem + port tc8_enable_strict_warnings into
    # this project + fix the first-party cascade (a separate cross-build migration).
    target_compile_options(${name} PRIVATE
        ${_tc8_lwip_flags}
        $<$<COMPILE_LANGUAGE:C>:-Waggregate-return>
        $<$<COMPILE_LANGUAGE:C>:-Wswitch-default>
    )
    target_compile_definitions(${name} PRIVATE ${LWIP_DEFINITIONS})
    target_link_libraries(${name} ${LWIP_SANITIZER_LIBS} ${APP_LWIP_LIBS})
endfunction()

# The conformance DUT fixture: stack + opcode Upper Tester + testability. The
# Upper Tester runs on the platform-agnostic core (src/upper_tester/ut_server.cpp,
# shared verbatim with the Linux tc8-dut) paired with this fixture's lwIP adapters
# (lwip_stack_probe = TCP-info / original-dst introspection) and the lwIP-only ARP
# cache-conditioning opcode (lwip_ut_extensions). lwip_socket_backend (in the
# common srcs) supplies the socket primitives for both the UT and testability.
# The fault seams live HERE, not in the common srcs — DUT-only, so the UTM
# bring-up stays fault-free. tc8_lwip_dut.cpp installs them via BringUpLwipStack's
# post-netif-up callback (under the core lock, atomic with bring-up); the bring-up
# TU never names them. Egress field-fault (OpSetEgressFlavor) + ingress
# reaction-fault (OpSetIngressFlavor — ARP emission §4.2.4.2 + UDP acceptance
# §4.6.5.4).
tc8_lwip_app(tc8-lwip-dut SRCS
    tc8_lwip_dut.cpp
    lwip_stack_probe.cpp
    lwip_ut_extensions.cpp
    lwip_egress_fault.cpp
    lwip_ingress_fault.cpp
    ${_tc8_lwip_dut_isn_srcs}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/upper_tester/ut_server.cpp)

# The vendor-neutral AUTOSAR engines (src/autosar/) — pure byte math, the same
# sources the POSIX build compiles via tc8_add_engine. Globbed (CONFIGURE_DEPENDS)
# so a new engine joins the lwIP build with no second source list to keep in sync,
# and compiled into the UTM (not the conformance DUT) because they are the
# mechanisms an OEM middleware module on the lwIP UTM composes. Building them here
# proves the engines compile under the embedded lwIP toolchain, not only the host.
file(GLOB _tc8_autosar_engine_srcs CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/../../src/autosar/*.cpp)

# Build a SECOND, isolated lwIP core + unix-port library pair against an alternate
# lwipopts.h (`lwipopts_dir`), for a binary whose stack config diverges from the
# conformance one in a way that changes struct layout (here LWIP_IGMP, which alters
# struct netif) — mixing such translation units in one link image is undefined.
#
# The recipe MIRRORS upstream's lwipcore / lwipcontribportunix (src/Filelists.cmake,
# contrib/ports/unix/Filelists.cmake) FAITHFULLY — the same source-list variables,
# flags, definitions, includes, AND the unix-port link deps (mbedtls link libs plus
# the Linux util/pthread/rt / Darwin util that upstream attaches PUBLIC). Keeping the
# whole recipe in one helper is the SSOT guard: the earlier hand-clone silently
# dropped the link deps, so the conformance binary linked util/pthread/rt while the
# UTM binary did not — masked on glibc (pthread/rt folded into libc) but a latent
# link break on a split-lib toolchain. The conformance build deliberately keeps
# using upstream's OWN lwipcore / lwipcontribportunix targets directly: re-deriving
# those through this helper would risk perturbing the wire behaviour the TC8 ratchet
# pins, for no benefit. Sets ${out_core} / ${out_port} in the caller scope.
function(tc8_lwip_alt_core suffix lwipopts_dir out_core out_port)
    set(_inc "${lwipopts_dir}" ${LWIP_INCLUDE_DIRS} ${LWIP_MBEDTLS_INCLUDE_DIRS})

    add_library(lwipcore${suffix} EXCLUDE_FROM_ALL ${lwipnoapps_SRCS})
    target_compile_options(lwipcore${suffix} PRIVATE ${LWIP_COMPILER_FLAGS})
    target_compile_definitions(lwipcore${suffix} PRIVATE
        ${LWIP_DEFINITIONS} ${LWIP_MBEDTLS_DEFINITIONS})
    target_include_directories(lwipcore${suffix} PRIVATE ${_inc})

    add_library(lwipcontribportunix${suffix} EXCLUDE_FROM_ALL
        ${lwipcontribportunix_SRCS} ${lwipcontribportunixnetifs_SRCS})
    target_compile_options(lwipcontribportunix${suffix} PRIVATE ${LWIP_COMPILER_FLAGS})
    target_compile_definitions(lwipcontribportunix${suffix} PRIVATE
        ${LWIP_DEFINITIONS} ${LWIP_MBEDTLS_DEFINITIONS})
    target_include_directories(lwipcontribportunix${suffix} PRIVATE ${_inc})
    # The PUBLIC link deps upstream attaches to lwipcontribportunix — mirrored so a
    # binary linking this alt port-lib gets the same system libs as the conformance
    # one (this is the attribute the hand-clone dropped).
    target_link_libraries(lwipcontribportunix${suffix} PUBLIC ${LWIP_MBEDTLS_LINK_LIBRARIES})
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        find_library(LIBUTIL util)
        find_library(LIBPTHREAD pthread)
        find_library(LIBRT rt)
        target_link_libraries(lwipcontribportunix${suffix} PUBLIC
            ${LIBUTIL} ${LIBPTHREAD} ${LIBRT})
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        find_library(LIBUTIL util)  # Darwin has no pthread/rt libs
        target_link_libraries(lwipcontribportunix${suffix} PUBLIC ${LIBUTIL})
    endif()

    set(${out_core} lwipcore${suffix} PARENT_SCOPE)
    set(${out_port} lwipcontribportunix${suffix} PARENT_SCOPE)
endfunction()

# The IGMP-enabled core for the UTM (and the multicast/etharp test below).
tc8_lwip_alt_core(_utm "${CMAKE_CURRENT_SOURCE_DIR}/utm" _utm_core _utm_port)
# The link arg list shared by every binary on the UTM core (one SSOT for the pair).
set(_tc8_utm_core_args
    LWIPOPTS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/utm"
    LWIP_LIBS ${_utm_port} ${_utm_core})

# The standalone, OEM-deployable AUTOSAR Testability UTM: stack + testability
# endpoint only (no opcode UT). The lwIP analog of dut/utm (tc8-utm). Built
# against the IGMP-enabled core so a middleware module can join multicast groups.
tc8_lwip_app(tc8-lwip-utm
    ${_tc8_utm_core_args}
    SRCS lwip_utm_main.cpp ${_tc8_autosar_engine_srcs} ${_tc8_lwip_utm_isn_src})

# In-process runtime test for the middleware rx reactor on the lwIP backend (the
# lwIP IoMultiplexer: lwip_select poll() + the 127.0.0.1 socket-pair Waker). Runs
# entirely over the loopback netif — no tap/netns/root — so it exercises the one
# lwIP-specific path the host POSIX tests cannot. Registered as a CTest with a
# hard timeout so a regression that hangs the reactor fails fast. Needs no AUTOSAR
# engines (it tests the reactor, not the engines). Built against the UTM core/config
# (the reactor is a UTM-side feature), so it uses lwIP's default assert and needs
# no conformance sink.
enable_testing()
tc8_lwip_app(tc8-lwip-reactor-test
    ${_tc8_utm_core_args}
    SRCS lwip_reactor_test.cpp ${_tc8_lwip_utm_isn_src} ${_tc8_aes_cmac_src})
add_test(NAME lwip_reactor_test COMMAND tc8-lwip-reactor-test)
set_tests_properties(lwip_reactor_test PROPERTIES TIMEOUT 30)

# In-process runtime test for the lwIP backend's multicast (IGMP) + static ARP
# (etharp) ops. Built against the IGMP-on UTM core — the conformance core has IGMP
# off, where joinMulticast compiles to its false stub. Runs over loopback plus a
# stub ethernet netif (no tap/netns/root). Hard timeout so a hang fails fast.
tc8_lwip_app(tc8-lwip-arp-mcast-test
    ${_tc8_utm_core_args}
    SRCS lwip_arp_multicast_test.cpp ${_tc8_lwip_utm_isn_src} ${_tc8_aes_cmac_src})
add_test(NAME lwip_arp_multicast_test COMMAND tc8-lwip-arp-mcast-test)
set_tests_properties(lwip_arp_multicast_test PROPERTIES TIMEOUT 30)
