cmake_minimum_required(VERSION 3.16)
project(tc8-harness LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Strict warnings applied to first-party targets (tc8-harness, the shared
# tc8_stimulus / tc8_harness_core libraries, and the engines). SCE-generated /
# third-party headers live behind SYSTEM include paths where available,
# so they do not contribute to this warning set. `-Werror` IS on by default
# (TC8_WARNINGS_AS_ERRORS) now that the first-party tree is clean — opt out with
# `-DTC8_WARNINGS_AS_ERRORS=OFF`.
#
# The flag set, the TC8_WARNINGS_AS_ERRORS option, and the
# tc8_enable_strict_warnings() target helper all live in a shared module so the
# separate lwIP DUT sub-project (dut/lwip_dut) applies the exact same gate without
# a hand-copied second list or a second option default that could drift.
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/tc8_strict_warnings.cmake)

# DUT-identity cross-check at CONFIGURE time. The DUT service/instance/ports/IP/
# SD-multicast/app-name are hand-encoded across dut_config.h, someip_method_dest.h,
# four vsomeip*.json and two .fdepl; a drift silently breaks reachability for every
# SOME/IP case (same "silent breakage" severity that makes the sce-codegen probe a
# FATAL). The CI gate enforces it on push; this catches it locally before a build,
# the FATAL counterpart of the wire-`.def` `--check` gates. Skipped (with a warning)
# only when no python3 is on PATH, so a python-less configure is not blocked.
find_program(TC8_PYTHON3 NAMES python3 python)
if(TC8_PYTHON3)
    execute_process(
        COMMAND ${TC8_PYTHON3} ${CMAKE_CURRENT_SOURCE_DIR}/tools/check_dut_identity.py
        RESULT_VARIABLE _tc8_identity_rc
        OUTPUT_VARIABLE _tc8_identity_out ERROR_VARIABLE _tc8_identity_out)
    if(NOT _tc8_identity_rc EQUAL 0)
        message(FATAL_ERROR
            "TC8: DUT identity drift (tools/check_dut_identity.py):\n${_tc8_identity_out}")
    endif()
else()
    message(WARNING
        "TC8: python3 not found — skipping the DUT-identity cross-check (CI still gates it)")
endif()

# Sanitizer build variant. Enables ASan + UBSan on every target (not just
# first-party) so memory / UB issues in the full dissect pipeline surface
# at test time. Critical once §4 ARP/ICMP/IP/UDP/DHCP/TCP decoders land
# — that is where bit-manipulation bugs tend to hide.
#
# Usage: `cmake -S . -B build-san -DTC8_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug`
# Runtime tip: export `ASAN_OPTIONS=abort_on_error=1:detect_leaks=1` and
# `UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1` before running the
# smoke-test so a hit fails the run instead of just printing a report.
option(TC8_SANITIZE
    "Build with -fsanitize=address,undefined across all targets"
    OFF)

if(TC8_SANITIZE)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        message(FATAL_ERROR
            "TC8_SANITIZE requires GCC or Clang; got ${CMAKE_CXX_COMPILER_ID}")
    endif()
    # -fno-omit-frame-pointer + -g: give sanitizers readable stack traces.
    # Applied globally via *_FLAGS so third-party + generated code also runs
    # instrumented — ASan is pointless if only half the graph is checked.
    #
    # -fno-sanitize=vptr: UBSan's vptr check requires typeinfo objects for
    # every polymorphic type reachable at link time. CommonAPI-SomeIP is
    # linked as a system shared library built without such exports, and
    # `tc8-dut` dies at link with "undefined reference to typeinfo for
    # CommonAPI::SomeIP::OutputStream". Disabling only the vptr check
    # keeps every other UBSan + ASan check active across the build.
    add_compile_options(
        -fsanitize=address,undefined
        -fno-sanitize=vptr
        -fno-omit-frame-pointer
        -g
    )
    add_link_options(
        -fsanitize=address,undefined
        -fno-sanitize=vptr
    )
    message(STATUS "TC8_SANITIZE: enabled (ASan + UBSan minus vptr, global)")
endif()

option(TC8_SCE_FIND_PACKAGE
    "Use installed SCE via find_package(SCE) instead of embed package" OFF)

if(TC8_SCE_FIND_PACKAGE)
    find_package(SCE REQUIRED)
    add_library(sce_base ALIAS SCE::sce_base)
    # Target that owns the include paths (can't set_property on ALIAS —
    # SCE::sce_base is the real IMPORTED target the alias points to).
    set(_SCE_BASE_REAL_TARGET SCE::sce_base)
else()
    add_subdirectory(third_party/sce)
    # Embed ships SCECodegen.cmake but doesn't auto-include it;
    # pull it in so sce_add_state_machine() becomes available.
    include(${CMAKE_CURRENT_SOURCE_DIR}/third_party/sce/SCECodegen.cmake)
    set(_SCE_BASE_REAL_TARGET sce_base)
endif()

# Demote third-party SCE include dirs to SYSTEM so the strict-warning set
# below (Wshadow, Wold-style-cast, ...) does not fire against headers we
# do not own. CMake requires a path to be in both INTERFACE_INCLUDE_DIRECTORIES
# *and* INTERFACE_SYSTEM_INCLUDE_DIRECTORIES for GCC/Clang to apply `-isystem`
# — the SYSTEM property is a subset tag, not a replacement. So the paths stay
# in the regular interface list and get additionally marked system.
get_target_property(_sce_base_incs ${_SCE_BASE_REAL_TARGET} INTERFACE_INCLUDE_DIRECTORIES)
if(_sce_base_incs)
    set_property(TARGET ${_SCE_BASE_REAL_TARGET} APPEND PROPERTY
        INTERFACE_SYSTEM_INCLUDE_DIRECTORIES ${_sce_base_incs})
endif()
if(TARGET sce_core)
    get_target_property(_sce_core_incs sce_core INTERFACE_INCLUDE_DIRECTORIES)
    if(_sce_core_incs)
        set_property(TARGET sce_core APPEND PROPERTY
            INTERFACE_SYSTEM_INCLUDE_DIRECTORIES ${_sce_core_incs})
    endif()
endif()

# Shared IPv4-family wire math — the single build-level home for src/wire
# (RFC 1071 Internet checksum, RFC 792 ICMP echo body). Linked by the harness,
# tc8-dut, the testability server library and the unit tests so no target names
# the source by path (the former pattern left ip_checksum.cpp listed in four
# CMakeLists and tempted in-tree checksum copies). Pure byte math — no syscalls,
# no third-party deps — so it cross-compiles and the lwIP DUT port can link it.
add_library(tc8_wire STATIC
    src/wire/ip_checksum.cpp
    src/wire/icmp_echo.cpp
)
# Every header tc8_wire exposes, and every header its .cpp compile against, lives
# under include/tc8/wire/ (RFC 1071 checksum, RFC 792 echo body, the read/format
# helpers) — all namespaced. So include/ is the sole PUBLIC include root; this
# target reaches nothing through the flat src/ tree.
target_include_directories(tc8_wire PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
tc8_enable_strict_warnings(tc8_wire)

# The tester-side AUTOSAR Testability Protocol client — the standard counterpart
# to the DUT-side endpoint in dut/dut_service (tc8_testability_core + a backend).
# Both halves frame against the one codec SSOT, include/tc8/testability_protocol.h,
# so they decode identically; this archive adds the tester's socket round trip and
# the standard typed primitives.
#
# A library for the same reason tc8_wire is one: the harness, the cross-compile
# portability check and the unit tests all drive this client, and naming the source
# by path in each list is what invites a second, drifting copy. It is also what the
# UTM SDK exports — a consumer that attaches an OEM service-group module to the
# endpoint links THIS to exercise it, so the exported surface carries both halves
# of the protocol rather than the endpoint alone.
#
# Dependency-light and vendor-neutral by construction: POSIX sockets plus the
# header-only codec — no threads, no libpcap/libtins/vsomeip — so it cross-compiles
# and an out-of-tree consumer inherits nothing but the seam.
add_library(tc8_testability_client STATIC
    src/stimulus/testability_client.cpp
)
# The client's public header (include/tc8/testability_client.h) and the codec SSOT
# it frames against (tc8/testability_protocol.h) both live under include/tc8/, and
# the .cpp compiles against only those — so include/ is the sole PUBLIC include
# root, which the export block collapses onto the single install-tree include root.
target_include_directories(tc8_testability_client PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
tc8_enable_strict_warnings(tc8_testability_client)

# Vendor-neutral AUTOSAR engines (src/autosar/) — the public mechanisms a
# separate, private OEM UTM repo composes with its own config. Every engine is
# the same shape: a dependency-light STATIC lib (pure byte math — no syscalls,
# no third-party deps, no OEM content) with the src/ include root on its
# BUILD_INTERFACE and the strict first-party warning set. tc8_add_engine is the
# single home for that recipe so adding an engine is one line and the lib
# pattern never drifts across copies. The install/EXPORT interface for each
# engine is wired once in the TC8_UTM_INSTALL block below.
function(tc8_add_engine name)
    add_library(${name} STATIC ${ARGN})
    # Every engine's public header (tc8/autosar/*.h) and every include its .cpp
    # reaches live under include/tc8/autosar/ — all namespaced — so include/ is the
    # sole PUBLIC root; no engine reaches through the flat src/ tree.
    target_include_directories(${name} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
    tc8_enable_strict_warnings(${name})
    # Record the engine in the single list the UTM export iterates, so adding an
    # engine stays one line and the install/EXPORT never drifts from the build.
    set(TC8_UTM_ENGINES ${TC8_UTM_ENGINES} ${name} PARENT_SCOPE)
endfunction()

# tc8::crypto — AES-CMAC (FIPS-197 AES-128 + RFC 4493), the SecOC MAC primitive.
# Keys are passed per call by the caller, so no keying material lives here.
tc8_add_engine(tc8_crypto src/autosar/aes_cmac.cpp)

# tc8::pn — AUTOSAR Partial Networking relevance filter: a bitwise AND of the
# received PNC bit vector with the ECU's cluster mask. Range location and
# cluster membership are injected config.
tc8_add_engine(tc8_pn src/autosar/pn_filter.cpp)

# tc8::crc — AUTOSAR CRC Routines (CRC-8/SAE-J1850 + CRC-16/CCITT-FALSE), the
# shared primitive the E2E profiles compose. Its own module so each CRC consumer
# links one verified implementation rather than re-deriving it.
tc8_add_engine(tc8_crc src/autosar/crc.cpp)

# tc8::e2e — AUTOSAR FO PRS E2EProtocol protect/check. Composes tc8::crc for the
# CRC; profile/Data ID/offset are injected config. Links tc8_crc.
tc8_add_engine(tc8_e2e src/autosar/e2e.cpp)
target_link_libraries(tc8_e2e PUBLIC tc8_crc)

# tc8::com — AUTOSAR SWS COM signal pack/unpack into I-PDUs (Intel + Motorola
# bit layout). Signal/PDU database is injected config.
tc8_add_engine(tc8_com src/autosar/com.cpp)

# tc8::nm — AUTOSAR Network Management state machine (SWS UDPNetworkManagement).
# State logic only; timings/layout/node id are injected config, and the owning
# module drives it via mainFunction()/rxNmPdu() and onTransmit.
tc8_add_engine(tc8_nm src/autosar/nm.cpp)

# tc8::someiptp — AUTOSAR SOME/IP-TP transport (PRS_SOMEIP §4.2.1.4): segment a
# large SOME/IP message into TP segments and reassemble received ones. Wire framing
# only; OEM ids and any connection lifecycle are the owning module's config.
tc8_add_engine(tc8_someiptp src/autosar/someiptp.cpp)

# tc8_stimulus — the wire-frame builders (ARP / 802.1Q / IPv4 / ICMPv4 / DHCPv4 /
# UDP / TCP-segment / SOME/IP RPC+SD+TP) plus the SOME/IP header dissectors. Pure
# byte-layout code: endianness- and bit-layout-sensitive, POSIX sockets at most, no
# libpcap / libtins / vsomeip — so it cross-compiles. A library for the same reason
# tc8_wire is one: the tester, the cross-compile portability check, and the unit
# tests all drive these builders, and listing them by path in three CMakeLists (as
# they were) is exactly what invites a second, drifting copy. tcp_client is here
# because someip_rpc_builder emits RPC over TCP through it (connectTcpFromIface) —
# the builder graph is closed over it, so it must not sit in a consumer. The socket
# responders that own threads / capture loops (arp_responder, tcp_server, …) stay
# with the tester; this archive is the stateless builders + dissectors + that
# client.
add_library(tc8_stimulus STATIC
    src/dissect/someip_header.cpp
    src/dissect/someip_dispatcher.cpp
    src/stimulus/arp_builder.cpp
    src/stimulus/dot1q.cpp
    src/stimulus/dhcpv4_frame_builder.cpp
    src/stimulus/ipv4_frame_builder.cpp
    src/stimulus/icmpv4_builder.cpp
    src/stimulus/someip_rpc_builder.cpp
    src/stimulus/someip_sd_builder.cpp
    src/stimulus/tcp_client.cpp
    src/stimulus/udp_emit.cpp
    src/stimulus/someip_tp_emit.cpp
    src/stimulus/tcp_segment_builder.cpp
    src/stimulus/udp_datagram_builder.cpp
    src/stimulus/upper_tester_client.cpp
)
# PUBLIC roots consumers inherit by linkage: include/ (the tc8/... headers — wire
# math, protocol frames, dut_config, the namespaced tc8/net + tc8/someip + tc8/wire
# helpers the builders use), src/dissect/include (this lib's own dissect/ headers —
# the SOME/IP dissectors), and src/stimulus/include (this lib's own stimulus/ builder
# + header-only helper headers — moved out of the flat tree so stimulus/*.h resolves
# only through here; the socket responders live in tc8_harness_core's own stimulus/
# responder root). All PUBLIC so every consumer inherits the roots by linkage.
target_include_directories(tc8_stimulus PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/dissect/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/stimulus/include>
)
# tc8_wire: RFC 1071 checksum / RFC 792 echo body, used by the IPv4-family builders.
# tc8_someiptp: someip_tp_emit frames via someiptp::Segmenter. Threads:
# someip_sd_builder / upper_tester_client use std::this_thread::sleep_for.
find_package(Threads REQUIRED)
target_link_libraries(tc8_stimulus PUBLIC tc8_wire tc8_someiptp Threads::Threads)
tc8_enable_strict_warnings(tc8_stimulus)

# Portability check: cross-compile the dependency-light core — sce_base, tc8_wire,
# the AUTOSAR engines, tc8_stimulus (wire builders + SOME/IP dissectors), and
# tc8_testability_client, all defined above — without needing a target sysroot for
# libpcap / libtins / vsomeip / CommonAPI. Used with
# cmake/toolchains/aarch64-linux-gnu.cmake to keep the embedded-tester
# (target-to-target topology) build path verifiable on a host with only a cross
# compiler installed. `return()` ends top-level processing before the heavy
# find_package set, the case glob, tc8-dut, and unit tests — all host-build
# concerns — so `cmake --build` cross-compiles exactly the core libraries.
option(TC8_PORTABILITY_CHECK
    "Build only the dependency-light core (for cross-compile verification)"
    OFF)

if(TC8_PORTABILITY_CHECK)
    message(STATUS
        "TC8: portability-check configuration — cross-compiling the "
        "dependency-light core libraries (tc8_wire, AUTOSAR engines, "
        "tc8_stimulus, tc8_testability_client) for ${CMAKE_SYSTEM_PROCESSOR}; "
        "harness/tc8-dut/cases/unit tests are skipped (no target sysroot required)")
    return()
endif()

# ── Build-shape options ─────────────────────────────────────────────────────
# Three targets carry the project's heavy host prerequisites; each is now
# individually skippable so a pure tc8-utm SDK consumer (TC8_UTM_INSTALL=ON,
# building only the exported library archives) needs none of them installed at
# configure time:
#
#   * TC8_BUILD_HARNESS    — the tc8-harness tester executable (the SOME/IP wire
#                            runner) and its per-case state machines. Owns the
#                            vsomeip3 + CommonAPI link and the libpcap/libtins
#                            capture stack.
#   * TC8_BUILD_MOCK_DUT   — the vsomeip/CommonAPI ETS mock DUT under dut/ets,
#                            which also links the SOME/IP stack.
#   * TC8_BUILD_UNIT_TESTS — the C++ unit tests (declared here, not at their
#                            add_subdirectory below, so the capture-stack probe
#                            can be gated on them too).
#
# None of the exported SDK archives links any of the gated dependencies. All
# default ON, so every existing configuration — including the hosted build-test
# job, which sets only TC8_BUILD_MOCK_DUT=OFF — configures byte-for-byte as before.
option(TC8_BUILD_HARNESS
    "Build the tc8-harness tester executable (SOME/IP wire runner)"
    ON)
option(TC8_BUILD_MOCK_DUT
    "Build the vsomeip/CommonAPI ETS mock DUT (tc8-dut) from dut/"
    ON)
option(TC8_BUILD_UNIT_TESTS
    "Build C++ unit tests in unit_tests/ (requires GTest)"
    ON)

# The SOME/IP wire stack is a REQUIRED configure-time dependency of exactly two
# consumers: the tester executable and the ETS mock DUT (dut/ets links vsomeip3 +
# CommonAPI and is added only under TC8_BUILD_MOCK_DUT, relying on the imported
# targets found here). Gate the whole find_package set — and the SYSTEM-include
# demotion that operates on its imported targets — on whether either is built.
if(TC8_BUILD_HARNESS OR TC8_BUILD_MOCK_DUT)
    find_package(vsomeip3 REQUIRED)
    find_package(CommonAPI REQUIRED)
    find_package(CommonAPI-SomeIP REQUIRED)

    # Demote vsomeip / CommonAPI third-party include dirs to SYSTEM (same idiom as
    # the SCE demotion above) so a first-party strict-warning gate on the DUT does
    # not fire against headers we do not own. The generated CommonAPI proxy/stub
    # headers (GEN_DIR) are marked SYSTEM on the ets/ets2/ets3 targets where added.
    foreach(_tp vsomeip3 CommonAPI CommonAPI-SomeIP)
        if(TARGET ${_tp})
            get_target_property(_tp_incs ${_tp} INTERFACE_INCLUDE_DIRECTORIES)
            if(_tp_incs)
                set_property(TARGET ${_tp} APPEND PROPERTY
                    INTERFACE_SYSTEM_INCLUDE_DIRECTORIES ${_tp_incs})
            endif()
        endif()
    endforeach()
endif()

# libpcap + libtins — the packet capture/dissection stack. Consumed by the tester
# and by the capture/dissection unit tests (which read the PCAP_*/LIBTINS_*
# variables set here), so gate the probe on either. A mock-DUT-only or SDK-only
# configure needs neither.
if(TC8_BUILD_HARNESS OR TC8_BUILD_UNIT_TESTS)
    find_path(PCAP_INCLUDE_DIR NAMES pcap/pcap.h pcap.h)
    find_library(PCAP_LIBRARY NAMES pcap)
    if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
        message(FATAL_ERROR "libpcap not found — install libpcap-dev")
    endif()

    find_path(LIBTINS_INCLUDE_DIR NAMES tins/tins.h)
    find_library(LIBTINS_LIBRARY NAMES tins)
    if(NOT LIBTINS_INCLUDE_DIR OR NOT LIBTINS_LIBRARY)
        message(FATAL_ERROR "libtins not found — install libtins-dev")
    endif()
endif()

# tc8_harness_core — the dependency-light harness internals shared by the tester
# executable and the unit tests: pcap capture, the expect/summary CLI helpers, the
# SCE case registry + spec inventory, and the socket responders (ARP / method / TCP
# server + accept + subscribe) that own a thread or a capture loop. A library for the
# same reason tc8_stimulus is: the tester and every unit test link the SAME objects,
# so a responder covered by a test is the one the tester ships — no second, drifting
# copy (this set was listed by path in the tester AND in unit_tests' testable lib).
# harness_main, dut_control_factory, and the pcap/vsomeip-driving CLI commands stay in
# the tester: they pull heavier deps and are the executable's own edges. Built only
# when the tester or the unit tests are — an SDK-only configure needs none of it.
if(TC8_BUILD_HARNESS OR TC8_BUILD_UNIT_TESTS)
    add_library(tc8_harness_core STATIC
        src/capture/bpf_filter.cpp
        src/capture/pcap_source.cpp
        src/cli/expect_parser.cpp
        src/cli/packet_summary.cpp
        src/sce_integration/case_registry.cpp
        src/sce_integration/spec_inventory.cpp
        src/stimulus/arp_responder.cpp
        src/stimulus/method_responder.cpp
        src/stimulus/tcp_server.cpp
        src/stimulus/tcp_accept_service.cpp
        src/stimulus/subscribe_tcp_session.cpp
    )
    # PUBLIC roots consumers inherit by linkage: src/sce_integration/include (this
    # lib's OWN sce_integration/ tree — case registry, spec inventory, the expected/
    # captured helpers, and the 764 case traits headers under cases/ — moved out of
    # the flat tree so sce_integration/*.h resolves only through here);
    # src/stimulus/responders/include (this lib's OWN socket responders — arp/method
    # responder, tcp_server/accept_service, subscribe_tcp_session — under the stimulus/
    # prefix, a separate root from tc8_stimulus's builder headers); src/capture/include
    # and src/cli/include (its capture/ headers and cli/ helpers expect_parser +
    # packet_summary; the 9 tester-side cli/ command headers live under
    # src/cli/commands/include, private to the tester exes, not exposed here); and
    # include/ for the tc8/ namespace. The flat src/ seam remains only transitionally —
    # no bare prefix resolves through it now. PRIVATE pcap headers for the capture
    # sources (pcap_source / bpf_filter) — a test that #includes one adds its own.
    target_include_directories(tc8_harness_core
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/sce_integration/include>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/stimulus/responders/include>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/capture/include>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/cli/include>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        PRIVATE ${PCAP_INCLUDE_DIR})
    # tc8_stimulus: the responders drive the stateless builders (tcp_server →
    # tcp_segment_builder, arp_responder → arp_builder, …) and it carries tc8_wire /
    # tc8_someiptp / Threads transitively. tc8_testability_client: the case runner and
    # the UTM probe path. Both PUBLIC so consumers inherit the seam.
    target_link_libraries(tc8_harness_core PUBLIC tc8_stimulus tc8_testability_client)
    tc8_enable_strict_warnings(tc8_harness_core)
endif()

# ── Tester executable + per-case state machines (TC8_BUILD_HARNESS) ──────────
# Everything from here to tc8_enable_strict_warnings(tc8-harness) builds the
# tc8-harness tester and its case machinery; none of it is reachable from the
# exported SDK, so an SDK-only configure skips the SOME/IP link, the whole case
# glob, and the codegen probe (mirroring the portability check's early return
# above). The guarded body is left un-indented so this decoupling stays a minimal,
# reviewable diff over a ~475-line region; the endif() below is labelled to match.
if(TC8_BUILD_HARNESS)

# The tester-side ArpResponder owns a std::thread worker; link Threads
# explicitly rather than relying on a transitive vsomeip pull-in. Only the tester
# needs it at this scope — dut_service and unit_tests each find their own.
find_package(Threads REQUIRED)

# The stateless wire builders + SOME/IP dissectors come from tc8_stimulus, and the
# capture / CLI-helper / case-registry / responder core from tc8_harness_core (both
# linked below). Listed here are the tester's own edges: the entry point, the
# pcap/vsomeip-driving CLI commands, the packet pipeline, and the DUT control factory.
add_executable(tc8-harness
    src/harness_main.cpp
    src/dissect/packet_pipeline.cpp
    src/cli/signal_handler.cpp
    src/cli/capture_driver.cpp
    src/cli/decode_pcap_command.cpp
    src/cli/live_command.cpp
    src/cli/replay_command.cpp
    src/cli/test_command.cpp
    src/cli/ut_ping_command.cpp
    src/cli/testability_probe_command.cpp
    src/cli/testability_send_command.cpp
    src/sce_integration/dut_control_factory.cpp
)

# Each TC8 case lives in tests/<case_id>/ with its SCXML. The matching
# src/sce_integration/include/sce_integration/cases/<case_id>.h carries the TestCaseTraits
# specialization and a TC8_REGISTER_CASE() inline registrar. CMake generates
# a thin translation unit per case that includes the header, forcing the
# registrar to be pulled into the final link — so adding a case is just
# tests/<id>/<id>.scxml + src/sce_integration/include/sce_integration/cases/<id>.h.
#
# Out-of-tree extension points, for consumers embedding tc8-harness via
# FetchContent/add_subdirectory without forking it:
#
#   TC8_EXTRA_CASE_DIRS    — ;-separated directories, each containing case
#                            subdirectories shaped like tests/<case_id>/.
#                            A subdirectory whose name collides with an
#                            in-tree case is a configure error — replacing
#                            a case must be explicit (see below).
#   TC8_CASE_OVERRIDE_DIRS — ;-separated directories whose case
#                            subdirectories REPLACE the in-tree
#                            tests/<case_id>/ of the same name at collection
#                            time. A subdirectory that does not match any
#                            in-tree case is a configure error (typo guard).
#
# Traits header resolution for every collected case: <case_dir>/<case_id>.h
# first, then src/sce_integration/include/sce_integration/cases/<case_id>.h. An override that ships
# only the .scxml therefore reuses the in-tree traits (SCXML-level
# override); shipping <case_id>.h alongside replaces the whole case. New
# out-of-tree cases must carry their own traits header.
#
# Replacement happens before codegen, so exactly one state machine per case
# id reaches the link — the CaseRegistry duplicate-id abort stays a
# backstop, never the mechanism.
# Guarded cache declarations: under CMP0126 OLD (cmake_minimum_required
# 3.16) an unguarded `set(... CACHE ...)` erases a same-name normal
# variable inherited from a consumer superproject's scope — silently
# dropping the consumer's plain `set(TC8_EXTRA_CASE_DIRS ...)`. The
# guard keeps both spellings working: -D cache entries and plain set()
# before add_subdirectory/FetchContent_MakeAvailable.
if(NOT DEFINED TC8_EXTRA_CASE_DIRS)
    set(TC8_EXTRA_CASE_DIRS "" CACHE STRING
        "Directories containing additional out-of-tree case subdirectories")
endif()
if(NOT DEFINED TC8_CASE_OVERRIDE_DIRS)
    set(TC8_CASE_OVERRIDE_DIRS "" CACHE STRING
        "Directories whose case subdirectories replace in-tree tests/<id>/")
endif()
#   TC8_EXTRA_CASE_SUITES  — ;-separated suite names, one per TC8_EXTRA_CASE_DIRS
#                            root (index-aligned). A root's cases register under
#                            that suite; identity becomes (suite, case_id), so a
#                            non-default suite may reuse an in-tree case id. An
#                            empty or missing entry defaults to the in-tree
#                            suite "tc8" (kDefaultSuite).
if(NOT DEFINED TC8_EXTRA_CASE_SUITES)
    set(TC8_EXTRA_CASE_SUITES "" CACHE STRING
        "Suite name per TC8_EXTRA_CASE_DIRS root (;-aligned); empty/missing => default")
endif()

# The in-tree default suite name has its single source of truth in the C++
# constant kDefaultSuite (src/sce_integration/include/sce_integration/case_registry.h). Derive it here
# rather than restating the literal, so the configure-time suite logic and the
# runtime registry can never disagree on the default suite's name.
file(STRINGS src/sce_integration/include/sce_integration/case_registry.h _tc8_kdefault_line
     REGEX "kDefaultSuite[ \t]*=[ \t]*\"[^\"]+\"")
if(NOT _tc8_kdefault_line)
    message(FATAL_ERROR
        "TC8: could not derive the default suite name from kDefaultSuite in "
        "src/sce_integration/include/sce_integration/case_registry.h — update the SSOT-extraction regex")
endif()
string(REGEX REPLACE ".*\"([^\"]+)\".*" "\\1" TC8_DEFAULT_SUITE "${_tc8_kdefault_line}")

# gen/ holds the registration stubs and the per-suite codegen output, and its
# root is on the tc8-harness include path so a non-default suite's generated SM
# header resolves via its suite-qualified path "<suite>/<case_id>_sm.h" (stamped
# by tc8_add_case). The in-tree "<case_id>_sm.h" lives in the default
# "generated/" dir; SCE (SCECodegen.cmake) also adds each per-suite
# "gen/<suite>/" dir to the include path, so an in-tree bare include is
# disambiguated by SEARCH ORDER: Pass 2 (in-tree -> "generated/") is collected
# before Pass 3 (extra suites), so "generated/" precedes any "gen/<suite>/" and
# the in-tree case binds its own header. That pass ordering IS the isolation
# invariant — do not reorder the passes.
set(TC8_CASE_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen)
set(TC8_CASE_STUBS_DIR ${TC8_CASE_GEN_DIR}/cases_stubs)
file(MAKE_DIRECTORY ${TC8_CASE_STUBS_DIR})
set(TC8_CASE_STUBS)

# Fail loud at configure time if the resolved sce-codegen accepts but does NOT
# honour --cpp-namespace-prefix (some builds parse the flag yet emit un-nested
# headers — verified to happen). Without nesting, a non-default suite's SM type
# equals the in-tree type and the two collide silently (ODR / one-definition-
# wins) the moment they share a case id. Probes once per configure, only when a
# non-default suite is actually requested, so the default build pays nothing.
function(tc8_assert_codegen_nests)
    get_property(_done GLOBAL PROPERTY _TC8_CODEGEN_NEST_CHECKED)
    if(_done)
        return()
    endif()
    set_property(GLOBAL PROPERTY _TC8_CODEGEN_NEST_CHECKED 1)
    set(_probe ${TC8_CASE_GEN_DIR}/_codegen_probe)
    file(MAKE_DIRECTORY ${_probe})
    file(WRITE ${_probe}/tc8_probe.scxml
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<scxml xmlns=\"http://www.w3.org/2005/07/scxml\" version=\"1.0\" "
        "name=\"tc8_probe\" datamodel=\"null\" initial=\"s0\">\n"
        "  <state id=\"s0\"><transition target=\"s1\"/></state>\n"
        "  <final id=\"s1\"/>\n</scxml>\n")
    set(_probe_cmd ${SCE_CODEGEN} generate ${_probe}/tc8_probe.scxml
                   -o ${_probe} -l cpp --cpp-namespace-prefix __tc8_probe)
    if(SCE_TEMPLATE_DIR)
        set(_probe_cmd ${CMAKE_COMMAND} -E env
            "SCE_TEMPLATE_DIR=${SCE_TEMPLATE_DIR}" ${_probe_cmd})
    endif()
    execute_process(COMMAND ${_probe_cmd}
        RESULT_VARIABLE _rc OUTPUT_QUIET ERROR_QUIET)
    if(NOT _rc EQUAL 0)
        message(FATAL_ERROR
            "TC8: sce-codegen probe failed (rc=${_rc}) using ${SCE_CODEGEN}")
    endif()
    file(STRINGS ${_probe}/tc8_probe_sm.h _ns
         REGEX "namespace SCE::Generated::__tc8_probe")
    if(NOT _ns)
        message(FATAL_ERROR
            "TC8: sce-codegen (${SCE_CODEGEN}) accepts but does not honour "
            "--cpp-namespace-prefix — the probe header is not nested under "
            "::SCE::Generated::__tc8_probe. A non-default case suite needs a "
            "codegen that nests, else two suites sharing a case id collide "
            "(ODR). Update sce-codegen (>= the pinned third_party/sce VERSION).")
    endif()
endfunction()

# Registers one case directory: SCXML codegen + traits-header resolution +
# registration-stub TU. Appends the stub to TC8_CASE_STUBS in the caller's
# scope. `origin` is "in-tree", "override", or "extra" — out-of-tree
# origins are logged per case (the in-tree bulk is already covered by the
# per-machine SCE codegen lines). `suite` is the catalog name (empty or the
# default-suite name => the in-tree default; any other => a nested OEM suite).
function(tc8_add_case case_dir origin suite)
    get_filename_component(case_id ${case_dir} NAME)

    # Suite identity matches the registry's, which is case-insensitive: normalise
    # to lower case so a root declared "VENDORX" and the registry's "vendorx" never
    # diverge across the configure/runtime boundary. Empty or the default-suite
    # name selects the in-tree default.
    string(TOLOWER "${suite}" _suite)

    # Default suite: byte-identical to the pre-suite build. The SM generates as
    # ::SCE::Generated::<name> into the shared "generated/" dir and the stub
    # carries no suite define, so the ~750 in-tree cases are untouched.
    if(_suite STREQUAL "" OR _suite STREQUAL "${TC8_DEFAULT_SUITE}")
        sce_add_state_machines_from_dir(
            TARGET    tc8-harness
            SCXML_DIR ${case_dir})
        set(stub_dir ${TC8_CASE_STUBS_DIR})
        set(suite_defines "")
    else()
        # The suite name becomes a C++ namespace token, a path segment, and a
        # registry string — reject anything that is not a plain C++ identifier so
        # a bad name fails fast here instead of as a cryptic codegen/compile error
        # downstream.
        if(NOT _suite MATCHES "^[a-z_][a-z0-9_]*$")
            message(FATAL_ERROR
                "TC8: suite name '${suite}' is not a valid C++ identifier "
                "([A-Za-z_][A-Za-z0-9_]*) — it nests the generated namespace "
                "::SCE::Generated::<suite>::")
        endif()
        # Guard the ODR-distinctness invariant: a codegen that ignored the prefix
        # would silently un-nest this suite onto the in-tree type.
        tc8_assert_codegen_nests()
        # A non-default suite nests the SM under ::SCE::Generated::<suite>::<name>
        # in a per-suite output dir (so identical case ids never share a generated
        # file) and the stub stamps three tokens the OEM case header binds against:
        # TC8_CASE_SUITE (registry identity string), TC8_CASE_SUITE_NS (C++
        # namespace token), TC8_CASE_SM_HEADER (the suite-qualified header path).
        # Distinct suite => distinct namespace => distinct SM type => the
        # gRegisterCase<SM> ODR invariant in case_registry.h holds.
        sce_add_state_machines_from_dir(
            TARGET               tc8-harness
            SCXML_DIR            ${case_dir}
            OUTPUT_DIR           ${TC8_CASE_GEN_DIR}/${_suite}
            CPP_NAMESPACE_PREFIX ${_suite})
        set(stub_dir ${TC8_CASE_STUBS_DIR}/${_suite})
        file(MAKE_DIRECTORY ${stub_dir})
        set(suite_defines
            "#define TC8_CASE_SUITE \"${_suite}\"\n"
            "#define TC8_CASE_SUITE_NS ${_suite}\n"
            "#define TC8_CASE_SM_HEADER \"${_suite}/${case_id}_sm.h\"\n")
    endif()

    set(case_header ${case_dir}/${case_id}.h)
    set(traits_kind "case-local")
    if(NOT EXISTS ${case_header})
        set(case_header
            ${CMAKE_CURRENT_SOURCE_DIR}/src/sce_integration/include/sce_integration/cases/${case_id}.h)
        set(traits_kind "in-tree")
    endif()
    if(NOT EXISTS ${case_header})
        message(FATAL_ERROR
            "TC8: case '${case_id}' (${case_dir}): no traits header at "
            "${case_dir}/${case_id}.h or "
            "src/sce_integration/include/sce_integration/cases/${case_id}.h")
    endif()

    if(_suite STREQUAL "")
        set(_suite_disp "${TC8_DEFAULT_SUITE}")
    else()
        set(_suite_disp "${_suite}")
    endif()
    if(NOT origin STREQUAL "in-tree")
        message(STATUS
            "TC8: ${origin} case '${_suite_disp}:${case_id}' collected from "
            "${case_dir} (traits: ${traits_kind})")
    endif()

    set(stub_path    ${stub_dir}/${case_id}_register.cpp)
    set(stub_content
        "// Auto-generated by CMake. Do not edit.\n"
        "// Pulls the TC8_REGISTER_CASE inline registrar from the case's\n"
        "// traits header into the link.\n"
        ${suite_defines}
        "#include \"${case_header}\"\n")
    set(existing "")
    if(EXISTS ${stub_path})
        file(READ ${stub_path} existing)
    endif()
    string(JOIN "" stub_joined ${stub_content})
    if(NOT "${existing}" STREQUAL "${stub_joined}")
        file(WRITE ${stub_path} "${stub_joined}")
    endif()
    list(APPEND TC8_CASE_STUBS ${stub_path})
    set(TC8_CASE_STUBS ${TC8_CASE_STUBS} PARENT_SCOPE)
endfunction()

# Shared sanity checks for an out-of-tree injection root: a mistyped path
# or a flat .scxml layout would otherwise inject nothing, silently.
function(tc8_check_injection_root root_dir var_name)
    if(NOT IS_DIRECTORY ${root_dir})
        message(FATAL_ERROR
            "${var_name}: '${root_dir}' is not a directory — check the "
            "configured path")
    endif()
    file(GLOB _stray_scxml ${root_dir}/*.scxml)
    if(_stray_scxml)
        message(FATAL_ERROR
            "${var_name}: found .scxml file(s) directly under "
            "'${root_dir}' — cases must live in <root>/<case_id>/ "
            "subdirectories: ${_stray_scxml}")
    endif()
endfunction()

# Pass 1 — collect the override map: case id → replacement dir.
set(_tc8_override_ids "")
foreach(override_root ${TC8_CASE_OVERRIDE_DIRS})
    tc8_check_injection_root(${override_root} TC8_CASE_OVERRIDE_DIRS)
    set(_tc8_root_hits 0)
    file(GLOB _tc8_override_case_dirs LIST_DIRECTORIES true CONFIGURE_DEPENDS
         ${override_root}/*)
    foreach(case_dir ${_tc8_override_case_dirs})
        if(NOT IS_DIRECTORY ${case_dir})
            continue()
        endif()
        get_filename_component(case_id ${case_dir} NAME)
        if(case_id MATCHES "^_")
            message(STATUS
                "TC8: skipping auxiliary directory '${case_dir}' "
                "(leading underscore)")
            continue()
        endif()
        if(NOT IS_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests/${case_id})
            message(FATAL_ERROR
                "TC8_CASE_OVERRIDE_DIRS: '${case_dir}' does not match any "
                "in-tree tests/${case_id}/ — overrides must replace an "
                "existing case; use TC8_EXTRA_CASE_DIRS for new cases")
        endif()
        if(case_id IN_LIST _tc8_override_ids)
            message(FATAL_ERROR
                "TC8_CASE_OVERRIDE_DIRS: case '${case_id}' overridden by "
                "more than one directory")
        endif()
        list(APPEND _tc8_override_ids ${case_id})
        set(_tc8_override_dir_${case_id} ${case_dir})
        math(EXPR _tc8_root_hits "${_tc8_root_hits} + 1")
    endforeach()
    if(_tc8_root_hits EQUAL 0)
        message(WARNING
            "TC8_CASE_OVERRIDE_DIRS: '${override_root}' contains no case "
            "subdirectories — nothing overridden from this root")
    endif()
endforeach()

# Pass 2 — in-tree cases; an overridden id is collected from its
# replacement dir instead. Leading-underscore directories (e.g.
# tests/_templates/) are auxiliary — sce:template fragments, shared
# fixtures — not TC8 cases. Skip them so they don't try to resolve a
# non-existent traits header.
set(_tc8_intree_count 0)
set(_tc8_overrides_applied 0)
file(GLOB TC8_CASE_DIRS LIST_DIRECTORIES true CONFIGURE_DEPENDS
     ${CMAKE_CURRENT_SOURCE_DIR}/tests/*)
foreach(case_dir ${TC8_CASE_DIRS})
    if(NOT IS_DIRECTORY ${case_dir})
        continue()
    endif()
    get_filename_component(case_id ${case_dir} NAME)
    if(case_id MATCHES "^_")
        message(STATUS
            "TC8: skipping auxiliary directory '${case_dir}' "
            "(leading underscore)")
        continue()
    endif()
    if(case_id IN_LIST _tc8_override_ids)
        tc8_add_case(${_tc8_override_dir_${case_id}} override "")
        math(EXPR _tc8_overrides_applied "${_tc8_overrides_applied} + 1")
    else()
        tc8_add_case(${case_dir} in-tree "")
        math(EXPR _tc8_intree_count "${_tc8_intree_count} + 1")
    endif()
endforeach()

# Every collected override id matched an in-tree case (pass 1 enforces
# it), so the applied count can only diverge from the map size if the
# in-tree glob and the existence check raced a concurrent tree edit —
# fail loudly rather than ship a partially-applied override set.
list(LENGTH _tc8_override_ids _tc8_overrides_requested)
if(NOT _tc8_overrides_applied EQUAL _tc8_overrides_requested)
    message(FATAL_ERROR
        "TC8: ${_tc8_overrides_requested} override(s) requested but "
        "${_tc8_overrides_applied} applied — tests/ changed during "
        "configure; re-run cmake")
endif()

# Pass 3 — out-of-tree additional cases. Each injection root carries a suite
# (TC8_EXTRA_CASE_SUITES, index-aligned with TC8_EXTRA_CASE_DIRS; an empty or
# missing entry, or the default-suite name, selects the in-tree default).
# Identity is (suite, case_id): a case id shared with an in-tree case is allowed
# ONLY under a non-default suite — that is the suite axis. A default-suite extra
# that shadows tests/<id>/ stays an error (replacing a case must be explicit via
# TC8_CASE_OVERRIDE_DIRS).
list(LENGTH TC8_EXTRA_CASE_DIRS _tc8_dir_count)
list(LENGTH TC8_EXTRA_CASE_SUITES _tc8_suite_count)
if(_tc8_suite_count GREATER _tc8_dir_count)
    message(FATAL_ERROR
        "TC8_EXTRA_CASE_SUITES has ${_tc8_suite_count} entries but "
        "TC8_EXTRA_CASE_DIRS has ${_tc8_dir_count} — the two lists are "
        "index-aligned; remove the surplus suite name(s)")
endif()
set(_tc8_extra_keys "")
set(_tc8_extra_root_index 0)
foreach(extra_root ${TC8_EXTRA_CASE_DIRS})
    tc8_check_injection_root(${extra_root} TC8_EXTRA_CASE_DIRS)
    if(_tc8_extra_root_index LESS _tc8_suite_count)
        list(GET TC8_EXTRA_CASE_SUITES ${_tc8_extra_root_index} _tc8_raw_suite)
    else()
        set(_tc8_raw_suite "")
    endif()
    # Normalise to the registry's case-insensitive identity; an empty entry or
    # the default name both resolve to the in-tree default suite.
    string(TOLOWER "${_tc8_raw_suite}" _tc8_root_suite)
    if(_tc8_root_suite STREQUAL "" OR _tc8_root_suite STREQUAL "${TC8_DEFAULT_SUITE}")
        set(_tc8_root_suite "${TC8_DEFAULT_SUITE}")
        set(_tc8_root_is_default TRUE)
    else()
        set(_tc8_root_is_default FALSE)
    endif()
    set(_tc8_root_hits 0)
    file(GLOB _tc8_extra_case_dirs LIST_DIRECTORIES true CONFIGURE_DEPENDS
         ${extra_root}/*)
    foreach(case_dir ${_tc8_extra_case_dirs})
        if(NOT IS_DIRECTORY ${case_dir})
            continue()
        endif()
        get_filename_component(case_id ${case_dir} NAME)
        if(case_id MATCHES "^_")
            message(STATUS
                "TC8: skipping auxiliary directory '${case_dir}' "
                "(leading underscore)")
            continue()
        endif()
        if(_tc8_root_is_default AND
           IS_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests/${case_id})
            message(FATAL_ERROR
                "TC8_EXTRA_CASE_DIRS: '${case_dir}' collides with in-tree "
                "tests/${case_id}/ in the default suite — replace it via "
                "TC8_CASE_OVERRIDE_DIRS, or give this root a distinct suite "
                "name via TC8_EXTRA_CASE_SUITES")
        endif()
        set(_tc8_key "${_tc8_root_suite}:${case_id}")
        if(_tc8_key IN_LIST _tc8_extra_keys)
            message(FATAL_ERROR
                "TC8_EXTRA_CASE_DIRS: case '${_tc8_root_suite}:${case_id}' "
                "provided by more than one directory")
        endif()
        list(APPEND _tc8_extra_keys ${_tc8_key})
        tc8_add_case(${case_dir} extra "${_tc8_root_suite}")
        math(EXPR _tc8_root_hits "${_tc8_root_hits} + 1")
    endforeach()
    if(_tc8_root_hits EQUAL 0)
        message(WARNING
            "TC8_EXTRA_CASE_DIRS: '${extra_root}' contains no case "
            "subdirectories — nothing added from this root")
    endif()
    math(EXPR _tc8_extra_root_index "${_tc8_extra_root_index} + 1")
endforeach()

list(LENGTH _tc8_extra_keys _tc8_extra_count)
message(STATUS
    "TC8: case collection complete — ${_tc8_intree_count} in-tree, "
    "${_tc8_overrides_applied} overridden, ${_tc8_extra_count} "
    "out-of-tree extra")
target_sources(tc8-harness PRIVATE ${TC8_CASE_STUBS})
target_include_directories(tc8-harness PRIVATE
    src
    # The tester's own CLI command headers (capture_driver/live/replay/test/…),
    # exposed under the cli/ prefix from their owning sub-dir. Private to the two
    # executables that compile the commands (this one and tc8-testability-send);
    # kept off tc8_harness_core's public surface so a dep-light test linking the
    # core cannot reach the tester's libpcap/CLI11 command headers.
    src/cli/commands/include
    include
    third_party/CLI11
    ${TC8_CASE_GEN_DIR}
    ${PCAP_INCLUDE_DIR}
    ${LIBTINS_INCLUDE_DIR}
)
target_link_libraries(tc8-harness PRIVATE
    tc8_someiptp
    # tc8_e2e (AUTOSAR E2E Profile 5/11 checker engine) is linked so out-of-tree
    # cases injected via TC8_EXTRA_CASE_DIRS can resolve tc8::e2e::Profile*Checker
    # for E2E verdicts. No in-tree consumer references it, so the static archive
    # contributes no objects to the base binary (nothing to dead-strip differently).
    tc8_e2e
    vsomeip3
    CommonAPI
    CommonAPI-SomeIP
    sce_base
    tc8_wire
    # The stateless wire builders + SOME/IP dissectors, shared with the portability
    # check and the unit tests. Carries tc8_wire / tc8_someiptp / Threads transitively.
    tc8_stimulus
    # The dependency-light harness core (capture, CLI helpers, case registry, socket
    # responders) shared with the unit tests. Carries tc8_stimulus transitively.
    tc8_harness_core
    # The tester-side testability client (testability-probe + the case-side
    # primitives). The same archive the UTM SDK exports, so the harness drives a
    # DUT through exactly the client an out-of-tree consumer gets.
    tc8_testability_client
    Threads::Threads
    ${PCAP_LIBRARY}
    ${LIBTINS_LIBRARY}
)
tc8_enable_strict_warnings(tc8-harness)

endif() # TC8_BUILD_HARNESS

# Unconditional: dut/ hosts BOTH the vsomeip ETS mock DUT (gated internally by
# TC8_BUILD_MOCK_DUT, declared with the build-shape options above) and the
# vendor-neutral testability UTM that the tc8-utm SDK exports — and the latter
# must not depend on the former. Gating this whole subdirectory on the option is
# what previously made -DTC8_BUILD_MOCK_DUT=OFF (the hosted build-test CI
# configuration) silently drop the SDK and its export gate. See dut/CMakeLists.txt
# for the layer split.
add_subdirectory(dut)

if(TC8_BUILD_UNIT_TESTS)
    enable_testing()
    add_subdirectory(unit_tests)

    # NDA-hygiene lint (UTM SDK Part F): fail the build if a confidentiality
    # banner — the signature of pasted OEM-proprietary content — lands in the
    # tracked source. A source-only grep, so it runs in the same `ctest` the
    # build-test CI job runs, alongside utm_export_smoke.
    add_test(NAME nda_hygiene
        COMMAND ${CMAKE_COMMAND}
            -DTC8_SOURCE_DIR=${PROJECT_SOURCE_DIR}
            -P ${PROJECT_SOURCE_DIR}/cmake/check-nda-hygiene.cmake)
endif()

# ── Out-of-tree UTM SDK (PRS_TPSP §6.6 stateful extension) ──
# Export the vendor-neutral testability UTM — the ProtocolServer, the
# MiddlewareModule / MiddlewareContext seam, and the POSIX SocketBackend — as a
# find_package(tc8-utm) package so a separate, PRIVATE OEM repository links it
# and attaches its own service-group modules without vendoring this tree. The
# exported surface is public-standard only (AUTOSAR Testability + IETF RFC); it
# carries no OEM-specific content. Install with: cmake --install <build>
# --component utm-sdk --prefix <dir>.
#
# Both halves of the protocol ship: the DUT-side endpoint above and the
# tester-side client (tc8_testability_client) that drives it. A module attached to
# the endpoint is only reachable over the wire, so exporting the endpoint alone
# would leave each consumer to hand-roll a client and re-derive the framing rules
# include/tc8/testability_protocol.h owns. The client speaks the standard protocol
# and carries no OEM content, so it belongs on this same standard-only surface.
# utm_export_smoke holds the pairing: its consumer drives its own registered
# module through the exported client, so dropping either half fails the gate.
option(TC8_UTM_INSTALL
    "Install the testability UTM (DUT endpoint + tester client) as a find_package(tc8-utm) package"
    ON)

if(TC8_UTM_INSTALL AND TARGET tc8_testability_server)
    include(GNUInstallDirs)
    include(CMakePackageConfigHelpers)

    # Install-tree include root for the exported targets (the build-tree paths
    # are already BUILD_INTERFACE-scoped, so this is purely additive).
    target_include_directories(tc8_wire INTERFACE
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
    # The ports target carries the install-tree include root for the seam headers;
    # the core, the POSIX backend, and the alias all inherit it via their link to
    # the ports.
    target_include_directories(tc8_testability_ports INTERFACE
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
    # The POSIX adapter also installs its own header (posix_socket_backend.h) at the
    # include root, so it carries the install include for consumers of that header.
    target_include_directories(tc8_posix_backend INTERFACE
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
    # The tester-side client installs its own header (tc8/testability_client.h) and
    # reaches the codec SSOT (tc8/testability_protocol.h) — both under the one
    # install-tree include root, which its BUILD_INTERFACE include root collapses onto.
    target_include_directories(tc8_testability_client INTERFACE
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
    # AUTOSAR engines join the same exported surface so the OEM repo links the
    # mechanism it composes with its config. The set is TC8_UTM_ENGINES, built up
    # by tc8_add_engine() — there is one engine list, so the export cannot drift
    # from the build. The utm_export_smoke gate (the consumer calls each engine)
    # then fails if one is dropped from the export.
    foreach(_eng ${TC8_UTM_ENGINES})
        target_include_directories(${_eng} INTERFACE
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
    endforeach()

    # Export the ports (the seam), the split archives (core + POSIX adapter), the
    # INTERFACE convenience union, and the tester-side client. install(EXPORT)
    # checks the link closure, so a target that an exported one LINKS must itself
    # be exported — that is what protects tc8_wire and tc8_testability_ports, and
    # a dropped one fails install rather than a consumer. It does NOT protect the
    # closure roots: nothing links the client or the engines, so dropping either
    # leaves install(EXPORT) happy and breaks the consumer's find_package instead.
    # Those are held by utm_export_smoke, which links and drives them.
    install(TARGETS tc8_testability_server tc8_testability_core tc8_posix_backend
            tc8_testability_ports tc8_wire tc8_testability_client ${TC8_UTM_ENGINES}
        EXPORT tc8-utm-targets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT utm-sdk)

    # The codec SSOT — shared by the exported client and the exported endpoint, the
    # reason both decode identically.
    # Every public header ships under ONE namespaced root, include/tc8/ — never a
    # bare net/ or wire/ in the consumer's include path. An SDK cannot know what
    # else shares the prefix it is installed into (/usr/local is the common case),
    # and `net/socket_backend.h` or `wire/ip_checksum.h` are names an OEM tree
    # plausibly owns too; only the tc8/ prefix makes the spelling unambiguous.
    # The layout mirrors the source tree under include/tc8/ exactly, so the in-tree
    # and install-tree spellings are identical and cannot drift apart.
    install(FILES ${PROJECT_SOURCE_DIR}/include/tc8/testability_protocol.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tc8 COMPONENT utm-sdk)
    # The tester-side client: the standard primitives plus the generic
    # testabilityCall engine an OEM's own typed wrappers build on. Sits beside the
    # codec it frames against — the protocol's two public faces, one directory.
    install(FILES ${PROJECT_SOURCE_DIR}/include/tc8/testability_client.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tc8 COMPONENT utm-sdk)
    install(FILES
            ${PROJECT_SOURCE_DIR}/include/tc8/testability/middleware.h
            ${PROJECT_SOURCE_DIR}/include/tc8/testability/protocol_server.h
            ${PROJECT_SOURCE_DIR}/include/tc8/testability/socket_backend.h
            ${PROJECT_SOURCE_DIR}/include/tc8/testability/io_multiplexer.h
            ${PROJECT_SOURCE_DIR}/include/tc8/testability/reactor.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tc8/testability COMPONENT utm-sdk)
    install(FILES ${PROJECT_SOURCE_DIR}/include/tc8/net/socket_backend.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tc8/net COMPONENT utm-sdk)
    install(FILES
            ${PROJECT_SOURCE_DIR}/include/tc8/wire/icmp_echo.h
            ${PROJECT_SOURCE_DIR}/include/tc8/wire/ip_checksum.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tc8/wire COMPONENT utm-sdk)
    # One engine header per engine, globbed so a new engine's header installs
    # without a second list. include/tc8/autosar/ holds exactly the public engine
    # headers, so the glob cannot sweep an internal one into the export.
    file(GLOB _tc8_autosar_headers CONFIGURE_DEPENDS
        ${PROJECT_SOURCE_DIR}/include/tc8/autosar/*.h)
    install(FILES ${_tc8_autosar_headers}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tc8/autosar COMPONENT utm-sdk)
    install(FILES ${PROJECT_SOURCE_DIR}/include/tc8/posix_socket_backend.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tc8 COMPONENT utm-sdk)

    # ── The SDK's runnable tool: tc8-testability-send ──
    # The exported client library lets a consumer speak the protocol, but the
    # only CLI that addresses an arbitrary (GID, PID) — testability-send — lives
    # in the tc8-harness executable, which an SDK-only build gates off
    # (TC8_BUILD_HARNESS=OFF, no vsomeip/libpcap/libtins). So the SDK ships that
    # command as its own standalone executable: a consumer that links tc8-utm and
    # attaches its service groups gets a runnable way to drive the standard groups
    # its DUT now serves, without rebuilding the wire runner it configured out.
    #
    # It compiles the SAME command TU the harness does (testability_send_command
    # .cpp) behind a thin main, and links only the exported tc8_testability_client
    # (POSIX sockets + the header-only codec SSOT) and header-only CLI11 — none of
    # the harness's heavy prerequisites — so there is one codec/client path and the
    # two footprints cannot drift. Guarded by the SDK-install path, not
    # TC8_BUILD_HARNESS, so it is present exactly when the SDK it serves is.
    add_executable(tc8-testability-send
        ${PROJECT_SOURCE_DIR}/src/cli/testability_send_main.cpp
        ${PROJECT_SOURCE_DIR}/src/cli/testability_send_command.cpp)
    # Only the command header it shares with the harness (cli/testability_send_command
    # .h, from the tester-command include root) plus header-only CLI11; the tc8/...
    # protocol + client headers arrive via tc8_testability_client's public include/.
    # No flat src/ root — this SDK tool depends on nothing else under the source tree.
    target_include_directories(tc8-testability-send PRIVATE
        ${PROJECT_SOURCE_DIR}/src/cli/commands/include
        ${PROJECT_SOURCE_DIR}/third_party/CLI11)
    target_link_libraries(tc8-testability-send PRIVATE tc8_testability_client)
    tc8_enable_strict_warnings(tc8-testability-send)
    install(TARGETS tc8-testability-send
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT utm-sdk)

    # ── Optional lwIP backend (utm-sdk-lwip component) ──
    # SDK surface: the lwIP SocketBackend bridge + the self-contained UTM lwipopts.
    # Shipped as SOURCE because they compile against the OEM's own (target-specific)
    # lwIP stack — the SDK ships the bridge to the testability seam, not the stack.
    # These are the EXACT files the in-tree tc8-lwip-utm builds (dut/lwip_dut), so
    # build-lwip-dut keeps them compiling — no hand-copy to drift. An lwIP OEM
    # installs utm-sdk too (the bridge's header pulls in net/ + testability/, the
    # .cpp pulls in wire/), compiles lwip_socket_backend.cpp into its UTM against
    # lwip/lwipopts.h, and links tc8::tc8_testability_core (the backend-agnostic
    # core, no POSIX adapter).
    install(FILES ${PROJECT_SOURCE_DIR}/dut/lwip_dut/lwip_socket_backend.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} COMPONENT utm-sdk-lwip)
    install(FILES ${PROJECT_SOURCE_DIR}/dut/lwip_dut/lwip_socket_backend.cpp
        DESTINATION ${CMAKE_INSTALL_DATADIR}/tc8-utm/lwip COMPONENT utm-sdk-lwip)
    # The UTM lwIP config: lwipopts_base.h (the product-neutral infra shared with
    # the conformance fixture — single source of truth) + the utm/ layer (LWIP_IGMP
    # + multicast TX for join/leave; lwIP's default assert, no fixture sink) which
    # #includes "../lwipopts_base.h". Both ship preserving that relative layout, so
    # point lwIP at lwip/utm/. These are the exact files the in-tree tc8-lwip-utm
    # compiles, so the reference cannot drift. The lwIP stack and the final config
    # are the OEM's — a working reference.
    install(FILES ${PROJECT_SOURCE_DIR}/dut/lwip_dut/lwipopts_base.h
        DESTINATION ${CMAKE_INSTALL_DATADIR}/tc8-utm/lwip COMPONENT utm-sdk-lwip)
    install(FILES ${PROJECT_SOURCE_DIR}/dut/lwip_dut/utm/lwipopts.h
        DESTINATION ${CMAKE_INSTALL_DATADIR}/tc8-utm/lwip/utm COMPONENT utm-sdk-lwip)
    # The UTM's RFC 6528 ISN generator, named by utm/lwipopts.h's LWIP_HOOK_TCP_ISN /
    # LWIP_HOOK_FILENAME. tc8-owned and self-contained: the hook header (named by the
    # lwipopts so the OEM's lwIP core resolves it on the include path), the bring-up
    # seed seam, and the AES-CMAC implementation. The OEM compiles tc8_lwip_tcp_isn.cpp
    # into its UTM and links the already-exported AES-CMAC engine (utm-sdk's
    # tc8::...crypto) — there is NO dependency on the lwIP-contrib tcp_isn addon, the
    # PPP tree, or its MD5: the exported stack config builds from these files plus the
    # OEM's own lwIP checkout. These are the exact files tc8-lwip-utm compiles, so the
    # reference cannot drift. Shipped next to lwipopts_base.h (the dir the OEM puts on
    # the include path for the hook header).
    install(FILES
            ${PROJECT_SOURCE_DIR}/dut/lwip_dut/tc8_lwip_utm_hooks.h
            ${PROJECT_SOURCE_DIR}/dut/lwip_dut/tc8_lwip_isn.h
            ${PROJECT_SOURCE_DIR}/dut/lwip_dut/tc8_lwip_tcp_isn.cpp
        DESTINATION ${CMAKE_INSTALL_DATADIR}/tc8-utm/lwip COMPONENT utm-sdk-lwip)

    # EXAMPLE (not stable SDK surface): the stack bring-up. Bringing the stack up —
    # netif selection, address, RFC 6528 ISN seed, process park — is the composition
    # root's job and is target-specific (a real embedded netif replaces this
    # unix-tapif version). Shipped under example/ as a working reference the OEM
    # copies and adapts; it needs the unix-port default_netif on the OEM's lwIP
    # include path and the ISN seam impl above. It is fixture-free (fault hooks come
    # via the afterNetifUp callback, the assert sink stays in the DUT), and it seeds
    # the ISN through the tc8_lwip_isn.h seam, so it carries no contrib dependency.
    install(FILES
            ${PROJECT_SOURCE_DIR}/dut/lwip_dut/lwip_stack_bringup.h
            ${PROJECT_SOURCE_DIR}/dut/lwip_dut/lwip_stack_bringup.cpp
        DESTINATION ${CMAKE_INSTALL_DATADIR}/tc8-utm/lwip/example COMPONENT utm-sdk-lwip)

    install(EXPORT tc8-utm-targets
        NAMESPACE tc8::
        FILE tc8-utm-targets.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/tc8-utm COMPONENT utm-sdk)

    configure_package_config_file(
        ${PROJECT_SOURCE_DIR}/cmake/tc8-utm-config.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/tc8-utm-config.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/tc8-utm)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/tc8-utm-config.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/tc8-utm COMPONENT utm-sdk)

    # Make the export a verified gate: a CTest that installs the utm-sdk to a
    # temp prefix and builds examples/oem-utm-consumer against it via
    # find_package(tc8-utm). Runs in the same `ctest` the build-test CI job runs,
    # so a dropped header or broken install-interface fails CI, not a human.
    if(TC8_BUILD_UNIT_TESTS)
        add_test(NAME utm_export_smoke
            COMMAND ${CMAKE_COMMAND}
                -DTC8_BUILD_DIR=${CMAKE_BINARY_DIR}
                -DTC8_SOURCE_DIR=${PROJECT_SOURCE_DIR}
                -DTC8_CMAKE=${CMAKE_COMMAND}
                -DTC8_GENERATOR=${CMAKE_GENERATOR}
                -P ${PROJECT_SOURCE_DIR}/cmake/verify-utm-export.cmake)
    endif()
endif()

option(TC8_AUTO_SETCAP
    "Apply cap_net_raw,cap_net_admin after build (requires sudoers NOPASSWD for /usr/sbin/setcap)"
    OFF)

if(TC8_AUTO_SETCAP AND TARGET tc8-harness AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_program(SETCAP_BIN setcap REQUIRED)
    add_custom_command(TARGET tc8-harness POST_BUILD
        COMMAND sudo -n ${SETCAP_BIN}
                cap_net_raw,cap_net_admin=eip
                $<TARGET_FILE:tc8-harness>
        COMMENT "Applying cap_net_raw,cap_net_admin via sudo -n"
        VERBATIM)
endif()
