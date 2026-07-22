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

# Shared IPv4-family wire math (tc8_wire) — RFC 1071 Internet checksum + RFC 792
# ICMP echo body. A dependency-light leaf STATIC lib built in its own component
# dir; linked by the harness, tc8-dut, the testability server and the unit tests,
# and exported on the UTM SDK surface (install wiring in the TC8_UTM_INSTALL block).
add_subdirectory(src/wire)

# The tester-side AUTOSAR Testability Protocol client (tc8_testability_client) —
# the standard counterpart to the DUT-side endpoint in dut/dut_service. Built in
# its own component dir; dependency-light (POSIX sockets + the header-only codec
# SSOT, no threads/pcap/vsomeip) so it cross-compiles, and exported on the UTM SDK
# surface (install wiring in the TC8_UTM_INSTALL block).
add_subdirectory(src/testability_client)

# Vendor-neutral AUTOSAR engines (src/autosar/) — the dependency-light byte-math
# mechanisms (crypto / pn / crc / e2e / com / nm / someiptp) an OEM UTM module
# composes with its own config. Built in their own component dir via the
# tc8_add_engine recipe; each also joins TC8_UTM_ENGINES (propagated back to this
# scope) for the UTM SDK export wired in the TC8_UTM_INSTALL block below.
add_subdirectory(src/autosar)

# Threads — tc8_stimulus PUBLIC-links Threads::Threads (someip_sd_builder /
# upper_tester_client use std::this_thread::sleep_for). Resolved here in the
# top-level scope so the component dir and every later consumer (tc8_harness_core
# inherits it transitively) see the one imported target.
find_package(Threads REQUIRED)

# tc8_stimulus — the stateless wire-frame builders (src/stimulus) plus the SOME/IP
# header dissectors (src/dissect). Pure byte-layout code, no libpcap/libtins/vsomeip,
# so it cross-compiles; the tester, the portability check, and the unit tests all
# link it. Built in its own component dir, which also owns the sibling src/dissect
# dissector sources — one library over two single-owner dirs.
add_subdirectory(src/stimulus)

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
# executable and the unit tests (pcap capture, the expect/summary CLI helpers, the
# SCE case registry + spec inventory, and the socket responders). Built in its own
# component dir — which aggregates the library's four single-owner subtrees (capture/,
# cli/, sce_integration/, stimulus/responders/) — only when the tester or the unit
# tests are; an SDK-only configure needs none of it. PCAP_INCLUDE_DIR (found above)
# is inherited by the subdir scope.
if(TC8_BUILD_HARNESS OR TC8_BUILD_UNIT_TESTS)
    add_subdirectory(src/harness_core)
endif()

# ── Tester executable + per-case state machines (TC8_BUILD_HARNESS) ──────────
# The tc8-harness tester and its SCE case machinery — built in the src/harness
# component dir. None of it is reachable from the exported SDK, so an SDK-only
# configure (TC8_BUILD_HARNESS=OFF) skips the SOME/IP link, the whole case glob,
# and the codegen probe (mirroring the portability check's early return above).
if(TC8_BUILD_HARNESS)
    add_subdirectory(src/harness)
endif()

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
        ${PROJECT_SOURCE_DIR}/src/cli/commands/testability_send_main.cpp
        ${PROJECT_SOURCE_DIR}/src/cli/commands/testability_send_command.cpp)
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
