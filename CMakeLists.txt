cmake_minimum_required(VERSION 3.16)
project(tc8-harness LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Strict warnings applied to first-party targets (tc8-harness and the
# `tc8_harness_testable` library used by unit tests). SCE-generated /
# third-party headers live behind SYSTEM include paths where available,
# so they do not contribute to this warning set. `-Werror` is not on by
# default — flip via `-DTC8_WARNINGS_AS_ERRORS=ON` once the tree is clean.
function(tc8_enable_strict_warnings target)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target} PRIVATE
            -Wall
            -Wextra
            -Wpedantic
            -Wshadow
            -Wconversion
            -Wsign-conversion
            -Wnon-virtual-dtor
            -Wold-style-cast
            -Woverloaded-virtual
            -Wdouble-promotion
            -Wformat=2
        )
        if(TC8_WARNINGS_AS_ERRORS)
            target_compile_options(${target} PRIVATE -Werror)
        endif()
    endif()
endfunction()

option(TC8_WARNINGS_AS_ERRORS
    "Promote compiler warnings to errors on first-party targets"
    ON)

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
target_include_directories(tc8_wire PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>)
tc8_enable_strict_warnings(tc8_wire)

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
    target_include_directories(${name} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>)
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

# Portability check: cross-compile the dependency-light core — the SCE
# engine plus every wire builder / SOME/IP dissector where the
# endianness- and bit-layout-sensitive code lives — without needing a
# target sysroot for libpcap / libtins / vsomeip / CommonAPI. Used with
# cmake/toolchains/aarch64-linux-gnu.cmake to keep the embedded-tester
# (target-to-target topology) build path verifiable on a host with only
# a cross compiler installed. `return()` ends top-level processing: the
# heavy find_package set, the case glob, tc8-dut, and unit tests are
# all host-build concerns.
option(TC8_PORTABILITY_CHECK
    "Build only the dependency-light core (for cross-compile verification)"
    OFF)

if(TC8_PORTABILITY_CHECK)
    add_library(tc8-core-portability STATIC
        src/dissect/someip_header.cpp
        src/dissect/someip_dispatcher.cpp
        src/stimulus/arp_builder.cpp
        src/stimulus/dot1q.cpp
        src/stimulus/dhcpv4_frame_builder.cpp
        src/stimulus/ipv4_frame_builder.cpp
        src/stimulus/icmpv4_builder.cpp
        src/stimulus/someip_rpc_builder.cpp
        src/stimulus/someip_sd_builder.cpp
        src/stimulus/udp_emit.cpp
        src/stimulus/someip_tp_emit.cpp
        src/stimulus/tcp_segment_builder.cpp
        src/stimulus/udp_datagram_builder.cpp
        src/stimulus/upper_tester_client.cpp
        src/stimulus/testability_client.cpp
    )
    target_include_directories(tc8-core-portability PRIVATE src include)
    target_link_libraries(tc8-core-portability PRIVATE sce_base tc8_wire tc8_someiptp)
    tc8_enable_strict_warnings(tc8-core-portability)
    message(STATUS
        "TC8: portability-check configuration — building "
        "tc8-core-portability for ${CMAKE_SYSTEM_PROCESSOR} only; "
        "harness/tc8-dut/cases/unit tests are skipped (no target "
        "sysroot required)")
    return()
endif()

find_package(vsomeip3 REQUIRED)
find_package(CommonAPI REQUIRED)
find_package(CommonAPI-SomeIP REQUIRED)

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

add_executable(tc8-harness
    src/harness_main.cpp
    src/capture/pcap_source.cpp
    src/capture/bpf_filter.cpp
    src/dissect/someip_header.cpp
    src/dissect/someip_dispatcher.cpp
    src/dissect/packet_pipeline.cpp
    src/cli/signal_handler.cpp
    src/cli/capture_driver.cpp
    src/cli/expect_parser.cpp
    src/cli/live_command.cpp
    src/cli/replay_command.cpp
    src/cli/test_command.cpp
    src/cli/ut_ping_command.cpp
    src/cli/testability_probe_command.cpp
    src/sce_integration/case_registry.cpp
    src/sce_integration/dut_control_factory.cpp
    src/sce_integration/spec_inventory.cpp
    src/stimulus/arp_builder.cpp
    src/stimulus/dot1q.cpp
    src/stimulus/dhcpv4_frame_builder.cpp
    src/stimulus/ipv4_frame_builder.cpp
    src/stimulus/icmpv4_builder.cpp
    src/stimulus/someip_rpc_builder.cpp
    src/stimulus/someip_sd_builder.cpp
    src/stimulus/udp_emit.cpp
    src/stimulus/someip_tp_emit.cpp
    src/stimulus/tcp_segment_builder.cpp
    src/stimulus/udp_datagram_builder.cpp
    src/stimulus/upper_tester_client.cpp
    src/stimulus/testability_client.cpp
)

# Each TC8 case lives in tests/<case_id>/ with its SCXML. The matching
# src/sce_integration/cases/<case_id>.h carries the TestCaseTraits
# specialization and a TC8_REGISTER_CASE() inline registrar. CMake generates
# a thin translation unit per case that includes the header, forcing the
# registrar to be pulled into the final link — so adding a case is just
# tests/<id>/<id>.scxml + src/sce_integration/cases/<id>.h.
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
# first, then src/sce_integration/cases/<case_id>.h. An override that ships
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
        "Suite name per TC8_EXTRA_CASE_DIRS root (;-aligned); empty/missing => 'tc8'")
endif()

# gen/ holds both the registration stubs and the per-suite codegen output. Its
# root is on the tc8-harness include path so a non-default suite's generated SM
# header resolves via its suite-qualified path "<suite>/<case_id>_sm.h" (stamped
# by tc8_add_case) without colliding with the in-tree "<case_id>_sm.h" that
# carries the same case id. gen/ itself holds no top-level *_sm.h, so an in-tree
# bare include still resolves only against the default "generated/" dir.
set(TC8_CASE_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen)
set(TC8_CASE_STUBS_DIR ${TC8_CASE_GEN_DIR}/cases_stubs)
file(MAKE_DIRECTORY ${TC8_CASE_STUBS_DIR})
set(TC8_CASE_STUBS)

# Registers one case directory: SCXML codegen + traits-header resolution +
# registration-stub TU. Appends the stub to TC8_CASE_STUBS in the caller's
# scope. `origin` is "in-tree", "override", or "extra" — out-of-tree
# origins are logged per case (the in-tree bulk is already covered by the
# per-machine SCE codegen lines).
function(tc8_add_case case_dir origin suite)
    get_filename_component(case_id ${case_dir} NAME)

    # Default suite ("tc8" or empty): today's behavior, byte-identical. The SM
    # generates as ::SCE::Generated::<name> into the shared "generated/" dir and
    # the stub carries no suite define, so the ~750 in-tree cases are untouched.
    #
    # A non-default suite nests the SM under ::SCE::Generated::<suite>::<name> in
    # a per-suite output dir (so identical case ids never share a generated
    # file) and the stub stamps three tokens the OEM case header binds against,
    # suite-agnostically: TC8_CASE_SUITE (the registry identity string),
    # TC8_CASE_SUITE_NS (the C++ namespace token), and TC8_CASE_SM_HEADER (the
    # suite-qualified generated-header path). Distinct suite => distinct
    # namespace => distinct SM type => the gRegisterCase<SM> ODR invariant in
    # case_registry.h holds.
    if(suite STREQUAL "" OR suite STREQUAL "tc8")
        sce_add_state_machines_from_dir(
            TARGET    tc8-harness
            SCXML_DIR ${case_dir})
        set(stub_dir ${TC8_CASE_STUBS_DIR})
        set(suite_defines "")
    else()
        sce_add_state_machines_from_dir(
            TARGET               tc8-harness
            SCXML_DIR            ${case_dir}
            OUTPUT_DIR           ${TC8_CASE_GEN_DIR}/${suite}
            CPP_NAMESPACE_PREFIX ${suite})
        set(stub_dir ${TC8_CASE_STUBS_DIR}/${suite})
        file(MAKE_DIRECTORY ${stub_dir})
        set(suite_defines
            "#define TC8_CASE_SUITE \"${suite}\"\n"
            "#define TC8_CASE_SUITE_NS ${suite}\n"
            "#define TC8_CASE_SM_HEADER \"${suite}/${case_id}_sm.h\"\n")
    endif()

    set(case_header ${case_dir}/${case_id}.h)
    set(traits_kind "case-local")
    if(NOT EXISTS ${case_header})
        set(case_header
            ${CMAKE_CURRENT_SOURCE_DIR}/src/sce_integration/cases/${case_id}.h)
        set(traits_kind "in-tree")
    endif()
    if(NOT EXISTS ${case_header})
        message(FATAL_ERROR
            "TC8: case '${case_id}' (${case_dir}): no traits header at "
            "${case_dir}/${case_id}.h or "
            "src/sce_integration/cases/${case_id}.h")
    endif()

    if(NOT origin STREQUAL "in-tree")
        message(STATUS
            "TC8: ${origin} case '${suite}:${case_id}' collected from "
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
        tc8_add_case(${_tc8_override_dir_${case_id}} override tc8)
        math(EXPR _tc8_overrides_applied "${_tc8_overrides_applied} + 1")
    else()
        tc8_add_case(${case_dir} in-tree tc8)
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
# missing entry defaults to "tc8"). Identity is (suite, case_id): a case id
# shared with an in-tree case is allowed ONLY under a non-default suite — that
# is the suite axis. A default-suite extra that shadows tests/<id>/ stays an
# error (replacing a case must be explicit via TC8_CASE_OVERRIDE_DIRS).
set(_tc8_extra_keys "")
set(_tc8_extra_root_index 0)
list(LENGTH TC8_EXTRA_CASE_SUITES _tc8_suite_count)
foreach(extra_root ${TC8_EXTRA_CASE_DIRS})
    tc8_check_injection_root(${extra_root} TC8_EXTRA_CASE_DIRS)
    if(_tc8_extra_root_index LESS _tc8_suite_count)
        list(GET TC8_EXTRA_CASE_SUITES ${_tc8_extra_root_index} _tc8_root_suite)
    else()
        set(_tc8_root_suite "")
    endif()
    if(_tc8_root_suite STREQUAL "")
        set(_tc8_root_suite "tc8")
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
        if(_tc8_root_suite STREQUAL "tc8" AND
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
        tc8_add_case(${case_dir} extra ${_tc8_root_suite})
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
    include
    third_party/CLI11
    ${TC8_CASE_GEN_DIR}
    ${PCAP_INCLUDE_DIR}
    ${LIBTINS_INCLUDE_DIR}
)
target_link_libraries(tc8-harness PRIVATE
    tc8_someiptp
    vsomeip3
    CommonAPI
    CommonAPI-SomeIP
    sce_base
    tc8_wire
    ${PCAP_LIBRARY}
    ${LIBTINS_LIBRARY}
)
tc8_enable_strict_warnings(tc8-harness)

option(TC8_BUILD_MOCK_DUT
    "Build the DUT service (ETS stub) from dut/"
    ON)

if(TC8_BUILD_MOCK_DUT)
    add_subdirectory(dut)
endif()

option(TC8_BUILD_UNIT_TESTS
    "Build C++ unit tests in unit_tests/ (requires GTest)"
    ON)

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
# Export the vendor-neutral testability UTM core — the ProtocolServer, the
# MiddlewareModule / MiddlewareContext seam, and the POSIX SocketBackend — as a
# find_package(tc8-utm) package so a separate, PRIVATE OEM repository links it
# and attaches its own service-group modules without vendoring this tree. The
# exported surface is public-standard only (AUTOSAR Testability + IETF RFC); it
# carries no OEM-specific content. Install with: cmake --install <build>
# --component utm-sdk --prefix <dir>.
option(TC8_UTM_INSTALL
    "Install the testability UTM core as a find_package(tc8-utm) package"
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
    # AUTOSAR engines join the same exported surface so the OEM repo links the
    # mechanism it composes with its config. The set is TC8_UTM_ENGINES, built up
    # by tc8_add_engine() — there is one engine list, so the export cannot drift
    # from the build. The utm_export_smoke gate (the consumer calls each engine)
    # then fails if one is dropped from the export.
    foreach(_eng ${TC8_UTM_ENGINES})
        target_include_directories(${_eng} INTERFACE
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
    endforeach()

    # Export the ports (the seam), the split archives (core + POSIX adapter), and
    # the INTERFACE convenience union. install(EXPORT) checks the link closure, so
    # every target any exported one links must itself be exported — a dropped one
    # fails install, not a consumer.
    install(TARGETS tc8_testability_server tc8_testability_core tc8_posix_backend
            tc8_testability_ports tc8_wire ${TC8_UTM_ENGINES}
        EXPORT tc8-utm-targets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT utm-sdk)

    install(FILES ${PROJECT_SOURCE_DIR}/include/tc8/testability_protocol.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/tc8 COMPONENT utm-sdk)
    install(FILES
            ${PROJECT_SOURCE_DIR}/src/testability/middleware.h
            ${PROJECT_SOURCE_DIR}/src/testability/protocol_server.h
            ${PROJECT_SOURCE_DIR}/src/testability/socket_backend.h
            ${PROJECT_SOURCE_DIR}/src/testability/io_multiplexer.h
            ${PROJECT_SOURCE_DIR}/src/testability/reactor.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/testability COMPONENT utm-sdk)
    install(FILES ${PROJECT_SOURCE_DIR}/src/net/socket_backend.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/net COMPONENT utm-sdk)
    install(FILES
            ${PROJECT_SOURCE_DIR}/src/wire/icmp_echo.h
            ${PROJECT_SOURCE_DIR}/src/wire/ip_checksum.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/wire COMPONENT utm-sdk)
    # One engine header per engine, globbed so a new engine's header installs
    # without a second list (same source of truth as the lwIP src/autosar glob).
    file(GLOB _tc8_autosar_headers CONFIGURE_DEPENDS
        ${PROJECT_SOURCE_DIR}/src/autosar/*.h)
    install(FILES ${_tc8_autosar_headers}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/autosar COMPONENT utm-sdk)
    install(FILES ${PROJECT_SOURCE_DIR}/dut/dut_service/posix_socket_backend.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR} COMPONENT utm-sdk)

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

if(TC8_AUTO_SETCAP AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_program(SETCAP_BIN setcap REQUIRED)
    add_custom_command(TARGET tc8-harness POST_BUILD
        COMMAND sudo -n ${SETCAP_BIN}
                cap_net_raw,cap_net_admin=eip
                $<TARGET_FILE:tc8-harness>
        COMMENT "Applying cap_net_raw,cap_net_admin via sudo -n"
        VERBATIM)
endif()
