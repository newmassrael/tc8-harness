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
        src/stimulus/dhcpv4_frame_builder.cpp
        src/stimulus/ipv4_frame_builder.cpp
        src/stimulus/icmpv4_builder.cpp
        src/stimulus/someip_rpc_builder.cpp
        src/stimulus/someip_sd_builder.cpp
        src/stimulus/tcp_segment_builder.cpp
        src/stimulus/udp_datagram_builder.cpp
        src/stimulus/upper_tester_client.cpp
        src/stimulus/testability_client.cpp
        src/wire/ip_checksum.cpp
    )
    target_include_directories(tc8-core-portability PRIVATE src include)
    target_link_libraries(tc8-core-portability PRIVATE sce_base)
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
    src/sce_integration/spec_inventory.cpp
    src/stimulus/arp_builder.cpp
    src/stimulus/dhcpv4_frame_builder.cpp
    src/stimulus/ipv4_frame_builder.cpp
    src/stimulus/icmpv4_builder.cpp
    src/stimulus/someip_rpc_builder.cpp
    src/stimulus/someip_sd_builder.cpp
    src/stimulus/tcp_segment_builder.cpp
    src/stimulus/udp_datagram_builder.cpp
    src/stimulus/upper_tester_client.cpp
    src/stimulus/testability_client.cpp
    src/wire/ip_checksum.cpp
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

set(TC8_CASE_STUBS_DIR ${CMAKE_CURRENT_BINARY_DIR}/gen/cases_stubs)
file(MAKE_DIRECTORY ${TC8_CASE_STUBS_DIR})
set(TC8_CASE_STUBS)

# Registers one case directory: SCXML codegen + traits-header resolution +
# registration-stub TU. Appends the stub to TC8_CASE_STUBS in the caller's
# scope. `origin` is "in-tree", "override", or "extra" — out-of-tree
# origins are logged per case (the in-tree bulk is already covered by the
# per-machine SCE codegen lines).
function(tc8_add_case case_dir origin)
    get_filename_component(case_id ${case_dir} NAME)

    sce_add_state_machines_from_dir(
        TARGET    tc8-harness
        SCXML_DIR ${case_dir})

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
            "TC8: ${origin} case '${case_id}' collected from ${case_dir} "
            "(traits: ${traits_kind})")
    endif()

    set(stub_path    ${TC8_CASE_STUBS_DIR}/${case_id}_register.cpp)
    set(stub_content
        "// Auto-generated by CMake. Do not edit.\n"
        "// Pulls the TC8_REGISTER_CASE inline registrar from the case's\n"
        "// traits header into the link.\n"
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
        tc8_add_case(${_tc8_override_dir_${case_id}} override)
        math(EXPR _tc8_overrides_applied "${_tc8_overrides_applied} + 1")
    else()
        tc8_add_case(${case_dir} in-tree)
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

# Pass 3 — out-of-tree additional cases.
set(_tc8_extra_ids "")
foreach(extra_root ${TC8_EXTRA_CASE_DIRS})
    tc8_check_injection_root(${extra_root} TC8_EXTRA_CASE_DIRS)
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
        if(IS_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests/${case_id})
            message(FATAL_ERROR
                "TC8_EXTRA_CASE_DIRS: '${case_dir}' collides with in-tree "
                "tests/${case_id}/ — use TC8_CASE_OVERRIDE_DIRS to replace "
                "an existing case")
        endif()
        if(case_id IN_LIST _tc8_extra_ids)
            message(FATAL_ERROR
                "TC8_EXTRA_CASE_DIRS: case '${case_id}' provided by more "
                "than one directory")
        endif()
        list(APPEND _tc8_extra_ids ${case_id})
        tc8_add_case(${case_dir} extra)
        math(EXPR _tc8_root_hits "${_tc8_root_hits} + 1")
    endforeach()
    if(_tc8_root_hits EQUAL 0)
        message(WARNING
            "TC8_EXTRA_CASE_DIRS: '${extra_root}' contains no case "
            "subdirectories — nothing added from this root")
    endif()
endforeach()

list(LENGTH _tc8_extra_ids _tc8_extra_count)
message(STATUS
    "TC8: case collection complete — ${_tc8_intree_count} in-tree, "
    "${_tc8_overrides_applied} overridden, ${_tc8_extra_count} "
    "out-of-tree extra")
target_sources(tc8-harness PRIVATE ${TC8_CASE_STUBS})
target_include_directories(tc8-harness PRIVATE
    src
    include
    third_party/CLI11
    ${PCAP_INCLUDE_DIR}
    ${LIBTINS_INCLUDE_DIR}
)
target_link_libraries(tc8-harness PRIVATE
    vsomeip3
    CommonAPI
    CommonAPI-SomeIP
    sce_base
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
