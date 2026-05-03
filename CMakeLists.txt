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
    src/wire/ip_checksum.cpp
)

# Each TC8 case lives in tests/<case_id>/ with its SCXML. The matching
# src/sce_integration/cases/<case_id>.h carries the TestCaseTraits
# specialization and a TC8_REGISTER_CASE() inline registrar. CMake generates
# a thin translation unit per case that includes the header, forcing the
# registrar to be pulled into the final link — so adding a case is just
# tests/<id>/<id>.scxml + src/sce_integration/cases/<id>.h.
set(TC8_CASE_STUBS_DIR ${CMAKE_BINARY_DIR}/gen/cases_stubs)
file(MAKE_DIRECTORY ${TC8_CASE_STUBS_DIR})
set(TC8_CASE_STUBS)

file(GLOB TC8_CASE_DIRS LIST_DIRECTORIES true CONFIGURE_DEPENDS
     ${CMAKE_CURRENT_SOURCE_DIR}/tests/*)
foreach(case_dir ${TC8_CASE_DIRS})
    if(IS_DIRECTORY ${case_dir})
        get_filename_component(case_dir_name ${case_dir} NAME)
        # Leading-underscore directories (e.g. tests/_templates/) are
        # auxiliary — sce:template fragments, shared fixtures — not TC8
        # cases. Skip them so they don't try to resolve a non-existent
        # traits header.
        if(case_dir_name MATCHES "^_")
            continue()
        endif()
        sce_add_state_machines_from_dir(
            TARGET    tc8-harness
            SCXML_DIR ${case_dir})

        get_filename_component(case_id ${case_dir} NAME)

        set(case_header
            ${CMAKE_CURRENT_SOURCE_DIR}/src/sce_integration/cases/${case_id}.h)
        if(NOT EXISTS ${case_header})
            message(FATAL_ERROR
                "tests/${case_id}/ present but "
                "src/sce_integration/cases/${case_id}.h is missing")
        endif()

        set(stub_path    ${TC8_CASE_STUBS_DIR}/${case_id}_register.cpp)
        set(stub_content
            "// Auto-generated by CMake. Do not edit.\n"
            "// Pulls the TC8_REGISTER_CASE inline registrar from\n"
            "// sce_integration/cases/${case_id}.h into the link.\n"
            "#include \"sce_integration/cases/${case_id}.h\"\n")
        set(existing "")
        if(EXISTS ${stub_path})
            file(READ ${stub_path} existing)
        endif()
        string(JOIN "" stub_joined ${stub_content})
        if(NOT "${existing}" STREQUAL "${stub_joined}")
            file(WRITE ${stub_path} "${stub_joined}")
        endif()
        list(APPEND TC8_CASE_STUBS ${stub_path})
    endif()
endforeach()
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
