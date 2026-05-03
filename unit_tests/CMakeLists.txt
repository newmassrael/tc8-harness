# Unit tests (GoogleTest). TC8 SCXML state-machine cases live in tests/
# at the repo root; this directory is for C++-level harness unit tests.

# GoogleTest pulled in via FetchContent so the build is hermetic across
# distros (Ubuntu's libgtest-dev ships sources only; RHEL/macOS have
# their own quirks). Pinned tag avoids silent upstream API drift.
include(FetchContent)
FetchContent_Declare(googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
)
# Prevent GoogleTest from overriding the parent project's compiler /
# linker settings on Windows. No-op on Linux but harmless.
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# A slim static library of the harness internals we want to unit-test,
# reused across every test executable so each one links the same
# implementation the main binary does.
add_library(tc8_harness_testable STATIC
    ${CMAKE_SOURCE_DIR}/src/capture/bpf_filter.cpp
    ${CMAKE_SOURCE_DIR}/src/cli/expect_parser.cpp
    ${CMAKE_SOURCE_DIR}/src/sce_integration/case_registry.cpp
    ${CMAKE_SOURCE_DIR}/src/stimulus/arp_builder.cpp
    ${CMAKE_SOURCE_DIR}/src/stimulus/ipv4_frame_builder.cpp
    ${CMAKE_SOURCE_DIR}/src/stimulus/icmpv4_builder.cpp
    ${CMAKE_SOURCE_DIR}/src/stimulus/someip_sd_builder.cpp
    ${CMAKE_SOURCE_DIR}/src/stimulus/tcp_segment_builder.cpp
    ${CMAKE_SOURCE_DIR}/src/stimulus/udp_datagram_builder.cpp
    ${CMAKE_SOURCE_DIR}/src/stimulus/upper_tester_client.cpp
    ${CMAKE_SOURCE_DIR}/src/wire/ip_checksum.cpp
)
target_include_directories(tc8_harness_testable PUBLIC
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
)
tc8_enable_strict_warnings(tc8_harness_testable)

function(tc8_add_unit_test name)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE
        tc8_harness_testable
        GTest::gtest
        GTest::gtest_main
    )
    target_include_directories(${name} PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/include
    )
    add_test(NAME ${name} COMMAND ${name})
endfunction()

tc8_add_unit_test(bpf_filter_test)
tc8_add_unit_test(case_registry_test)
tc8_add_unit_test(expect_parser_test)
tc8_add_unit_test(subscribe_builder_test)
tc8_add_unit_test(arp_builder_test)
tc8_add_unit_test(ipv4_frame_builder_test)
tc8_add_unit_test(icmpv4_builder_test)
tc8_add_unit_test(ipv4_decode_test)
tc8_add_unit_test(tcp_segment_builder_test)
tc8_add_unit_test(udp_datagram_builder_test)
tc8_add_unit_test(udp_captured_test)
tc8_add_unit_test(someip_captured_test)
tc8_add_unit_test(upper_tester_client_test)
