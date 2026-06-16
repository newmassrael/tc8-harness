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
    ${PROJECT_SOURCE_DIR}/src/capture/bpf_filter.cpp
    ${PROJECT_SOURCE_DIR}/src/cli/expect_parser.cpp
    ${PROJECT_SOURCE_DIR}/src/sce_integration/case_registry.cpp
    ${PROJECT_SOURCE_DIR}/src/sce_integration/spec_inventory.cpp
    ${PROJECT_SOURCE_DIR}/src/dissect/someip_header.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/arp_builder.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/dot1q.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/ipv4_frame_builder.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/icmpv4_builder.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/someip_sd_builder.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/tcp_segment_builder.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/udp_datagram_builder.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/upper_tester_client.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/testability_client.cpp
    ${PROJECT_SOURCE_DIR}/src/wire/ip_checksum.cpp
)
target_include_directories(tc8_harness_testable PUBLIC
    ${PROJECT_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/include
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
        ${PROJECT_SOURCE_DIR}/src
        ${PROJECT_SOURCE_DIR}/include
    )
    add_test(NAME ${name} COMMAND ${name})
endfunction()

tc8_add_unit_test(bpf_filter_test)
# bpf_filter_test pcap_compiles every group filter to prove the VLAN-aware
# wrap is valid libpcap syntax, so it links libpcap.
target_include_directories(bpf_filter_test PRIVATE ${PCAP_INCLUDE_DIR})
target_link_libraries(bpf_filter_test PRIVATE ${PCAP_LIBRARY})
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
tc8_add_unit_test(tcp_captured_test)
tc8_add_unit_test(upper_tester_client_test)
tc8_add_unit_test(testability_client_test)
# Server-side integration: drives the real DUT-side TestabilityServer
# (vsomeip-independent) with the client wrappers over loopback, covering the
# UDP and TCP service-primitive backends end to end. Links the shared
# tc8_testability_server library (whose PUBLIC includes carry the server header),
# so it builds whenever the DUT component does — no by-path source duplication.
if(TARGET tc8_testability_server)
    tc8_add_unit_test(testability_server_test)
    target_link_libraries(testability_server_test PRIVATE tc8_testability_server)
endif()
# Opcode-UT TCP control adapter, driven against a mock UT responder (the real
# opcode server needs a netns/veth topology, not loopback).
tc8_add_unit_test(opcode_tcp_control_test)
tc8_add_unit_test(iface_enumeration_test)
tc8_add_unit_test(spec_inventory_test)
# Verdict SSOT parser: drives the runner's donedata->verdict flattening with
# the *real* SCE DoneDataHelper encoding (emitContentLiteral), so it links
# sce_base to pin the engine's string-content wrapping contract.
tc8_add_unit_test(verdict_donedata_test)
target_link_libraries(verdict_donedata_test PRIVATE sce_base)

# The 802.1Q round-trip test decodes the builder's output with libtins —
# the same decoder the live dissector uses — so it links libtins on top
# of the shared testable library. (LIBTINS_* are set by the top-level
# find_path/find_library before unit_tests/ is added.)
tc8_add_unit_test(dot1q_test)
target_include_directories(dot1q_test PRIVATE ${LIBTINS_INCLUDE_DIR})
target_link_libraries(dot1q_test PRIVATE ${LIBTINS_LIBRARY})
