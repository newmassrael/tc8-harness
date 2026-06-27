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
    ${PROJECT_SOURCE_DIR}/src/stimulus/udp_emit.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/someip_tp_emit.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/tcp_segment_builder.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/udp_datagram_builder.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/upper_tester_client.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/testability_client.cpp
)
target_include_directories(tc8_harness_testable PUBLIC
    ${PROJECT_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/include
)
# Shared wire math (checksum + ICMP echo body); PUBLIC so every test executable
# linking tc8_harness_testable inherits the one tc8_wire archive.
target_link_libraries(tc8_harness_testable PUBLIC tc8_wire tc8_someiptp)
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
# AES-CMAC engine: the RFC 4493 published vectors (the four example MACs plus the
# key-length guard) pin FIPS-197 AES-128 and the CMAC construction. Pure byte
# math, no I/O — links the tc8_crypto engine on top of the shared testable lib.
tc8_add_unit_test(aes_cmac_test)
target_link_libraries(aes_cmac_test PRIVATE tc8_crypto)
# Partial Networking filter: synthetic PNC masks (no OEM cluster IDs) exercise
# the AND-and-test mechanism, the byte offset, short-PDU handling, and the
# fail-fast config guards.
tc8_add_unit_test(pn_filter_test)
target_link_libraries(pn_filter_test PRIVATE tc8_pn)
# CRC Routines: the catalog "123456789" check values (0x4B / 0x29B1) pin the
# CRC-8/SAE-J1850 and CRC-16/CCITT-FALSE definitions against a published external
# reference, so the E2E profiles built on them inherit a verified CRC.
tc8_add_unit_test(crc_test)
target_link_libraries(crc_test PRIVATE tc8_crc)
# E2E Profile 5: protect outputs and check verdicts pinned to the AUTOSAR FO PRS
# E2EProtocol Profile 5 worked vectors (Data ID 0x1234), so the CRC coverage,
# Data ID feed order, little-endian CRC placement, and counter SM are verified.
tc8_add_unit_test(e2e_test)
target_link_libraries(e2e_test PRIVATE tc8_e2e)
# COM signal packing: little-endian (Intel) and big-endian (Motorola sawtooth)
# layouts pinned with hand-derived vectors + pack/unpack round-trips.
tc8_add_unit_test(com_test)
target_link_libraries(com_test PRIVATE tc8_com)
# NM state machine: the canonical AUTOSAR transitions and timer expiries driven
# deterministically through mainFunction()/requestNetwork()/rxNmPdu().
tc8_add_unit_test(nm_test)
target_link_libraries(nm_test PRIVATE tc8_nm)
# SOME/IP-TP transport: segment/reassemble round-trips, the spec example vectors
# (PRS_SOMEIP §4.2.1.4 Table 4.10), out-of-order, overflow, and reception timeout.
tc8_add_unit_test(someiptp_test)
target_link_libraries(someiptp_test PRIVATE tc8_someiptp)
# Synthetic demo middleware module: a fake MiddlewareContext + in-memory backend
# drive the module's lifecycle hermetically, proving the seam composes with the
# engines (the SDK template, examples/demo_middleware_module/).
tc8_add_unit_test(demo_module_test)
target_sources(demo_module_test PRIVATE
    ${PROJECT_SOURCE_DIR}/examples/demo_middleware_module/demo_module.cpp)
# nm/com/e2e/crypto resolve via tc8_harness_testable; pn and someiptp are their own
# engine libs, so the demo (which now composes them too) links them explicitly.
target_link_libraries(demo_module_test PRIVATE tc8_pn tc8_someiptp)
target_include_directories(demo_module_test PRIVATE
    ${PROJECT_SOURCE_DIR}/examples/demo_middleware_module)
target_link_libraries(demo_module_test PRIVATE tc8_nm tc8_com tc8_e2e tc8_crypto)
# ETS DUT emission engine (dut/dut_service/ets_emission.*). It is self-contained
# (no CommonAPI/vsomeip deps), so it is compiled directly into the test rather
# than linked from the tc8-dut executable. Covers the trigger-policy timing logic
# (incl. the zero-duration single-shot regression) and the controller's source
# dispatch + owned counters, driven deterministically via the step(now) seam.
find_package(Threads REQUIRED)
add_executable(ets_emission_test
    ets_emission_test.cpp
    ${PROJECT_SOURCE_DIR}/dut/dut_service/ets_emission.cpp)
target_include_directories(ets_emission_test PRIVATE
    ${PROJECT_SOURCE_DIR}/dut/dut_service)
target_link_libraries(ets_emission_test PRIVATE
    GTest::gtest GTest::gtest_main Threads::Threads)
add_test(NAME ets_emission_test COMMAND ets_emission_test)

tc8_add_unit_test(expect_parser_test)
tc8_add_unit_test(subscribe_builder_test)
tc8_add_unit_test(arp_builder_test)
tc8_add_unit_test(ipv4_frame_builder_test)
tc8_add_unit_test(icmp_echo_test)
tc8_add_unit_test(icmpv4_builder_test)
tc8_add_unit_test(ipv4_decode_test)
tc8_add_unit_test(tcp_segment_builder_test)
tc8_add_unit_test(udp_datagram_builder_test)
# Fixed source-port UDP emit (sendUdpUnicast): loopback round-trip asserts the
# datagram leaves from the caller-chosen source port.
tc8_add_unit_test(udp_emit_test)
# SOME/IP-TP tester-side emit: loopback round-trip (Segmenter -> sendUdpUnicast ->
# Reassembler) proves the emitted segments are spec-valid.
tc8_add_unit_test(someip_tp_emit_test)
tc8_add_unit_test(udp_captured_test)
tc8_add_unit_test(someip_captured_test)
# Method Request destination helper: derives the DUT endpoint from cfg.someip
# (the --expect surface) and guards the TCP-port-leak regression. Header-only
# logic, no DUT — links the shared testable lib for TestConfig.
tc8_add_unit_test(someip_method_dest_test)
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
    # The PosixBackendNeighbor privileged writes (rtnetlink RTM_NEW/DELNEIGH, the
    # /proc neigh sysctl) self-skip without CAP_NET_ADMIN, so the plain run above
    # only covers their error paths. Re-run them inside an unprivileged user+net
    # namespace (no sudo) so the success paths are exercised in the hosted CI ctest
    # too; the wrapper exits 77 (SKIP) where user namespaces are unavailable.
    add_test(NAME posix_neighbor_privileged
        COMMAND ${PROJECT_SOURCE_DIR}/scripts/run-netns-test.sh
            $<TARGET_FILE:testability_server_test>
            --gtest_filter=PosixBackendNeighbor.*)
    set_tests_properties(posix_neighbor_privileged PROPERTIES SKIP_RETURN_CODE 77)
    # The reusable Reactor (src/testability/reactor.h) exercised in isolation
    # against the real POSIX IoMultiplexer — no ProtocolServer/module — proving the
    # extracted event loop stands on its own. Links tc8_testability_server for
    # PosixSocketBackend (the IoMultiplexer) and the server header include path.
    tc8_add_unit_test(reactor_test)
    target_link_libraries(reactor_test PRIVATE tc8_testability_server)
endif()
# Server-side integration: drives the real DUT-side Upper Tester server core
# (tc8::ut::UpperTesterServer) over loopback with injected POSIX adapters,
# covering the opcode dispatch, capability derivation, TCP session lifecycle,
# and UDP backends end to end — the hermetic oracle the netns case suite alone
# previously provided. Links the UT server lib plus tc8_testability_server for
# the shared net::SocketBackend (PosixSocketBackend) adapter.
if(TARGET tc8_upper_tester_server AND TARGET tc8_testability_server)
    tc8_add_unit_test(ut_server_test)
    target_link_libraries(ut_server_test PRIVATE
        tc8_upper_tester_server tc8_testability_server)
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
