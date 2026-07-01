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
    ${PROJECT_SOURCE_DIR}/src/cli/packet_summary.cpp
    ${PROJECT_SOURCE_DIR}/src/sce_integration/case_registry.cpp
    ${PROJECT_SOURCE_DIR}/src/sce_integration/spec_inventory.cpp
    ${PROJECT_SOURCE_DIR}/src/dissect/someip_header.cpp
    ${PROJECT_SOURCE_DIR}/src/dissect/someip_dispatcher.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/arp_builder.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/arp_responder.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/method_responder.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/tcp_server.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/tcp_accept_service.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/dot1q.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/ipv4_frame_builder.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/icmpv4_builder.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/someip_sd_builder.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/someip_rpc_builder.cpp
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
# linking tc8_harness_testable inherits the one tc8_wire archive. Threads is
# PUBLIC because someip_sd_builder.cpp / upper_tester_client.cpp use
# std::this_thread::sleep_for (the responders are threadless — driven by the
# capture loop), and consumers link this archive directly.
find_package(Threads REQUIRED)
target_link_libraries(tc8_harness_testable PUBLIC tc8_wire tc8_someiptp Threads::Threads)
tc8_enable_strict_warnings(tc8_harness_testable)

# DELIBERATE: test TUs are NOT strict-gated. GoogleTest's own macros (EXPECT_*/
# TEST) and headers expand C-style casts and sign conversions that -Wold-style-cast
# / -Wsign-conversion / -Werror would flag in every test, drowning real signal.
# The code UNDER test is strict-gated where it lives (tc8_harness_testable + the
# engine/DUT libraries carry tc8_enable_strict_warnings); the tests exercise it.
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

# Strict-set compile witness for src/net/link_control.h (the only net header with
# no strict production consumer — rtnetlink.h is now strict-compiled via the
# strict-gated tc8_posix_backend, but link_control.h is included only by unit-test
# TUs, which are not strict-gated). Without this, a glibc-macro cast/conversion
# leak into link_control.h would surface only when a strict first-party consumer
# (an OEM conformance case) hit it. This OBJECT target compiles it UNDER the strict
# gate so the contract is build-enforced and cannot regress. Compile, no link.
add_library(net_headers_strict_guard OBJECT net_headers_strict_guard.cpp)
target_include_directories(net_headers_strict_guard PRIVATE ${PROJECT_SOURCE_DIR}/src)
tc8_enable_strict_warnings(net_headers_strict_guard)

# Hermetic functional cover for the rtnetlink walk helpers (nlmsgOk/Next, rtaOk/
# Next, nlmsgData/rtaData): a synthetic RTM_NEWNEIGH dump walked in memory, no
# privilege. The privileged netns neighbor fixture self-skips without CAP_NET_ADMIN
# and walks an empty lo table, so rtaOk/rtaNext/rtaData run nowhere else in the
# hosted CI lane. Needs only the header (src on the include path) + GTest.
add_executable(rtnetlink_walk_test rtnetlink_walk_test.cpp)
target_include_directories(rtnetlink_walk_test PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(rtnetlink_walk_test PRIVATE GTest::gtest GTest::gtest_main)
add_test(NAME rtnetlink_walk_test COMMAND rtnetlink_walk_test)

tc8_add_unit_test(captured_frame_observer_test)
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
# (Threads::Threads is already imported above for tc8_harness_testable.)
add_executable(ets_emission_test
    ets_emission_test.cpp
    ${PROJECT_SOURCE_DIR}/dut/dut_service/ets_emission.cpp)
target_include_directories(ets_emission_test PRIVATE
    ${PROJECT_SOURCE_DIR}/dut/dut_service)
target_link_libraries(ets_emission_test PRIVATE
    GTest::gtest GTest::gtest_main Threads::Threads)
add_test(NAME ets_emission_test COMMAND ets_emission_test)

# DUT client-role Method Request wire builder (dut/dut_service/client_mode.*).
# Self-contained raw-UDP firmware (no CommonAPI/vsomeip), compiled directly like
# ets_emission_test. Pins the SOMEIPCLT outbound call wire layout.
add_executable(client_mode_wire_test
    client_mode_wire_test.cpp
    ${PROJECT_SOURCE_DIR}/dut/dut_service/client_mode.cpp)
target_include_directories(client_mode_wire_test PRIVATE
    ${PROJECT_SOURCE_DIR}/dut/dut_service
    ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(client_mode_wire_test PRIVATE
    GTest::gtest GTest::gtest_main Threads::Threads)
add_test(NAME client_mode_wire_test COMMAND client_mode_wire_test)

# Availability-gated Request buffer (dut/dut_service/pending_requests.h): the
# timing-robust callMethod policy split out of VsomeipEtsClientControl so it is
# testable without vsomeip. Drives submit/flush with a recording sender, pinning
# send-when-available, park-when-not, in-order flush, drain, and key isolation.
add_executable(pending_requests_test pending_requests_test.cpp)
target_include_directories(pending_requests_test PRIVATE
    ${PROJECT_SOURCE_DIR}/dut/dut_service)
target_link_libraries(pending_requests_test PRIVATE
    GTest::gtest GTest::gtest_main)
add_test(NAME pending_requests_test COMMAND pending_requests_test)

# DUT-side pollable drain owner (dut/dut_service/pollable_host.h): the receiver an
# extension adopts via IEtsIoHost, drained on the DUT main loop. Backs a fake
# pollable with a non-blocking socketpair so the poll()/onReadable() drain path is
# exercised without a DUT or vsomeip.
add_executable(pollable_host_test pollable_host_test.cpp)
target_include_directories(pollable_host_test PRIVATE
    ${PROJECT_SOURCE_DIR}/dut/dut_service
    ${PROJECT_SOURCE_DIR}/include)
target_link_libraries(pollable_host_test PRIVATE
    GTest::gtest GTest::gtest_main)
add_test(NAME pollable_host_test COMMAND pollable_host_test)

tc8_add_unit_test(expect_parser_test)
tc8_add_unit_test(someip_sd_builder_test)
# Tester server-role RPC reply builders (buildMethodResponse/buildMethodError):
# byte-level assertions pin the SOME/IP header per PRS_SOMEIP_00701/00757 and
# the Request-ID echo the DUT client correlates on.
tc8_add_unit_test(someip_rpc_reply_test)
tc8_add_unit_test(arp_builder_test)
# Tester-side ARP responder: the pure buildArpReplyForRequest match/reply layout
# and macOfInterface, with no privilege. The live socket/thread plumbing is
# proven separately in arp_responder_privileged_test (needs a veth pair).
tc8_add_unit_test(arp_responder_test)
# Tester-side method responder: the pure parseMethodRequest match/extract over a
# built Eth+IPv4+UDP+SOME/IP Request frame, with no privilege. The live AF_PACKET
# socket plumbing shares the ArpResponder pattern (privileged path covered there).
tc8_add_unit_test(method_responder_test)
# Tester-as-TCP-server accept surface (SOMEIPCLT): TcpServer/TcpConnection over a
# loopback round-trip — accept + peer endpoint, server send, peer-FIN observe,
# multi-accept. No privilege (loopback only); no DUT required.
tc8_add_unit_test(tcp_server_test)
# Autonomous TCP-accept adapter (SOMEIPCLT): TcpAcceptService folds a non-blocking
# accept into the capture-loop drain (IPollableService) so a DUT that opens the
# reliable connection on its own schedule is accepted without blocking. Loopback
# round-trip, no privilege, no DUT.
tc8_add_unit_test(tcp_accept_service_test)
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
# decode-pcap presentation layer (cli/packet_summary.*, TD-08): per-protocol
# summary builders + makeCandidate in isolation. Covers the shared UT decoder
# (TD-06 utSummary) and the SD wire-total / sub-240-DHCP display fixes (TD-09).
tc8_add_unit_test(packet_summary_test)
# Pins the DHCPv4 BOOTP fixed-header SSOT (dhcpv4_wire.def, TD-02). The .def now
# has a single C++ consumer — the documentation site no longer re-decodes the
# wire (TD-05), so there is no Python mirror left to gate.
tc8_add_unit_test(dhcpv4_wire_test)
# SOME/IP dispatcher datagram grouping: synthetic UDP datagrams carrying N
# concatenated SOME/IP messages drive deliver(), asserting each emitted event
# is stamped with its 0-based index and the datagram's message count; the TCP
# feed() path leaves the count-0 sentinel (no datagram boundary).
tc8_add_unit_test(someip_dispatcher_test)
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
    # Tester-side interface link-state fault injector (net::setLinkState, rtnetlink
    # RTM_NEWLINK). Links tc8_testability_server for the PosixSocketBackend the
    # CAP_NET_ADMIN probe (netns_test_util hasNetAdmin) uses. The privileged toggle
    # self-skips without CAP_NET_ADMIN; re-run it in a no-sudo user+net namespace.
    tc8_add_unit_test(link_control_test)
    target_link_libraries(link_control_test PRIVATE tc8_testability_server)
    add_test(NAME link_state_privileged
        COMMAND ${PROJECT_SOURCE_DIR}/scripts/run-netns-test.sh
            $<TARGET_FILE:link_control_test>
            --gtest_filter=SetLinkState.*)
    set_tests_properties(link_state_privileged PROPERTIES SKIP_RETURN_CODE 77)
    # Live ArpResponder over a veth pair (CAP_NET_RAW + CAP_NET_ADMIN). Links
    # tc8_testability_server for the netns_test_util veth/CAP_NET_ADMIN scaffolding
    # (PosixSocketBackend + the dut include path). The plain run self-skips without
    # privilege; the netns re-run exercises the success path with no sudo.
    tc8_add_unit_test(arp_responder_privileged_test)
    target_link_libraries(arp_responder_privileged_test PRIVATE tc8_testability_server)
    add_test(NAME arp_responder_privileged
        COMMAND ${PROJECT_SOURCE_DIR}/scripts/run-netns-test.sh
            $<TARGET_FILE:arp_responder_privileged_test>
            --gtest_filter=ArpResponderLive.*)
    set_tests_properties(arp_responder_privileged PROPERTIES SKIP_RETURN_CODE 77)
    # Live MethodResponder over a veth pair (CAP_NET_RAW + CAP_NET_ADMIN): the
    # AF_PACKET RX bind, drain, PACKET_OUTGOING self-skip, reply build, and
    # emitMethodReply egress the pure parseMethodRequest test cannot reach. Same
    # gating + scaffolding as arp_responder_privileged_test.
    tc8_add_unit_test(method_responder_privileged_test)
    target_link_libraries(method_responder_privileged_test PRIVATE tc8_testability_server)
    add_test(NAME method_responder_privileged
        COMMAND ${PROJECT_SOURCE_DIR}/scripts/run-netns-test.sh
            $<TARGET_FILE:method_responder_privileged_test>
            --gtest_filter=MethodResponderLive.*)
    set_tests_properties(method_responder_privileged PROPERTIES SKIP_RETURN_CODE 77)
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

# IEtsExtension / IEtsEventSink seam: a fake sink drives the in-tree demo
# extension hermetically (no vsomeip, no DUT), proving the offer/notify/onMethod
# contract. Compiles the demo's TC8_ETS_EXTENSION_SRC slot file too, so the OEM
# starter template is build-verified. The seam header is vsomeip-free, so this
# stays a pure-logic unit test.
tc8_add_unit_test(demo_ets_extension_test)
target_sources(demo_ets_extension_test PRIVATE
    ${PROJECT_SOURCE_DIR}/examples/demo_ets_extension/demo_ets_extension.cpp)
target_include_directories(demo_ets_extension_test PRIVATE
    ${PROJECT_SOURCE_DIR}/dut/dut_service
    ${PROJECT_SOURCE_DIR}/examples/demo_ets_extension)

# Boot-time regression guard for the PRODUCTION ETS event-sink (makeEtsEventSink).
# The demo test above drives the seam logic with a fake sink (vsomeip-free), but
# cannot prove the real VsomeipEtsEventSink retrieves the CommonAPI-owned vsomeip
# application — the part that silently broke. This boots the real tc8-dut and
# asserts it resolved that application (no "OEM event surface disabled"), pinning
# the CommonAPI/vsomeip application-keying contract makeEtsEventSink relies on.
# Gated on the real DUT target (present only when CommonAPI/vsomeip are found).
if(TARGET tc8-dut)
    add_test(NAME ets_event_sink_boot
        COMMAND ${PROJECT_SOURCE_DIR}/scripts/ets-event-sink-boot-check.sh
                $<TARGET_FILE:tc8-dut>)
endif()

# Golden-output gate for `tc8-harness decode-pcap`, the documentation-site pcap
# exporter that replaced the deleted Python wire decoder (docs/tech-debt.md
# TD-05). Replays a committed fixture pcap + transition trace through the real
# binary and asserts the emitted PacketCapture JSON is byte-identical to the
# committed expected file — the automated drift guard that took over from the
# removed `.def` --check gates (a one-time equivalence proof is not a wired
# gate). Regenerate via unit_tests/fixtures/gen_decode_pcap_fixture.py.
if(TARGET tc8-harness)
    add_test(NAME decode_pcap_golden
        COMMAND ${CMAKE_COMMAND}
            -DBIN=$<TARGET_FILE:tc8-harness>
            -DPCAP=${PROJECT_SOURCE_DIR}/unit_tests/fixtures/decode_pcap_sample.pcap
            -DTRACE=${PROJECT_SOURCE_DIR}/unit_tests/fixtures/decode_pcap_sample.trace.json
            -DEXPECTED=${PROJECT_SOURCE_DIR}/unit_tests/fixtures/decode_pcap_sample.expected.json
            -DOUT=${CMAKE_CURRENT_BINARY_DIR}/decode_pcap_golden.out.json
            -P ${CMAKE_CURRENT_SOURCE_DIR}/run_decode_pcap_golden.cmake)
endif()
