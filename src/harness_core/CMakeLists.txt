# tc8_harness_core — the dependency-light harness internals shared by the tester
# executable and the unit tests: pcap capture, the expect/summary CLI helpers, the
# SCE case registry + spec inventory, and the socket responders (ARP / method / TCP
# server + accept + subscribe) that own a thread or a capture loop. A library for the
# same reason tc8_stimulus is: the tester and every unit test link the SAME objects,
# so a responder covered by a test is the one the tester ships — no second, drifting
# copy (this set was listed by path in the tester AND in unit_tests' testable lib).
# harness_main, dut_control_factory, and the pcap/vsomeip-driving CLI commands stay in
# the tester: they pull heavier deps and are the executable's own edges.
#
# This dir carries no sources of its own — it aggregates the library's four
# single-owner subtrees (capture/, cli/, sce_integration/, stimulus/responders/) into
# one build definition, named by ${PROJECT_SOURCE_DIR} path so no second add_library
# can drift. Processed only under the (TC8_BUILD_HARNESS OR TC8_BUILD_UNIT_TESTS)
# guard at the add_subdirectory site, and PCAP_INCLUDE_DIR is inherited from the
# top-level find_package.
add_library(tc8_harness_core STATIC
    ${PROJECT_SOURCE_DIR}/src/capture/bpf_filter.cpp
    ${PROJECT_SOURCE_DIR}/src/capture/pcap_source.cpp
    ${PROJECT_SOURCE_DIR}/src/cli/expect_parser.cpp
    ${PROJECT_SOURCE_DIR}/src/cli/packet_summary.cpp
    ${PROJECT_SOURCE_DIR}/src/sce_integration/case_registry.cpp
    ${PROJECT_SOURCE_DIR}/src/sce_integration/spec_inventory.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/responders/arp_responder.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/responders/method_responder.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/responders/tcp_server.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/responders/tcp_accept_service.cpp
    ${PROJECT_SOURCE_DIR}/src/stimulus/responders/subscribe_tcp_session.cpp
)
# PUBLIC roots consumers inherit by linkage: src/sce_integration/include (this lib's
# OWN sce_integration/ tree — case registry, spec inventory, the expected/captured
# helpers, and the 764 case traits headers under cases/); src/stimulus/responders/
# include (its socket responders under the stimulus/ prefix, a separate root from
# tc8_stimulus's builder headers); src/capture/include and src/cli/include (its
# capture/ headers and cli/ helpers expect_parser + packet_summary; the tester-side
# cli/ command headers live under src/cli/commands/include, not exposed here); and
# include/ for the tc8/ namespace. PRIVATE pcap headers for the capture sources
# (pcap_source / bpf_filter) — a test that #includes one adds its own.
target_include_directories(tc8_harness_core
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/sce_integration/include>
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/stimulus/responders/include>
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/capture/include>
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/cli/include>
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    PRIVATE ${PCAP_INCLUDE_DIR})
# tc8_stimulus: the responders drive the stateless builders (tcp_server →
# tcp_segment_builder, arp_responder → arp_builder, …) and it carries tc8_wire /
# tc8_someiptp / Threads transitively. tc8_testability_client: the case runner and
# the UTM probe path. Both PUBLIC so consumers inherit the seam.
target_link_libraries(tc8_harness_core PUBLIC tc8_stimulus tc8_testability_client)
tc8_enable_strict_warnings(tc8_harness_core)
