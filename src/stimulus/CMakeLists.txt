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
# with the tester (tc8_harness_core's responders/ dir); this archive is the stateless
# builders + dissectors.
#
# One library, two single-owner dirs: the builders live here in src/stimulus/ and the
# SOME/IP dissectors in the sibling src/dissect/ (its own include root, A3). Both are
# owned solely by tc8_stimulus, so the dissect sources are named by ${PROJECT_SOURCE_
# DIR} path rather than split into a second add_library that could drift.
add_library(tc8_stimulus STATIC
    ${PROJECT_SOURCE_DIR}/src/dissect/someip_header.cpp
    ${PROJECT_SOURCE_DIR}/src/dissect/someip_dispatcher.cpp
    arp_builder.cpp
    dot1q.cpp
    dhcpv4_frame_builder.cpp
    ipv4_frame_builder.cpp
    icmpv4_builder.cpp
    someip_rpc_builder.cpp
    site_target.cpp
    someip_sd_builder.cpp
    tcp_client.cpp
    udp_emit.cpp
    someip_tp_emit.cpp
    tcp_segment_builder.cpp
    udp_datagram_builder.cpp
    upper_tester_client.cpp
)
# PUBLIC roots consumers inherit by linkage: include/ (the tc8/... headers — wire
# math, protocol frames, dut_config, the namespaced tc8/net + tc8/someip + tc8/wire
# helpers the builders use), src/dissect/include (this lib's own dissect/ headers —
# the SOME/IP dissectors), and src/stimulus/include (this lib's own stimulus/ builder
# + header-only helper headers — moved out of the flat tree so stimulus/*.h resolves
# only through here; the socket responders live in tc8_harness_core's own stimulus/
# responder root). All PUBLIC so every consumer inherits the roots by linkage.
target_include_directories(tc8_stimulus PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/dissect/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
# tc8_wire: RFC 1071 checksum / RFC 792 echo body, used by the IPv4-family builders.
# tc8_someiptp: someip_tp_emit frames via someiptp::Segmenter. Threads::Threads
# (resolved in the top-level scope): someip_sd_builder / upper_tester_client use
# std::this_thread::sleep_for.
target_link_libraries(tc8_stimulus PUBLIC tc8_wire tc8_someiptp Threads::Threads)
tc8_enable_strict_warnings(tc8_stimulus)
