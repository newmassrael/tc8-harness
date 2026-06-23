#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>

#include <arpa/inet.h>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/ipv4_frame_builder.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_header_11_sm.h"

namespace tc8::sce::cases {

using TcpHeader11SM = ::SCE::Generated::tcp_header_11::tcp_header_11;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::TcpHeader11SM>
    : TcpAnyBase<cases::TcpHeader11SM> {
    static constexpr std::string_view kCaseId       = "TCP_HEADER_11";
    static constexpr std::string_view kDescription  =
        "DUT silently discards SYN with multicast IP destination address "
        "(RFC 1122 §4.2.3.10 p104; Linux PACKET_HOST gate)";

    // RFC 1112 §6.4 IPv4 multicast → Ethernet MAC mapping: low 23
    // bits of the IP address copied into 01:00:5E:00:00:00. For
    // 224.0.0.1 (all-hosts) the mapped MAC is 01:00:5E:00:00:01.
    static constexpr std::array<std::uint8_t, 6> kMulticastMacAllHosts = {
        0x01U, 0x00U, 0x5EU, 0x00U, 0x00U, 0x01U};

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IDutControl& dut) {
        using namespace ::tc8::sce::tcp;
        std::this_thread::sleep_for(kTcpUtBootWait);

        const std::uint16_t local_port  = kBasicsActiveLocalPort  + 38U;
        const std::uint16_t remote_port = kBasicsActiveRemotePort + 38U;

        auto open = driveSeamActiveOpen(dut, cfg, local_port, remote_port);
        (void)open;

        // 224.0.0.1 — IANA all-hosts multicast group, the canonical
        // multicast address for testing the spec's "Multicast IP
        // Destination" condition. inet_addr returns network-byte
        // order which matches both Ipv4FrameSpec.dst_ip and the
        // pseudo-header argument to buildTcpSegment.
        const std::uint32_t multicast_dst_ip = ::inet_addr("224.0.0.1");

        ::tc8::stimulus::TcpSegmentSpec syn{};
        syn.src_port = remote_port;
        syn.dst_port = local_port;
        syn.seq_num  = kTesterInitialSeq + 1U;
        syn.ack_num  = 0U;
        syn.flags    = ::tc8::stimulus::kTcpFlagSyn;
        // Pseudo-header checksum must match the IP layer dst — the
        // multicast IP, not the unicast DUT IP.
        const auto tcp_bytes = ::tc8::stimulus::buildTcpSegment(
            cfg.ipv4.tester_ip, multicast_dst_ip, syn);

        ::tc8::stimulus::Ipv4FrameSpec ip_spec{};
        ip_spec.dst_mac     = kMulticastMacAllHosts;
        ip_spec.src_ip      = cfg.ipv4.tester_ip;
        ip_spec.dst_ip      = multicast_dst_ip;
        ip_spec.ip_protocol = ::tc8::stimulus::kIpProtoTcp;
        ::tc8::stimulus::IpBootTiming timing{};
        timing.initial_wait = std::chrono::milliseconds(0);
        ::tc8::stimulus::emitIpv4Frame(iface, ip_spec, tcp_bytes, timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::TcpHeader11SM, tcp_header_11)
