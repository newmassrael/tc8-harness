#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <arpa/inet.h>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_tcp_seam.h"
#include "sce_integration/cases/_tcp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_runner.h"
#include "stimulus/ipv4_frame_builder.h"
#include "stimulus/tcp_segment_builder.h"

#include "tcp_header_11_neg_sm.h"

namespace tc8::sce::cases {

using TcpHeader11NegSM = ::SCE::Generated::tcp_header_11_neg::tcp_header_11_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.8.6.16 TCP_HEADER_11: a conformant DUT silently drops a SYN whose IP
// destination is a multicast address (RFC 1122 §4.2.3.10). kTcpSynthAck makes the lwIP netif
// input hook synthesize the prohibited challenge ACK on the connection 4-tuple when the
// multicast SYN arrives — DUT-sourced, since the synthesis uses the DUT's own netif IP rather
// than the trigger's multicast destination. Armed per-phase (after ESTABLISHED) so the
// handshake SYN,ACK is not mistaken for the trigger. lwIP-only (kCapIngressFault).
template <>
struct TestCaseTraits<cases::TcpHeader11NegSM>
    : TcpIngressFaultNegBase<cases::TcpHeader11NegSM> {
    static constexpr std::string_view kCaseId       = "TCP_HEADER_11_NEG";
    static constexpr std::string_view kDescription  =
        "Self-validation of TCP_HEADER_11: the lwIP kTcpSynthAck ingress flavor makes the DUT "
        "challenge-ACK a multicast-destination SYN; a conformant DUT drops it silently";

    // RFC 1112 §6.4 Ethernet mapping of 224.0.0.1 (mirrors the positive HEADER_11; an RFC-
    // frozen constant, not a tunable, so the local copy cannot drift).
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

        // Per-phase arm: the handshake has completed, so the synthesis fires only on the
        // multicast SYN injected next.
        emitIngressFlavorArmMidStream(cfg, iface, ::tc8::ut::kTcpSynthAck);

        const std::uint32_t multicast_dst_ip = ::inet_addr("224.0.0.1");

        ::tc8::stimulus::TcpSegmentSpec syn{};
        syn.src_port = remote_port;
        syn.dst_port = local_port;
        syn.seq_num  = kTesterInitialSeq + 1U;
        syn.ack_num  = 0U;
        syn.flags    = ::tc8::stimulus::kTcpFlagSyn;
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

TC8_REGISTER_CASE(::tc8::sce::cases::TcpHeader11NegSM, tcp_header_11_neg)
