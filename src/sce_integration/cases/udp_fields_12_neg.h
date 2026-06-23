#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/cases/udp_fields_12.h"  // SSOT for kUdpMaxPayloadBytes
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_fields_12_neg_sm.h"

namespace tc8::sce::cases {

using UdpFields12NegSM = ::SCE::Generated::udp_fields_12_neg::udp_fields_12_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §4.6.5.4 UDP_FIELDS_12: the reassembled-datagram length is a receive-
// operation property — the stack reassembles the 65 507 B datagram from ~45 IP fragments and
// the application surfaces the length in the GetReceivedUdp Confirmation. The
// kAppFaultReportWrongLength app fault makes the shared data listener over-report the length
// by one (the only faithful site — the stack delivered the full datagram correctly, so a
// wrong length is the receive operation's defect, and an ingress rewrite would make the DUT
// faithfully report the rewritten size). lwIP-only (kCapAppFault via UdpAppFaultNegBase).
template <>
struct TestCaseTraits<cases::UdpFields12NegSM>
    : UdpAppFaultNegBase<cases::UdpFields12NegSM> {
    static constexpr std::string_view kCaseId      = "UDP_FIELDS_12_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of UDP_FIELDS_12: the lwIP kAppFaultReportWrongLength app fault "
        "makes the Confirmation over-report the reassembled payload length; a conformant DUT "
        "reports the length the datagram carried";

    // Arm the length-report fault, then drive the same 65 507 B fragmented stimulus + UT
    // GetReceivedUdp query the positive uses (the wire-level reassembly is unchanged; the
    // flavor corrupts only the reported length), so the Confirmation surfaces a
    // ut_recv_payload_len != 65507.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitAppFlavorArm(cfg, iface, ::tc8::ut::kAppFaultReportWrongLength);

        std::vector<std::uint8_t> payload(cases::kUdpMaxPayloadBytes);
        for (std::size_t i = 0; i < payload.size(); ++i) {
            payload[i] = static_cast<std::uint8_t>(i & 0xFFU);
        }

        ::tc8::sce::udp::emitFragmentedUdpStimulus(
            cfg, iface,
            /*dst_ip_be=*/cfg.ipv4.dut_iface_ip,
            /*src_port=*/::tc8::sce::udp::kDataPeerPort,
            /*dst_port=*/::tc8::sce::udp::kDataPort,
            payload.data(),
            payload.size(),
            cfg.dut.mac);

        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        ::tc8::sce::udp::emitGetReceivedUdp(
            cfg, iface,
            /*req_id=*/1,
            /*listen_port=*/::tc8::sce::udp::kDataPort,
            /*expected_dst_ip_be=*/cfg.ipv4.dut_iface_ip,
            /*tester_src_port=*/::tc8::ut::kTesterSrcPort,
            /*dut_mac=*/cfg.dut.mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpFields12NegSM, udp_fields_12_neg)
