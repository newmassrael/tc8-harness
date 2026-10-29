#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_fields_05_sm.h"

namespace tc8::sce::cases {

using UdpFields05SM = ::SCE::Generated::udp_fields_05::udp_fields_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpFields05SM>
    : UdpReceiveDrivenBase<cases::UdpFields05SM> {
    static constexpr std::string_view kCaseId      = "UDP_FIELDS_05";
    static constexpr std::string_view kDescription =
        "DUT can receive UDP at the same destination port from two "
        "distinct source IP addresses; user interface returns the "
        "source IP per RFC 768 'Fields' / 'User Interface' MUST";
    static constexpr int              kTopology    = 2;

    // Phase 1: a receive window for a probe with src_ip=Host-1-IP. Phase 2: a
    // second window, once the first's answer is read, for a probe with
    // src_ip=Host-2-IP. tc8-dut's last_receipt slot is overwritten on each probe,
    // which is why the windows run in turn; the SCXML grades the two recorded
    // answers against the per-phase expected src_ip.
    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        ::tc8::sce::udp::emitIngressProbeAndObserve(
            c, cfg, ctx.iface, ctx.dut,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            ::tc8::sce::udp::kUdpDefaultData.size(),
            ::tc8::sce::udp::kDataPeerPort,
            ::tc8::sce::udp::UdpStimulusOverrides{});

        ::tc8::sce::udp::UdpStimulusOverrides ov{};
        ov.src_ip_override = ::tc8::sce::udp::kUdpHost2IpBe;
        ::tc8::sce::udp::observeSecondUdpReceive(
            c, ctx.dut,
            ::tc8::sce::Endpoint{cfg.ipv4.dut_iface_ip, ::tc8::sce::udp::kDataPort},
            [&] {
                ::tc8::sce::udp::emitUdpStimulus(
                    cfg, ctx.iface, cfg.ipv4.dut_iface_ip,
                    ::tc8::sce::udp::kDataPeerPort, ::tc8::sce::udp::kDataPort,
                    ::tc8::sce::udp::kUdpDefaultData.data(),
                    ::tc8::sce::udp::kUdpDefaultData.size(), ov);
            },
            [&] { ::tc8::sce::udp::emitReceiveSentinel(cfg, ctx.iface); });
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpFields05SM, udp_fields_05)
