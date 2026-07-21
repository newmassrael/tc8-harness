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
    : UdpAnyBase<cases::UdpFields05SM> {
    static constexpr std::string_view kCaseId      = "UDP_FIELDS_05";
    static constexpr std::string_view kDescription =
        "DUT can receive UDP at the same destination port from two "
        "distinct source IP addresses; user interface returns the "
        "source IP per RFC 768 'Fields' / 'User Interface' MUST";
    static constexpr int              kTopology    = 2;

    // Phase 1 (synchronous): probe with src_ip=Host-1-IP +
    // OpGetReceivedUdp query. Phase 2 (scheduled on Listening_phase2
    // entry): probe with src_ip=Host-2-IP + query. tc8-dut's
    // last_receipt slot is overwritten on each probe; the SCXML
    // observes only the Confirmation that carries the per-phase
    // expected src_ip.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::sce::udp::emitIngressProbeAndQuery(
            cfg, iface, cfg.dut.mac,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            ::tc8::sce::udp::kUdpDefaultData.size(),
            ::tc8::sce::udp::kDataPeerPort,
            ::tc8::sce::udp::UdpStimulusOverrides{});

        std::string iface_copy(iface);
        ::tc8::TestConfig cfg_copy = cfg;
        const auto dut_mac = cfg.dut.mac;
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_phase2),
            [iface_copy, cfg_copy, dut_mac]() {
                ::tc8::sce::udp::UdpStimulusOverrides ov{};
                ov.src_ip_override = ::tc8::sce::udp::kUdpHost2IpBe;
                ::tc8::sce::udp::emitIngressProbeAndQuery(
                    cfg_copy, iface_copy, dut_mac,
                    ::tc8::sce::udp::kUdpDefaultData.data(),
                    ::tc8::sce::udp::kUdpDefaultData.size(),
                    ::tc8::sce::udp::kDataPeerPort,
                    ov,
                    /*initial_wait=*/std::chrono::milliseconds(0),
                    /*req_id=*/2);
            });
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpFields05SM, udp_fields_05)
