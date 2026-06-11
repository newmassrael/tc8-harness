#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_user_interface_08_sm.h"

namespace tc8::sce::cases {

using UdpUserInterface08SM = ::SCE::Generated::udp_user_interface_08::udp_user_interface_08;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpUserInterface08SM>
    : UdpAnyBase<cases::UdpUserInterface08SM> {
    static constexpr std::string_view kCaseId      = "UDP_USER_INTERFACE_08";
    static constexpr std::string_view kSpecSection = "4.6.5.5";
    static constexpr std::string_view kDescription =
        "DUT-emit UDP datagram carries caller-specified Destination IP "
        "Address (RFC 768 'User Interface' MUST)";

    // §4.6.5.5 UI_08 spec axis: TESTER asks DUT to emit a UDP message
    // with dst=`<AIface-0-IP>` — the tester's interface IP. With a
    // single primary IP per side the axis vacuously passes; the
    // tester-side `kTesterAliasIp4Be` alias (configured in
    // setup-netns.sh) makes it observable. Stimulus passes the alias
    // as `target_ip_be`; the DUT egress UDP carries dst_ip=alias iff
    // it honoured the caller's choice. SCXML cond literal gates the
    // pass branch on the alias literal — a buggy DUT that silently
    // emits to the primary tester_ip lands on `fail_wrong_dst_ip`.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::udp::emitTriggerSendUdp(
            cfg, iface, /*req_id=*/1,
            /*dut_src_port=*/20028,
            /*target_ip_be=*/::tc8::sce::udp::kTesterAliasIp4Be,
            /*target_port=*/::tc8::sce::udp::kDataPort,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            static_cast<std::uint16_t>(::tc8::sce::udp::kUdpDefaultData.size()),
            ::tc8::ut::kTesterSrcPort,
            cfg.arp.dut_real_mac);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                return "pass";
            case State::Fail_wrong_dst_ip:   return "fail:dut_emitted_udp_with_wrong_user_interface_dst_ip";
            case State::Fail_timeout:        return "fail:no_dut_originated_udp_within_listen_window";
            default:                         return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpUserInterface08SM, udp_user_interface_08)
