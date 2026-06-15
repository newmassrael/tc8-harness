#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_user_interface_07_sm.h"

namespace tc8::sce::cases {

using UdpUserInterface07SM = ::SCE::Generated::udp_user_interface_07::udp_user_interface_07;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpUserInterface07SM>
    : UdpAnyBase<cases::UdpUserInterface07SM> {
    static constexpr std::string_view kCaseId      = "UDP_USER_INTERFACE_07";
    static constexpr std::string_view kSpecSection = "4.6.5.5";
    static constexpr std::string_view kDescription =
        "DUT-emit UDP datagram carries caller-specified Source IP "
        "Address (RFC 768 'User Interface' MUST)";

    // §4.6.5.5 UI_07 spec axis: TESTER asks DUT to emit a UDP message
    // with src=`<DIface-0-IP>`. With a single primary IP per side the
    // axis vacuously passes; the DUT-side `kDutAliasIp4Be` alias makes
    // it observable. Stimulus passes the alias as the TriggerSendUdp
    // src_ip override; tc8-dut binds the transient socket to
    // (alias, dut_src_port) and sends, so wire src_ip carries the alias
    // iff the DUT honoured the caller's choice. SCXML cond literal
    // (the `0x050010ACU` = `kDutAliasIp4Be`) gates the pass branch on
    // exact match — a buggy DUT that silently defaults to the primary
    // iface IP lands on `fail_wrong_src_ip_or_port`.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::sce::udp::emitTriggerSendUdp(
            cfg, iface, /*req_id=*/1,
            /*dut_src_port=*/20027,
            /*target_ip_be=*/cfg.ipv4.tester_ip,
            /*target_port=*/::tc8::sce::udp::kDataPort,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            static_cast<std::uint16_t>(::tc8::sce::udp::kUdpDefaultData.size()),
            ::tc8::ut::kTesterSrcPort,
            cfg.dut.mac,
            ::tc8::sce::udp::kUdpPilotInitialWait,
            /*dut_src_ip_override_be=*/::tc8::sce::udp::kDutAliasIp4Be);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpUserInterface07SM, udp_user_interface_07)
