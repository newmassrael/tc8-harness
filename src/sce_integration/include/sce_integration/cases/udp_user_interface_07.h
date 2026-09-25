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
    : UdpDutOriginatedBase<cases::UdpUserInterface07SM> {
    static constexpr std::string_view kCaseId      = "UDP_USER_INTERFACE_07";
    static constexpr std::string_view kDescription =
        "DUT-emit UDP datagram carries caller-specified Source IP "
        "Address (RFC 768 'User Interface' MUST)";

    // This case cannot be asked of a DUT that holds ONE address: the axis it grades
    // is whether the DUT honours a caller-specified source, and with nothing to
    // choose between, the ask is meaningless. The netns topologies alias
    // 172.16.0.5 onto the DUT veth; the lwIP fixture runs one netif and cannot, so
    // its OpTriggerSendUdp answers status 0x03 and the case reported a standing
    // `inconclusive:stimulus_TriggerSendUdp_not_performed` — the guard doing its job
    // for a premise nothing had declared. Declaring it makes that an honest
    // capability skip, and answers for DUTs not yet written (docs/tech-debt.md
    // TD-25).
    static constexpr ::tc8::sce::DutCapabilities kRequiredCapabilities =
        UdpDutOriginatedBase<cases::UdpUserInterface07SM>::kRequiredCapabilities |
        ::tc8::sce::kCapSecondaryDutAddress;

    // §4.6.5.5 UI_07 spec axis: TESTER asks DUT to emit a UDP message
    // with src=`<DIface-0-IP>`. With a single primary IP per side the
    // axis vacuously passes; the DUT's SECOND address makes it
    // observable. Stimulus passes that address as the TriggerSendUdp
    // src_ip override; tc8-dut binds the transient socket to
    // (secondary, dut_src_port) and sends, so wire src_ip carries it
    // iff the DUT honoured the caller's choice. The SCXML cond gates
    // the pass branch on `captured.src_ip == expected.dut_alias_ip` —
    // a buggy DUT that silently defaults to the primary iface IP lands
    // on `fail_wrong_src_ip_or_port`.
    //
    // ⚠ The ask is sourced from `cfg.dut.secondary_ip` -- the SAME field the
    // capability above is derived from -- and NOT from the compiled
    // `kDutAliasIp4Be`, which is the netns fixture's own value and is only one
    // of the addresses a DUT may hold. A site naming its external DUT's alias
    // moves the config, the expectation and this ask together; the constant
    // would have stayed at 172.16.0.5 and asked a conforming DUT for an address
    // it does not have (docs/tech-debt.md TD-48).
    //
    // ⚠ And NOT from `cfg.ipv4.dut_alias_ip`, which holds the same value: that
    // one is the EXPECTATION a `--negative ipv4.dut_alias_ip=…` row flips to
    // prove this assertion is load-bearing. Sourcing the ask from it would move
    // both sides together and make that negative vacuous.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view /*iface*/,
                         ::tc8::sce::IDutControl& dut) {
        ::tc8::sce::udp::emitTriggerSendUdp(
            dut,
            /*dut_src_port=*/20027,
            /*target_ip_be=*/cfg.ipv4.tester_ip,
            /*target_port=*/::tc8::sce::udp::kDataPort,
            ::tc8::sce::udp::kUdpDefaultData.data(),
            static_cast<std::uint16_t>(::tc8::sce::udp::kUdpDefaultData.size()),
            ::tc8::sce::udp::kUdpPilotInitialWait,
            /*dut_src_ip_override_be=*/cfg.dut.secondary_ip);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpUserInterface07SM, udp_user_interface_07)
