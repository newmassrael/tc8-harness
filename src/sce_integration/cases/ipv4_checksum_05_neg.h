#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_ipv4_traits_base.h"
#include "sce_integration/ipv4_pilot_common.h"
#include "sce_integration/test_runner.h"

#include "ipv4_checksum_05_neg_sm.h"

namespace tc8::sce::cases {

using Ipv4Checksum05NegSM = ::SCE::Generated::ipv4_checksum_05_neg::ipv4_checksum_05_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Checksum05NegSM>
    : Ipv4EgressFaultNegBase<cases::Ipv4Checksum05NegSM> {
    static constexpr std::string_view kCaseId      = "IPv4_CHECKSUM_05_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of IPv4_CHECKSUM_05: the lwIP kIpv4FaultHdrChecksumWrong egress "
        "flavor invalidates the Echo Reply IPv4 header checksum; a conformant DUT emits a "
        "valid one";

    // Arm the header-checksum fault, then send the same Echo Request the positive uses.
    // The flavor XOR-invalidates the DUT Echo Reply's IPv4 header checksum — the RFC 791
    // violation the positive forbids; libtins still dissects the frame (it does not
    // validate the IPv4 header checksum) so header_checksum_valid() recomputes to false.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitEgressFlavorArm(cfg, iface, ::tc8::ut::kIpv4FaultHdrChecksumWrong);
        ::tc8::sce::ipv4::emitStimulus(cfg, iface);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Checksum05NegSM, ipv4_checksum_05_neg)
