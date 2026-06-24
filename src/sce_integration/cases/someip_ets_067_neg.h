#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_067_neg_sm.h"

namespace tc8::sce::cases {

using SomeipEts067NegSM = ::SCE::Generated::someip_ets_067_neg::someip_ets_067_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §5.1.6 SOMEIP_ETS_067: the DUT must echo an empty UINT8Array for a
// zero-length-array request. kEtsFaultEchoArrayWrong makes the harness-owned EtsImpl
// echoUINT8Array (0x0009) response carry one extra byte, so the DUT echoes a NON-empty array
// — the violation the positive forbids. The zero-length array is well-formed, so CommonAPI
// invokes echoUINT8Array (unlike ETS_003's EOF-rejected echoUINT8 request, which the vendored
// deserializer rejects before EtsImpl), making the echoed value an EtsImpl-owned faithful
// fault site. Pass = the non-empty echo observed; fail_compliant = the DUT echoed empty
// despite the flavor (fault inert). tc8-dut-only (kCapEtsFault via SomeIpEtsFaultNegBase).
template <>
struct TestCaseTraits<cases::SomeipEts067NegSM>
    : SomeIpEtsFaultNegBase<cases::SomeipEts067NegSM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_067_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of SOMEIP_ETS_067: the kEtsFaultEchoArrayWrong app fault makes "
        "echoUINT8Array echo a non-empty array for a zero-length request; a conformant DUT "
        "echoes empty";

    // Arm the echo-array fault, then send the same zero-length-array echoUINT8Array (0x0009)
    // request the positive uses. The flavor appends a byte to the EtsImpl echo, so the reply
    // is non-empty (the violation the positive's empty-array guard forbids).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitEtsFlavorArm(cfg, iface, ::tc8::ut::kEtsFaultEchoArrayWrong);

        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0009;
        target.payload   = {0x00, 0x00, 0x00, 0x00};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts067NegSM, someip_ets_067_neg)
