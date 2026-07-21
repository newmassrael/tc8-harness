#pragma once

#include <string_view>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_fault_flavor_arm.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_rpc_11_neg_sm.h"

namespace tc8::sce::cases {

using Rpc11NegSM = ::SCE::Generated::someipsrv_rpc_11_neg::someipsrv_rpc_11_neg;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// Self-validation of §5.1.5.7.11 SOMEIPSRV_RPC_11: a field setter's Response payload must echo
// the value the Request set. kEtsFaultSetterEchoWrong makes the harness-owned EtsImpl setFieldA
// echo the stored value bit-flipped (0x42 ^ 0xFF = 0xBD != 0x42) while leaving the stored field
// correct, so a buggy DUT surfaces a setter response that does not echo the set value. The only
// faithful SOME/IP fault site — the response serialization is vendored-vsomeip-owned, but the
// echoed value is EtsImpl-owned. A distinct flavor from the getter fault, so the get/set/get
// _neg cases keep a correct setter echo. tc8-dut-only (kCapEtsFault via SomeIpEtsFaultNegBase).
template <>
struct TestCaseTraits<cases::Rpc11NegSM>
    : SomeIpEtsFaultNegBase<cases::Rpc11NegSM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_RPC_11_NEG";
    static constexpr std::string_view kDescription =
        "Self-validation of SOMEIPSRV_RPC_11: the kEtsFaultSetterEchoWrong app fault makes the "
        "field setter response echo a value other than the one set; a conformant DUT echoes the "
        "set value";

    // Arm the setter-echo fault, then drive the same setFieldA(0x42) the positive uses. The
    // store stays correct; only the setter Response payload flips (0xBD != 0x42).
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        emitEtsFlavorArm(cfg, iface, ::tc8::ut::kEtsFaultSetterEchoWrong);

        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::SomeIpRpcMessage target{};
        target.method_id = 0x0042;
        target.payload   = {0x42};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Rpc11NegSM, someipsrv_rpc_11_neg)
