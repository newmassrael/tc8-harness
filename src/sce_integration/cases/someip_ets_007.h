#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_007_sm.h"

namespace tc8::sce::cases {

using SomeipEts007SM = ::SCE::Generated::someip_ets_007::someip_ets_007;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_007 — echoBitfields. Tester sends three
// integer args (UInt8 + UInt16 BE + UInt32 BE = 7 bytes back-to-back,
// CommonAPI default deployment with no inter-arg padding). DUT echoes
// each arg back with its bit order reversed (PRS_SOMEIP_00191 +
// PRS_SOMEIP_00300 + PRS_SOMEIP_003001):
//   Req: UInt8 0x80, UInt16 0x4001, UInt32 0x12345678
//   Res: UInt8 0x01, UInt16 0x8002, UInt32 0x1E6A2C48
// 0x80 / 0x4001 / 0x12345678 are deliberately non-palindromic in their
// bit representations so a regression that drops the bit-reversal step
// can't trivially pass an identity-echo cond.
template <>
struct TestCaseTraits<cases::SomeipEts007SM> : SomeIpAnyBase<cases::SomeipEts007SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_007";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "echoBitfields — DUT echoes each integer arg with bit order reversed";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0041;
        // UInt8 0x80, UInt16 0x4001 BE, UInt32 0x12345678 BE — back-to-back.
        target.payload = {0x80, 0x40, 0x01, 0x12, 0x34, 0x56, 0x78};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts007SM, someip_ets_007)
