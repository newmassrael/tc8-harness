#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_029_sm.h"

namespace tc8::sce::cases {

using SomeipEts029SM = ::SCE::Generated::someip_ets_029::someip_ets_029;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_029 — echoUINT8Array16BitLength
// round-trip. Identical to ETS_028 but the array carries a 16-bit BE
// length prefix on the wire (ets.fdepl: SomeIpArrayLengthWidth = 2).
// Method ID 0x003F (METHOD-ID-29-SI-1 per spec Table 1).
template <>
struct TestCaseTraits<cases::SomeipEts029SM> : SomeIpAnyBase<cases::SomeipEts029SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_029";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "echoUINT8Array16BitLength round-trip — DUT echoes the array";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x003F;
        // CommonAPI UInt8[] with 16-bit BE length prefix:
        // [len_BE = 0x0003] [0x42 0x43 0x44]. payload_len = 5.
        target.payload = {0x00, 0x03, 0x42, 0x43, 0x44};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts029SM, someip_ets_029)
