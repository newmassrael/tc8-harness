#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_072_sm.h"

namespace tc8::sce::cases {

using SomeipEts072SM = ::SCE::Generated::someip_ets_072::someip_ets_072;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_072 — DUT must reject (or silently ignore)
// an echoUNION Request whose union-internal length prefix claims a
// zero-byte variant. Stimulus reuses the ETS_038 Type 2 (uint8)
// baseline but corrupts payload byte 3 from 0x01 to 0x00. SOME/IP
// Length stays self-consistent so the frame reaches CommonAPI; the
// Variant decoder reads itsSize = 0, cannot read the value byte for
// the declared Type 2, trips errorOccurred_, the dispatcher emits
// Error Response. Lenient ETS_001/_002 4-path verdict pattern.
template <>
struct TestCaseTraits<cases::SomeipEts072SM> : SomeIpAnyBase<cases::SomeipEts072SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_072";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "echoUNION inner union-length zero — DUT must reject or ignore";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0019;
        target.payload = {
            // unionLength_BE = 0x00000000 (lies — claims zero-byte
            // variant; Variant decoder cannot read the Type 2 value)
            0x00, 0x00, 0x00, 0x00,
            // unionType_BE = 0x00000002 (Type 2 = uint8)
            0x00, 0x00, 0x00, 0x02,
            // value = 0x42 (present on the wire but unionLength = 0
            // tells the decoder no value bytes follow the type tag)
            0x42,
        };
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts072SM, someip_ets_072)
