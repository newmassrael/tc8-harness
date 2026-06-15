#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_002_sm.h"

namespace tc8::sce::cases {

using SomeipEts002SM = ::SCE::Generated::someip_ets_002::someip_ets_002;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_002 — DUT must reject (or silently ignore)
// an echoUINT8 Request whose SOME/IP Length header overshoots the
// actual payload by a smaller margin than ETS_001. `length_override =
// 0x20` claims 32 bytes follow Request ID; the UDP datagram only
// carries 1 byte of payload (0x42). vsomeip's parser detects the
// shortfall and drops the frame. Pass shape mirrors ETS_001 (Error
// Response or silent ignore); fail = DUT echoed back with
// return_code 0x00.
template <>
struct TestCaseTraits<cases::SomeipEts002SM> : SomeIpAnyBase<cases::SomeipEts002SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_002";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "Length field overshoots actual payload — DUT must reject or ignore";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0008;
        target.payload = {0x42};
        target.length_override = 0x20u;
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts002SM, someip_ets_002)
