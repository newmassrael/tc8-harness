#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_112_sm.h"

namespace tc8::sce::cases {

using SomeipEts112SM = ::SCE::Generated::someip_ets_112::someip_ets_112;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_112 — SubscribeEventgroup with IPv4 Endpoint
// option's body Length field = 0 (canonical 9). Per PRS_SOMEIPSD_00307 the
// DUT must Nack. Lenient verdict accepts silent ignore via vsomeip's
// option-walker bad-length gate. Lift of ETS_136 (option_body_len_override
// = 0).
template <>
struct TestCaseTraits<cases::SomeipEts112SM> : SomeIpAnyBase<cases::SomeipEts112SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_112";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup with IPv4Option Length=0 — DUT Nacks or ignores";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SubscribeEventgroupParams params{};
        params.target.eventgroup_id = 0x0002;
        params.session_id = 0x0001;
        // IPv4 Endpoint option Length field set to 0 (canonical 9). Walker
        // reads the option body as zero bytes → cannot parse address/port
        // → option invalid → walk fails → Nack or ignore.
        params.option_body_len_override = std::uint16_t{0};
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts112SM, someip_ets_112)
