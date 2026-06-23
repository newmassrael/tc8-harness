#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_139_sm.h"

namespace tc8::sce::cases {

using SomeipEts139SM = ::SCE::Generated::someip_ets_139::someip_ets_139;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_139 — SubscribeEventgroup whose OptionsLen
// (2) is shorter than required to access the IPv4 Endpoint option
// referenced by the entry's #Opt1 field. Per PRS_SOMEIPSD_00265 / 00270
// / 00566 the DUT must Nack. Lenient verdict accepts ignore as well.
template <>
struct TestCaseTraits<cases::SomeipEts139SM> : SomeIpAnyBase<cases::SomeipEts139SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_139";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup OptionsLen too short to access the option — DUT Nacks or ignores";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SubscribeEventgroupParams params{};
        params.target.eventgroup_id = 0x0001;
        params.session_id = 0x0001;
        // Spec wording: 2 bytes vs the original 24 — declared OptionsLen
        // smaller than even one option's 2-byte Length field can hold.
        // Triggers the DUT-side options-array truncation path.
        params.options_len_override = 2U;
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts139SM, someip_ets_139)
