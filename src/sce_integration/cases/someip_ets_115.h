#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_115_sm.h"

namespace tc8::sce::cases {

using SomeipEts115SM = ::SCE::Generated::someip_ets_115::someip_ets_115;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_115 — SubscribeEventgroup whose entry's
// #Opt1 nibble (canonical 1, "one option in run 1") is set to 2 while
// only one IPv4 Endpoint option is physically present in the options
// array. Per PRS_SOMEIPSD_00393 / 00566 the DUT must Nack. Lenient
// verdict accepts silent ignore.
template <>
struct TestCaseTraits<cases::SomeipEts115SM> : SomeIpAnyBase<cases::SomeipEts115SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_115";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup with more option references than exist — DUT Nacks or ignores";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SubscribeEventgroupParams params{};
        params.target.eventgroup_id = 0x0002;
        params.session_id = 0x0001;
        // #Opt1 nibble = 2; options array still carries only 1 option.
        // Walker reads "2 options in run 1", advances 24 bytes (2 × 12),
        // overshoots the options array, fails to parse.
        params.num_options_first_override = std::uint8_t{2};
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts115SM, someip_ets_115)
