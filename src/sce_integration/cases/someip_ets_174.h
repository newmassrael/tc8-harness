#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_174_sm.h"

namespace tc8::sce::cases {

using SomeipEts174SM = ::SCE::Generated::someip_ets_174::someip_ets_174;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_174 — SubscribeEventgroup referencing an
// unknown option type (0x77). Per PRS_SOMEIPSD_00273 / 00393 the DUT must
// Nack. Same wire-shape axis as ETS_116; this case-id documents the spec
// reference SD_Unknown_Option_type (vs _116's "non-existing option type").
template <>
struct TestCaseTraits<cases::SomeipEts174SM> : SomeIpAnyBase<cases::SomeipEts174SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_174";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup with unknown option type — DUT Nacks or ignores";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SubscribeEventgroupParams params{};
        params.target.eventgroup_id = 0x0002;
        params.session_id = 0x0001;
        params.option_type_override = std::uint8_t{0x77};
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts174SM, someip_ets_174)
