#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_135_sm.h"

namespace tc8::sce::cases {

using SomeipEts135SM = ::SCE::Generated::someip_ets_135::someip_ets_135;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_135 — SubscribeEventgroup whose OptionsLen
// is set smaller than the actual option bytes on-wire (declared 4 vs
// actual 12), while the SOME/IP Length stays canonical. The IPv4
// Endpoint option's own Length field stays correct, so individual
// option parsing would over-read past the declared OptionsLen. Per
// PRS_SOMEIPSD_00274 / 00393 / PRS_SOMEIP_00042 the DUT must Nack or
// ignore. Lenient verdict accepts both.
template <>
struct TestCaseTraits<cases::SomeipEts135SM> : SomeIpAnyBase<cases::SomeipEts135SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_135";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup OptionsLen smaller than actual option bytes — DUT Nacks or ignores";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SubscribeEventgroupParams params{};
        params.target.eventgroup_id = 0x0001;
        params.session_id = 0x0001;
        // Spec wording (Var B): Options Length surpasses the Length
        // indicated for the Options Array. Declared OptionsLen = 4 vs
        // actual one IPv4 Endpoint option = 12 bytes physically present.
        // SOME/IP Length stays canonical (48); only OptionsLen lies.
        params.options_len_override = 4U;
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts135SM, someip_ets_135)
