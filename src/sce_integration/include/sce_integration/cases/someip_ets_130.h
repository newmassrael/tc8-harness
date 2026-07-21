#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_130_sm.h"

namespace tc8::sce::cases {

using SomeipEts130SM = ::SCE::Generated::someip_ets_130::someip_ets_130;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_130 — multicast FindService with SD Unicast
// Flag = 0 (sd_flags = 0x80 — Reboot=1 Unicast=0). DUT must ignore the
// flag and respond with at least one OfferService per PRS_SOMEIPSD_00268
// / 00305 / 00306 / 00307. Builds the FindService directly via
// buildFindService + sendSdMulticast because emitFindServiceBoot
// hardcodes sd_flags = 0xC0.
template <>
struct TestCaseTraits<cases::SomeipEts130SM> : SomeIpAnyBase<cases::SomeipEts130SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_130";
    static constexpr std::string_view kDescription =
        "FindService with Unicast Flag=0 — DUT ignores flag and answers";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& /*cfg*/,
                         std::string_view iface) {
        // Initial wait so DUT's SD comes up before stimulus.
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        ::tc8::stimulus::FindServiceParams p{};
        p.target = ::tc8::stimulus::FindServiceTarget{};
        p.session_id = 0x0001;
        p.sd_flags = 0x80;  // Reboot=1 Unicast=0 — the case's whole point.
        const auto bytes = ::tc8::stimulus::buildFindService(p);
        ::tc8::stimulus::sendSdMulticast(bytes, iface);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts130SM, someip_ets_130)
