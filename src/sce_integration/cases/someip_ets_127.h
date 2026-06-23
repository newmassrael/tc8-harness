#pragma once

#include <chrono>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_127_sm.h"

namespace tc8::sce::cases {

using SomeipEts127SM = ::SCE::Generated::someip_ets_127::someip_ets_127;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_127 — 10 multicast FindService at 100 ms
// intervals; DUT replies with at least one unicast OfferService per
// PRS_SOMEIPSD_00305 / 00306 / 00307 / 00261. Reuses emitFindServiceBoot
// with `total_emits = 10` + `retry_interval = 100 ms` (default initial
// wait 1.5 s for SD warm-up).
template <>
struct TestCaseTraits<cases::SomeipEts127SM> : SomeIpAnyBase<cases::SomeipEts127SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_127";
    static constexpr std::string_view kDescription =
        "10 multicast FindService at 100 ms — DUT answers with unicast OfferService";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& /*cfg*/,
                         std::string_view iface) {
        ::tc8::stimulus::BootTiming timing{};
        timing.initial_wait    = std::chrono::milliseconds(1500);
        timing.retry_interval  = std::chrono::milliseconds(100);
        timing.total_emits     = 10;
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{}, timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts127SM, someip_ets_127)
