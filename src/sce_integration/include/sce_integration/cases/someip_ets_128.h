#pragma once

#include <chrono>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_128_sm.h"

namespace tc8::sce::cases {

using SomeipEts128SM = ::SCE::Generated::someip_ets_128::someip_ets_128;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_128 — burst A: 10 FindService at 100 ms with
// Major Version = 0xFF (wildcard "any major"); burst B: 10 FindService at
// 100 ms with Minor Version = 0xFFFFFFFF (wildcard "any minor"). Per
// PRS_SOMEIPSD_00422 / 00423 the DUT must reply with at least one
// OfferService per burst; the ids in TC8's Reference row (00268 / 00305 /
// 00306 / 00307 / 00351) are entry- and option-format requirements, with
// 00351 covering the wildcard fields this case sets, not the answer duty.
template <>
struct TestCaseTraits<cases::SomeipEts128SM> : SomeIpAnyBase<cases::SomeipEts128SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_128";
    static constexpr std::string_view kDescription =
        "Major-Version wildcard burst + Minor-Version wildcard burst — DUT answers each";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& /*cfg*/,
                         std::string_view iface) {
        // Burst A: Major = 0xFF (any major), Minor = 0 (default).
        ::tc8::stimulus::BootTiming timing_a{};
        timing_a.initial_wait    = std::chrono::milliseconds(1500);
        timing_a.retry_interval  = std::chrono::milliseconds(100);
        timing_a.total_emits     = 10;
        ::tc8::stimulus::FindServiceTarget target_a{};
        target_a.major_version = 0xFF;
        target_a.minor_version = 0x00000000U;
        ::tc8::stimulus::emitFindServiceBoot(iface, target_a, timing_a);

        // Burst B: Major = 1 (default), Minor = 0xFFFFFFFF (any minor).
        // initial_wait = 0 — already in main phase after burst A.
        ::tc8::stimulus::BootTiming timing_b{};
        timing_b.initial_wait    = std::chrono::milliseconds(0);
        timing_b.retry_interval  = std::chrono::milliseconds(100);
        timing_b.total_emits     = 10;
        ::tc8::stimulus::FindServiceTarget target_b{};
        target_b.major_version = 0x01;
        target_b.minor_version = 0xFFFFFFFFU;
        ::tc8::stimulus::emitFindServiceBoot(iface, target_b, timing_b);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts128SM, someip_ets_128)
