#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_sd_behavior_01_sm.h"

namespace tc8::sce::cases {

using SdBehavior01SM =
    ::SCE::Generated::someipsrv_sd_behavior_01::someipsrv_sd_behavior_01;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.4.1 SOMEIPSRV_SD_BEHAVIOR_01: Repetition Phase delay
// shall double after each message — verified by capturing the gap
// between the 1st and 2nd Notification IN the Repetition Phase and
// asserting it lies within REP_BASE*2 ± ParamToleranceTimeMillisec
// (vsomeip default 200 ms * 2 = 400 ms; tolerance ±100 ms encoded as
// the [300_000, 500_000] microsecond window in the SCXML guard).
//
// SD-only base; no stimulus (the Repetition Phase fires from DUT-side
// vsomeip SD bootstrap on its own — tester only listens). Inter-frame
// timing is read off `SomeIpCaptured::frame_delta_us()`, populated by
// the auto-managed prev-ts snapshot in `SomeIpSdOnlyBase::dispatch`.
template <>
struct TestCaseTraits<cases::SdBehavior01SM>
    : SomeIpSdOnlyBase<cases::SdBehavior01SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_SD_BEHAVIOR_01";
    static constexpr std::string_view kDescription =
        "Repetition Phase OfferService delay doubles between consecutive emits";
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SdBehavior01SM, someipsrv_sd_behavior_01)
