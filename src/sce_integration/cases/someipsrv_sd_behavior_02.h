#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "someipsrv_sd_behavior_02_sm.h"

namespace tc8::sce::cases {

using SdBehavior02SM =
    ::SCE::Generated::someipsrv_sd_behavior_02::someipsrv_sd_behavior_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.4.2 SOMEIPSRV_SD_BEHAVIOR_02: Main Phase
// OfferService messages cyclic with cyclic_offer_delay. The pre-main
// listen window discards Repetition Phase Offers via deadline-only
// transition; phase 2 captures the first Main Phase Offer; phase 3
// asserts the gap to the second is within cyclic_offer_delay ± tol
// (2000 ms ± 200 ms gate in the SCXML).
template <>
struct TestCaseTraits<cases::SdBehavior02SM>
    : SomeIpSdOnlyBase<cases::SdBehavior02SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_SD_BEHAVIOR_02";
    static constexpr std::string_view kSpecSection = "5.1.5.4.2";
    static constexpr std::string_view kDescription =
        "Main Phase OfferService cyclic gap == cyclic_offer_delay ± tolerance";

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                      return "pass";
            case State::Fail_phase2_no_first_main_offer:           return "fail:no_first_main_phase_offer_within_listen_window";
            case State::Fail_phase3_no_second_main_offer:          return "fail:no_second_main_phase_offer_within_listen_window";
            case State::Fail_phase3_cyclic_out_of_tolerance:       return "fail:cyclic_offer_gap_not_within_cyclic_offer_delay_tolerance";
            default:                                               return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SdBehavior02SM, someipsrv_sd_behavior_02)
