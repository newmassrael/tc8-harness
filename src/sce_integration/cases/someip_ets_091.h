#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_091_sm.h"

namespace tc8::sce::cases {

using SomeipEts091SM = ::SCE::Generated::someip_ets_091::someip_ets_091;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_091 — SD_Check_OfferService_Request_ID_incrementation.
// Pure-observation case: the DUT's cyclic OfferService stream must carry
// strictly-increasing SD Session-IDs across iterations (PRS_SOMEIPSD_00154
// / 00157 / 00355). Phase 1 snapshots `prev_sd_session_id` on the first
// observed OfferService; phase 2 asserts `session_id > prev_sd_session_id`
// on the next.
template <>
struct TestCaseTraits<cases::SomeipEts091SM> : SomeIpAnyBase<cases::SomeipEts091SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_091";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "Cyclic OfferService Session-IDs must strictly increment across iterations";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        // FindServiceBoot warms up SD on the tester side and re-engages
        // the DUT's Repetition / Main Phase cadence — same envelope every
        // §5.1.6 ETS observation case uses. ETS_091's verdict only reads
        // session_id deltas, so no further stimulus is required.
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                            return "pass";
            case State::Fail_phase1_no_offer_with_endpoint:              return "fail:no_offer_service_with_ipv4_endpoint_within_listen_window";
            case State::Fail_phase2_session_id_did_not_increment:        return "fail:offer_service_session_id_did_not_increment";
            case State::Fail_phase2_no_second_offer:                     return "fail:no_second_offer_service_within_listen_window";
            default:                                                     return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts091SM, someip_ets_091)
