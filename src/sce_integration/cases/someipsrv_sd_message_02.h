#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_sd_message_02_sm.h"

namespace tc8::sce::cases {

using SdMessage02SM =
    ::SCE::Generated::someipsrv_sd_message_02::someipsrv_sd_message_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.3.2 — FindService(instance_id=specific) returns an
// OfferService with entries for that one instance only. Spec body
// chains Find(extracted-instance-1) and Find(extracted-instance-2);
// stimulus emits both sequentially, with a `retry_interval`-spaced gap
// so the DUT's first Find-triggered Offer doesn't race phase 2's
// observation window.
template <>
struct TestCaseTraits<cases::SdMessage02SM>
    : SomeIpSdOnlyBase<cases::SdMessage02SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_SD_MESSAGE_02";
    static constexpr std::string_view kSpecSection = "5.1.5.3.2";
    static constexpr std::string_view kDescription =
        "FindService(specific instance) returns OfferService with that one entry";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::FindServiceTarget find1{};
        find1.service_id = cfg.someip.service_id;
        find1.instance_id = cfg.someip.instance_id;
        ::tc8::stimulus::emitFindServiceBoot(iface, find1);

        ::tc8::stimulus::FindServiceTarget find2{};
        find2.service_id = cfg.someip.service_id;
        find2.instance_id = static_cast<std::uint16_t>(cfg.someip.instance_id + 1);
        // Boot timing already paid by find1's emitFindServiceBoot; reuse
        // a shorter envelope so phase 2 receives its trigger before the
        // 6 s phase-2 deadline.
        ::tc8::stimulus::SdBootTiming timing{};
        timing.initial_wait = std::chrono::milliseconds{500};
        timing.retry_interval = std::chrono::milliseconds{500};
        timing.total_emits = 2;
        ::tc8::stimulus::emitFindServiceBoot(iface, find2, timing);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:
                return "pass";
            case State::Fail_phase1_no_offer_for_instance_1:
                return "fail:no_single_entry_offer_for_instance_id_1_within_listen_window";
            case State::Fail_phase2_no_offer_for_instance_2:
                return "fail:no_single_entry_offer_for_instance_id_2_within_listen_window";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SdMessage02SM, someipsrv_sd_message_02)
