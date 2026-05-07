#pragma once

#include <chrono>
#include <string>
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

// TC8 v3.0 §5.1.5.3.2 — Spec body chains:
//   step 2: TESTER sends Find(instance_id=0xFFFF).
//   step 4-7: DUT replies with 2-entry OfferService; tester EXTRACTS
//             entries[0].instance_id → extractedInstID1 and
//             entries[1].instance_id → extractedInstID2.
//   step 8-11: TESTER sends Find(extractedInstID1); expects 1-entry
//              OfferService for that instance.
//   step 12+: TESTER sends Find(extractedInstID2); expects 1-entry
//             OfferService for that instance.
//
// Three-phase SCXML mirrors the spec literal: phase 1 observes the
// 2-entry response, phase 2 observes the inst1 response, phase 3
// observes the inst2 response. Stimulus emits Find(0xFFFF) at boot;
// the inst1/inst2 follow-up Finds fire from `scheduleAfterStateEntry`
// callbacks pinned to phase 2 / phase 3 entry, so the queries don't
// race ahead of the SCXML's listen window.
//
// Dispatch override: the base `SomeIpSdOnlyBase` is shadowed locally
// to snapshot entries[0..1].instance_id into captured slots whenever
// a 2-entry OfferService is observed. The SCXML phase 2/3 conds then
// compare incoming 1-entry replies against the slot values rather
// than hardcoding `expected.instance_id + 1` (which baked in the
// tc8-dut sequential allocator).
template <>
struct TestCaseTraits<cases::SdMessage02SM>
    : SomeIpSdOnlyBase<cases::SdMessage02SM> {
    using Base = SomeIpSdOnlyBase<cases::SdMessage02SM>;

    static constexpr std::string_view kCaseId      = "SOMEIPSRV_SD_MESSAGE_02";
    static constexpr std::string_view kSpecSection = "5.1.5.3.2";
    static constexpr std::string_view kDescription =
        "FindService(specific instance) returns OfferService with that one entry";

    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        const auto* f = std::get_if<::tc8::SomeIpFrame>(&ev);
        if (f == nullptr || f->service_id != 0xFFFF) return;
        ::tc8::fillSomeIpCapturedFromFrame(c, *f);
        // Spec body steps 6-7: extract instance IDs from the first
        // 2-entry OfferService observation. Always-update is benign
        // because vsomeip emits the same instance pair across all
        // OfferService frames in this scenario.
        if (c.sd_entry_count == 2 && c.sd_entries[0].type == 0x01 &&
            c.sd_entries[1].type == 0x01) {
            c.extracted_instance_id_1 = c.sd_entries[0].instance_id;
            c.extracted_instance_id_2 = c.sd_entries[1].instance_id;
        }
        const auto state_before = sm.getCurrentState();
        sm.raiseExternal(Event::Someip_notification);
        sm.step();
        if (sm.getCurrentState() != state_before) {
            c.prev_observed_ts_us = c.observed_ts_us;
            c.prev_sd_session_id = c.session_id;
        }
    }

    static void stimulus(Captured& c,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        // Phase 1: emit Find(instance_id=0xFFFF). Boot envelope absorbs
        // the DUT SD startup window and ensures at least one Find lands
        // during the DUT's Repetition Phase.
        ::tc8::stimulus::FindServiceTarget find_all{};
        find_all.service_id = cfg.someip.service_id;
        find_all.instance_id = 0xFFFF;
        ::tc8::stimulus::emitFindServiceBoot(iface, find_all);

        const std::string iface_owned(iface);
        const std::uint16_t service_id = cfg.someip.service_id;

        // Phase 2 entry → emit Find(extractedInstID1). State entry
        // observer guarantees the Find post-dates SCXML's listen-window
        // start, so the DUT's solicited 1-entry reply lands inside the
        // phase 2 deadline. Captured-by-reference `c` ensures the
        // callback reads the just-extracted instance ID.
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_phase2_find_inst1),
            [&c, iface_owned, service_id]() {
                ::tc8::stimulus::FindServiceTarget find_inst1{};
                find_inst1.service_id = service_id;
                find_inst1.instance_id = c.extracted_instance_id_1;
                ::tc8::stimulus::SdBootTiming timing{};
                timing.initial_wait = std::chrono::milliseconds{100};
                timing.retry_interval = std::chrono::milliseconds{500};
                timing.total_emits = 2;
                ::tc8::stimulus::emitFindServiceBoot(iface_owned, find_inst1, timing);
            });

        // Phase 3 entry → emit Find(extractedInstID2).
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_phase3_find_inst2),
            [&c, iface_owned, service_id]() {
                ::tc8::stimulus::FindServiceTarget find_inst2{};
                find_inst2.service_id = service_id;
                find_inst2.instance_id = c.extracted_instance_id_2;
                ::tc8::stimulus::SdBootTiming timing{};
                timing.initial_wait = std::chrono::milliseconds{100};
                timing.retry_interval = std::chrono::milliseconds{500};
                timing.total_emits = 2;
                ::tc8::stimulus::emitFindServiceBoot(iface_owned, find_inst2, timing);
            });
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:
                return "pass";
            case State::Fail_phase1_no_two_entry_offer:
                return "fail:no_two_entry_offer_for_findservice_any_within_listen_window";
            case State::Fail_phase2_no_offer_for_instance_1:
                return "fail:no_single_entry_offer_for_extracted_instance_1_within_listen_window";
            case State::Fail_phase3_no_offer_for_instance_2:
                return "fail:no_single_entry_offer_for_extracted_instance_2_within_listen_window";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SdMessage02SM, someipsrv_sd_message_02)
