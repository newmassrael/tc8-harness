#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_093_sm.h"

namespace tc8::sce::cases {

using SomeipEts093SM = ::SCE::Generated::someip_ets_093::someip_ets_093;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_093 — the DUT detects a client reboot on each SD
// channel, and keeps the channels apart (PRS_SOMEIPSD_00157). Evidence: the
// initial event of Field InterfaceVersion (0x8005) that a NEW subscription draws.
// Subtest A sends three FindService(multicast) + Subscribe(unicast) pairs with
// Session IDs { 0x4, 0x5, 0x1 }; subtest B three unicast Subscribes alone with the
// same IDs. In each, 0x8005 must follow the first Subscribe, must not follow the
// second (a renewal), and must follow the third, which only a DUT that detected
// the reboot treats as new. Subtest C cross-sends two pairs, multicast
// { 0x6, 0x7 } after A's 0x1 and unicast { 0x2, 0x3 } after B's 0x1: each channel
// only increases and unicast stays lower, so a DUT that keeps one tracker per
// channel sees renewals (no 0x8005) and one that mixes them reads a reboot.
//
// Subtest B's first Subscribe must meet no subscription (step 14 expects the
// initial event "due to the new subscription"), and the procedure states no step
// that ends A's. B therefore opens with a StopSubscribeEventgroup at Session ID
// 0x2: one more increment on the unicast channel after A's 0x1, so it is not a
// reboot, and below B's 0x4, so B's sequence is the procedure's. Waiting out A's
// TTL instead would put the same claim on the DUT's expiry timing and add 17 s.
template <>
struct TestCaseTraits<cases::SomeipEts093SM> : SomeIpAnyBase<cases::SomeipEts093SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_093";
    static constexpr std::string_view kDescription =
        "Reboot detection per SD channel — initial event after a new and a post-reboot Subscribe only";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        ::tc8::stimulus::emitFindServiceBoot(ctx.iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);

        // Capture-by-value so the lambdas survive past kickStimulus return.
        std::string iface_copy(ctx.iface);

        // One Subscribe(unicast) to eventgroup 0x0005 with the caller's `sid`
        // and rb=1, so the DUT's reboot rule consults old_sid >= new_sid alone.
        // `ttl` 0 makes it a StopSubscribeEventgroup. The live TTL outlasts
        // the next Subscribe of the subtest, which comes after an 11 s window,
        // so a third Subscribe meets a live subscription.
        auto subscribe = [iface_copy](std::uint16_t sid, std::uint32_t ttl) {
            // Every Subscribe follows the end of the previous phase by at least
            // this gap (subtests A and C send their FindService before it), so the
            // previous Subscribe's initial events, which the reference DUT has
            // been measured to send twice 70 us apart, are on the wire before the
            // next Subscribe's Ack opens a window that would charge them to it.
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            ::tc8::stimulus::SubscribeEventgroupTarget sub{};
            sub.eventgroup_id = 0x0005;
            sub.ttl           = ttl;
            ::tc8::stimulus::emitSubscribeEventgroupOnce(iface_copy, sub, sid, 0xC0);
        };

        // Subtests A and C: FindService(multicast) with `mcast_sid`, then
        // Subscribe(unicast) with `ucast_sid`.
        auto emit_pair = [iface_copy, subscribe](std::uint16_t mcast_sid, std::uint16_t ucast_sid) {
            ::tc8::stimulus::FindServiceParams fs{};
            fs.session_id = mcast_sid;
            fs.sd_flags   = 0xC0;  // rb=1 unicast=1
            const auto fs_datagram = ::tc8::stimulus::buildFindService(fs);
            ::tc8::stimulus::sendSdMulticast(fs_datagram, iface_copy);

            // The Subscribe's lead-in gap also lets the DUT process the
            // FindService (and advance its multicast tracker) before the
            // unicast Subscribe arrives, which keeps vsomeip's handling order
            // the same across the per-channel trackers.
            subscribe(ucast_sid, ::tc8::stimulus::kSubscribeOutlastTtl);
        };

        // Subtest A: the same Session ID on both channels.
        ctx.scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Awaiting_multicast_first_ack_and_initial_event),
            [emit_pair]() { emit_pair(0x0004, 0x0004); });
        ctx.scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Awaiting_multicast_second_ack),
            [emit_pair]() { emit_pair(0x0005, 0x0005); });
        ctx.scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Awaiting_multicast_reboot_ack_and_initial_event),
            [emit_pair]() { emit_pair(0x0001, 0x0001); });

        // Subtest B: unicast Subscribes alone, after stopping A's subscription.
        ctx.scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Awaiting_unicast_first_ack_and_initial_event),
            [subscribe]() {
                subscribe(0x0002, 0);
                subscribe(0x0004, ::tc8::stimulus::kSubscribeOutlastTtl);
            });
        ctx.scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Awaiting_unicast_second_ack),
            [subscribe]() { subscribe(0x0005, ::tc8::stimulus::kSubscribeOutlastTtl); });
        ctx.scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Awaiting_unicast_reboot_ack_and_initial_event),
            [subscribe]() { subscribe(0x0001, ::tc8::stimulus::kSubscribeOutlastTtl); });

        // Subtest C: both channels go on increasing, unicast below multicast.
        ctx.scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Awaiting_cross_first_ack),
            [emit_pair]() { emit_pair(0x0006, 0x0002); });
        ctx.scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Awaiting_cross_second_ack),
            [emit_pair]() { emit_pair(0x0007, 0x0003); });
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts093SM, someip_ets_093)
