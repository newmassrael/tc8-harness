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

// TC8 v3.0 §5.1.6 SOMEIP_ETS_093 (lite) — SD reboot detection separated
// across multicast and unicast SD channels. Subtest A only: tester
// drives 3 multicast FindService + unicast Subscribe pairs with
// session_ids { 0x4, 0x5, 0x1 }; the third lower-sid Subscribe must
// trigger vsomeip's per-channel reboot tracker (expire + reprocess) and
// the DUT must Ack — NOT Nack — the lower-sid Subscribe (PRS_SOMEIPSD_00157).
//
// The "initial event" wire signal called out by the spec body (Notify of
// Field InterfaceVersion 0x8005) is not exposed by tc8-dut, so the verdict
// is degraded to Ack-counting: 3 SubscribeEventgroupAcks all with ttl > 0.
// Subtests B (unicast-only) and C (cross-channel robustness) are deferred.
template <>
struct TestCaseTraits<cases::SomeipEts093SM> : SomeIpAnyBase<cases::SomeipEts093SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_093";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "Multicast/unicast reboot tracker — DUT Acks lower-sid Subscribe after reboot";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);

        // Capture-by-value so the lambdas survive past kickStimulus return.
        std::string iface_copy(iface);

        // Helper: emit one FindService(mcast) + one Subscribe(unicast)
        // pair with the caller's `sid`. Both wire frames carry rb=1 so
        // vsomeip's is_reboot rule consults old_sid >= new_sid as the
        // sole reboot discriminator.
        auto emit_pair = [iface_copy](std::uint16_t sid) {
            ::tc8::stimulus::FindServiceParams fs{};
            fs.session_id = sid;
            fs.sd_flags   = 0xC0;  // rb=1 unicast=1
            const auto fs_datagram = ::tc8::stimulus::buildFindService(fs);
            ::tc8::stimulus::sendSdMulticast(fs_datagram, iface_copy);

            // Small inter-emit gap so the DUT can process the FindService
            // (and its multicast tracker advance) before the unicast
            // Subscribe arrives — keeps vsomeip's handle ordering
            // consistent across the per-channel trackers.
            std::this_thread::sleep_for(std::chrono::milliseconds(200));

            ::tc8::stimulus::SubscribeEventgroupTarget sub{};
            sub.eventgroup_id = 0x0005;
            sub.ttl           = 3;
            ::tc8::stimulus::emitSubscribeEventgroupOnce(iface_copy, sub, sid, 0xC0);
        };

        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_phase2_first_ack),
            [emit_pair]() { emit_pair(0x0004); });

        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_phase3_second_ack),
            [emit_pair]() { emit_pair(0x0005); });

        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_phase4_reboot_ack),
            [emit_pair]() { emit_pair(0x0001); });
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts093SM, someip_ets_093)
