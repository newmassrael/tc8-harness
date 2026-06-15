#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_108_sm.h"

namespace tc8::sce::cases {

using SomeipEts108SM = ::SCE::Generated::someip_ets_108::someip_ets_108;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_108 — Subscribe → DUT Ack(+initial events)
// → StopSubscribeEventgroup → after the Stop, DUT must NOT broadcast any
// further TestEventUINT8 to the tester (subscription removed). Per
// PRS_SOMEIPSD_00386 / 00388 / 00389 the absence of post-Stop events is
// the conformance signal.
template <>
struct TestCaseTraits<cases::SomeipEts108SM> : SomeIpAnyBase<cases::SomeipEts108SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_108";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "Subscribe → StopSubscribe → DUT does not broadcast event to former subscriber";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        // Subscribe to eg 0x0005.
        ::tc8::stimulus::SubscribeEventgroupParams sub{};
        sub.target.eventgroup_id = 0x0005;
        sub.target.ttl = 3;
        sub.session_id = 0x0001;
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, sub);
        // Subscribe processed at t≈stim+2.5s; SCXML phase 2 → phase 3
        // grace timer (3 s) starts. Hold here long enough that Stop emit
        // lands inside the grace window — then by phase 4 entry (grace
        // expiry) vsomeip has dropped tester from the subscriber list
        // and the absence assertion is clean.
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        // StopSubscribe (ttl=0).
        ::tc8::stimulus::SubscribeEventgroupParams stop{};
        stop.target.eventgroup_id = 0x0005;
        stop.target.ttl = 0;
        stop.session_id = 0x0002;
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, stop);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts108SM, someip_ets_108)
