#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_107_sm.h"

namespace tc8::sce::cases {

using SomeipEts107SM = ::SCE::Generated::someip_ets_107::someip_ets_107;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_107 — Subscribe → DUT Ack(+initial events)
// → multi-entry SD message containing StopSubscribe (ttl=0) +
// SubscribeEventgroup (ttl=3) for the same eg → DUT Ack on the new
// Subscribe. Per PRS_SOMEIPSD_00263 the DUT shall process both entries
// in order (Stop then re-Subscribe).
template <>
struct TestCaseTraits<cases::SomeipEts107SM> : SomeIpAnyBase<cases::SomeipEts107SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_107";
    static constexpr std::string_view kDescription =
        "Subscribe → multi-entry SD (Stop+Subscribe) → DUT Acks both Subscribes";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        // First Subscribe (single-entry SD).
        ::tc8::stimulus::SubscribeEventgroupParams sub1{};
        sub1.target.eventgroup_id = 0x0005;
        sub1.target.ttl = 3;
        sub1.session_id = 0x0001;
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, sub1);
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));

        // Multi-entry SD: Stop (ttl=0) + Subscribe (ttl=3) both on the
        // same eg (0x0005). vsomeip's SD walker processes entries in
        // order: drop the existing subscription, then re-subscribe.
        std::vector<::tc8::stimulus::SubscribeEventgroupTarget> entries;
        ::tc8::stimulus::SubscribeEventgroupTarget stop{};
        stop.eventgroup_id = 0x0005;
        stop.ttl = 0;  // StopSubscribeEventgroup
        entries.push_back(stop);
        ::tc8::stimulus::SubscribeEventgroupTarget sub2{};
        sub2.eventgroup_id = 0x0005;
        sub2.ttl = 3;
        entries.push_back(sub2);
        ::tc8::stimulus::emitMultiSubscribeEventgroup(
            iface, entries, std::chrono::milliseconds(0));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts107SM, someip_ets_107)
