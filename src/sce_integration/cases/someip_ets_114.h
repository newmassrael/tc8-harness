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

#include "someip_ets_114_sm.h"

namespace tc8::sce::cases {

using SomeipEts114SM = ::SCE::Generated::someip_ets_114::someip_ets_114;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_114 — Multi-entry SD with two correct
// Subscribe entries but EntriesLen field shortened (declared 24 vs actual
// 32 bytes, i.e. 1.5 entries declared while 2 entries are physically on
// wire). Per PRS_SOMEIPSD_00264 / 00265 / 00393 the DUT must Nack.
// Lenient verdict accepts silent ignore — vsomeip's SD parser typically
// drops at the bad-length-field gate.
template <>
struct TestCaseTraits<cases::SomeipEts114SM> : SomeIpAnyBase<cases::SomeipEts114SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_114";
    static constexpr std::string_view kDescription =
        "Multi-entry Subscribe with shortened EntriesLen — DUT Nacks or ignores";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::MultiSubscribeEventgroupParams params{};
        ::tc8::stimulus::SubscribeEventgroupTarget e1{};
        e1.eventgroup_id = 0x0002;
        e1.ttl = 3;
        params.entries.push_back(e1);
        ::tc8::stimulus::SubscribeEventgroupTarget e2{};
        e2.eventgroup_id = 0x0005;
        e2.ttl = 3;
        params.entries.push_back(e2);
        // Two entries = 32 bytes actual; declare 24 (1.5 entries) so the
        // walker fails to align on the second entry boundary.
        params.entries_len_override = 24U;
        ::tc8::stimulus::emitMultiSubscribeEventgroupRaw(
            iface, std::move(params), std::chrono::milliseconds(0));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts114SM, someip_ets_114)
