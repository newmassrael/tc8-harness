#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_125_sm.h"

namespace tc8::sce::cases {

using SomeipEts125SM = ::SCE::Generated::someip_ets_125::someip_ets_125;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_125 — SubscribeEventgroup with EntriesLen
// too short to span the Type 2 entry actually present on-wire (16 B
// canonical, override = 8 B). Per PRS_SOMEIPSD_00265 / 00270 the DUT
// must Nack. Lenient verdict accepts ignore as well — vsomeip's parser
// truncates entries-array reading mid-entry and silently drops.
template <>
struct TestCaseTraits<cases::SomeipEts125SM> : SomeIpAnyBase<cases::SomeipEts125SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_125";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup EntriesLen too short — DUT Nacks or ignores";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SubscribeEventgroupParams params{};
        params.target.eventgroup_id = 0x0001;
        params.session_id = 0x0001;
        // Spec: "Entry Array Length less than the sum of the Lengths
        // indicated by each Option" — interpreted as EntriesLen < the
        // 16 bytes one Type 2 entry occupies. 8 B is half a Type 2
        // entry, so the parser walks 8 bytes and finds the boundary
        // mid-entry.
        params.entries_len_override = 8U;
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts125SM, someip_ets_125)
