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

#include "someip_ets_177_sm.h"

namespace tc8::sce::cases {

using SomeipEts177SM = ::SCE::Generated::someip_ets_177::someip_ets_177;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_177 — SubscribeEventgroup with trailing
// payload at the end whose length is NOT counted by the SOME/IP Length
// field. Per PRS_SOMEIPSD_00153 / 00273 the DUT shall ignore the trailing
// bytes and Ack. Single-phase variant of ETS_176 (uncounted-only).
template <>
struct TestCaseTraits<cases::SomeipEts177SM> : SomeIpAnyBase<cases::SomeipEts177SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_177";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup with uncounted trailing payload — DUT Acks";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SubscribeEventgroupParams params{};
        params.target.eventgroup_id = 0x0002;
        params.session_id = 0x0001;
        params.extra_trailing_payload = std::vector<std::uint8_t>{0xDE, 0xAD, 0xBE, 0xEF};
        params.extra_trailing_in_length = false;
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts177SM, someip_ets_177)
