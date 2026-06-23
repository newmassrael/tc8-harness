#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_138_sm.h"

namespace tc8::sce::cases {

using SomeipEts138SM = ::SCE::Generated::someip_ets_138::someip_ets_138;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_138 — SubscribeEventgroup whose OptionsLen
// (40) is larger than the message can actually hold (one IPv4 Endpoint
// option = 12 B physically present). Per PRS_SOMEIPSD_00390 the DUT
// shall Ack; AUTOSAR compatibility also allows ignoring. Lenient
// positive verdict accepts Ack OR silent ignore; Nack lands fail.
template <>
struct TestCaseTraits<cases::SomeipEts138SM> : SomeIpAnyBase<cases::SomeipEts138SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_138";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup OptionsLen larger than message — DUT Acks or ignores";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SubscribeEventgroupParams params{};
        // Use a configured eventgroup so a successful Ack can land
        // (Nack would still trip even on an unknown eg, but a real
        // configured eg gives the DUT the chance to take the Ack path).
        params.target.eventgroup_id = 0x0002;
        params.session_id = 0x0001;
        // Spec wording: declared OptionsLen 0x28 (40) vs canonical 0x18 (24).
        // Our 1-option canonical is 12; declaring 40 is longer than the
        // actual trailing bytes so the parser can't walk past the message
        // boundary. PRS_SOMEIPSD_00390 says Ack-or-ignore.
        params.options_len_override = 40U;
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts138SM, someip_ets_138)
