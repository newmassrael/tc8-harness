#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_136_sm.h"

namespace tc8::sce::cases {

using SomeipEts136SM = ::SCE::Generated::someip_ets_136::someip_ets_136;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_136 — SubscribeEventgroup whose IPv4
// Endpoint option's own Length field declares 4 bytes instead of the
// canonical 9 required for the option type (SD §7.4.3). Per
// PRS_SOMEIPSD_00307 / 00393 the DUT must Nack or fully ignore. Lenient
// verdict accepts both — vsomeip's SD parser bails out as soon as an
// individual option's Length doesn't match its type's expected size.
template <>
struct TestCaseTraits<cases::SomeipEts136SM> : SomeIpAnyBase<cases::SomeipEts136SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_136";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup IPv4 Endpoint option Length 4 instead of 9 — DUT Nacks or ignores";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SubscribeEventgroupParams params{};
        params.target.eventgroup_id = 0x0001;
        params.session_id = 0x0001;
        // Spec wording: option Length less than specified for the Type
        // (4 instead of 9). SOME/IP Length and OptionsLen stay canonical.
        params.option_body_len_override = std::uint16_t{4};
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                return "pass";
            case State::Fail_phase1_no_offer:                return "fail:no_offer_service_within_listen_window";
            case State::Fail_phase2_dut_acked_malformed:     return "fail:dut_acked_malformed_option_body_length";
            default:                                         return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts136SM, someip_ets_136)
