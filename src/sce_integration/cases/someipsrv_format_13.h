#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_format_13_sm.h"

namespace tc8::sce::cases {

using Format13SM =
    ::SCE::Generated::someipsrv_format_13::someipsrv_format_13;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.1.13 — Solicited OfferService Type 1 entry shall
// reference at least one option in the first options run. Same shape as
// FORMAT_12: tester-initiated FindService stimulus + entry-type 0x01 gate
// before fill.
template <>
struct TestCaseTraits<cases::Format13SM>
    : SomeIpSdOnlyBase<cases::Format13SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_FORMAT_13";
    static constexpr std::string_view kSpecSection = "5.1.5.1.13";
    static constexpr std::string_view kDescription =
        "Solicited OfferService Type 1 entry NumberOfOpt1 >= 1";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface,
            ::tc8::stimulus::FindServiceTarget{},
            cfg.stimulus_timing);
    }

    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        const auto* f = std::get_if<::tc8::SomeIpFrame>(&ev);
        if (f == nullptr || f->service_id != 0xFFFF) return;
        if (::tc8::peekSdEntry0Type(f->payload_data, f->payload_len) != 0x01) return;
        ::tc8::fillSomeIpCapturedFromFrame(c, *f);
        sm.raiseExternal(Event::Someip_notification);
        sm.step();
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:            return "pass";
            case State::Fail_num_opt1:   return "fail:entry_number_of_opt1_zero";
            case State::Fail_timeout:    return "fail:no_notification_within_listen_window";
            default:                     return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Format13SM, someipsrv_format_13)
