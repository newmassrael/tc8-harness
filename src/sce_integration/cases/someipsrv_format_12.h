#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_format_12_sm.h"

namespace tc8::sce::cases {

using Format12SM =
    ::SCE::Generated::someipsrv_format_12::someipsrv_format_12;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.1.12 — Solicited OfferService Type 1 entry shall carry
// IndexFirstOptionRun == 0. Stimulus is a tester-initiated FindService so
// the DUT emits a solicited OfferService; dispatch shadows the base to
// gate on entry type 0x01 (OfferService) before fill so unsolicited
// FindService echoes leave ctx untouched (invariant: ctx is mutated only
// on frames that raise an SM event).
template <>
struct TestCaseTraits<cases::Format12SM>
    : SomeIpSdOnlyBase<cases::Format12SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_FORMAT_12";
    static constexpr std::string_view kSpecSection = "5.1.5.1.12";
    static constexpr std::string_view kDescription =
        "Solicited OfferService Type 1 entry IndexFirstOptionRun == 0";

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
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Format12SM, someipsrv_format_12)
