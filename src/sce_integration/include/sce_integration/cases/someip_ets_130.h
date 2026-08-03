#pragma once

#include <string>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_130_sm.h"

namespace tc8::sce::cases {

using SomeipEts130SM = ::SCE::Generated::someip_ets_130::someip_ets_130;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_130 — multicast FindService with SD Unicast
// Flag = 0 (sd_flags = 0x80 — Reboot=1 Unicast=0). The case requires the DUT
// to ignore the flag and respond with at least one OfferService. That is TC8's
// requirement, not AUTOSAR's: PRS_SOMEIPSD_00843 requires the opposite (such
// entries "shall not be answered with unicast but ignored"), which is why the
// reference stack's answer is compile-gated — see the SCXML header. The ids in
// TC8's own Reference row for this case (PRS_SOMEIPSD_00268 / 00305 / 00306 /
// 00307) are entry- and option-format requirements; they cover the encoding the
// case exercises, not the duty to answer. Builds the FindService directly via
// buildFindService + sendSdMulticast because emitFindServiceBoot
// hardcodes sd_flags = 0xC0.
//
// The Find is CADENCE-RELATIVE: it fires on entry to `listening_offer_reply`,
// which the SCXML reaches on an observed cyclic OfferService (the anchor), so
// the reply window sits between two of the DUT's own 2000 ms cyclics. A
// fixed-offset window would instead collect a cyclic offer and pass whether or
// not the Find was answered — see the SCXML header for that history.
template <>
struct TestCaseTraits<cases::SomeipEts130SM> : SomeIpAnyBase<cases::SomeipEts130SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_130";
    static constexpr std::string_view kDescription =
        "FindService with Unicast Flag=0 — DUT ignores flag and answers";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& /*cfg*/,
                         std::string_view iface,
                         IStimulusScheduler& scheduler) {
        // Captures iface by value: the observer runs on the poll-loop thread
        // long after this returns.
        const std::string iface_owned(iface);
        scheduler.scheduleAfterStateEntry(
            static_cast<int>(State::Listening_offer_reply),
            [iface_owned]() {
            ::tc8::stimulus::FindServiceParams p{};
            p.target = ::tc8::stimulus::FindServiceTarget{};
            p.session_id = 0x0001;
            p.sd_flags = 0x80;  // Reboot=1 Unicast=0 — the case's whole point.
            const auto bytes = ::tc8::stimulus::buildFindService(p);
            ::tc8::stimulus::sendSdMulticast(bytes, iface_owned);
        });
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts130SM, someip_ets_130)
