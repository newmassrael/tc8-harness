#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_171_sm.h"

namespace tc8::sce::cases {

using SomeipEts171SM = ::SCE::Generated::someip_ets_171::someip_ets_171;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_171 — Tester sends several UNICAST FindService
// messages (vs the canonical multicast). Per PRS_SOMEIPSD_00422 / 00423 the
// DUT shall respond with at least one OfferService for the requested
// SERVICE-ID-1; the ids in TC8's Reference row (00268 / 00305 / 00306 /
// 00307) are entry- and option-format requirements, not the answer duty.
//
// This trait skips `emitFindServiceBoot` (which emits multicast) and instead
// builds + unicast-sends the FindService directly to the DUT's SD endpoint
// via `sendSdUnicast`. Cadence is 3 emits ~700 ms apart so the DUT's SD
// state machine receives the request after its initial-delay window even
// under cluster-regression timing jitter.
template <>
struct TestCaseTraits<cases::SomeipEts171SM> : SomeIpAnyBase<cases::SomeipEts171SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_171";
    static constexpr std::string_view kDescription =
        "Tester unicast FindService — DUT responds with OfferService";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        // Wait for DUT initial SD startup (vsomeip initial_delay_min/max
        // typically settles within ~1.5 s).
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));

        // The DUT's SD endpoint: the address this run targets, on the SD port. A
        // default-built SubscribeDestination holds 0 ("derive it"), which only the
        // Subscribe emitters resolve; sent raw it addressed 0.0.0.0 and the Finds
        // never reached the wire.
        for (std::uint16_t sid = 0x0001; sid <= 0x0003; ++sid) {
            ::tc8::stimulus::FindServiceParams p{};
            p.session_id = sid;
            p.sd_flags = 0xC0;
            const auto datagram = ::tc8::stimulus::buildFindService(p);
            ::tc8::stimulus::sendSdUnicast(datagram, ctx.iface, cfg.dut.ip, ::tc8::dut::kSdPort);
            std::this_thread::sleep_for(std::chrono::milliseconds(700));
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts171SM, someip_ets_171)
