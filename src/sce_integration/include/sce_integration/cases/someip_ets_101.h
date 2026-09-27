#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>

#include "tc8/someip/sd_wire_constants.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/someip_observation.h"
#include "sce_integration/stimulus_context.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_101_sm.h"

namespace tc8::sce::cases {

using SomeipEts101SM = ::SCE::Generated::someip_ets_101::someip_ets_101;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_101 — SD_ClientServiceActivate_send_
// StopOfferService. Tester activates Client Mode then emits StopOfferService
// (OfferService entry with TTL = 0) for SERVICE-ID-2; per spec the DUT must
// stop sending FindService for that Service+Instance pair. The DUT firmware
// realises this implicitly through the bounded Repetition Phase
// (kRepetitionsMax+1 emits then idle), so the wire pattern aligns with the
// spec without an explicit StopOfferService listener — see client_mode.h.
//
// Stimulus chain:
//   1. emitFindServiceBoot — wakes vsomeip server.
//   2. emitMethodRequestAfter(clientServiceActivate) — DUT spawns runner.
//   3. Await the runner's first FindService for SERVICE-ID-2.
//   4. emitOfferServiceMulticast(ttl=0) — StopOfferService for SERVICE-ID-2.
//
// Step 3 used to be a 500 ms sleep before step 4, standing for "the runner has
// at least one FindService on the wire before the Stop arrives". That is the
// case's precondition — phase 2 grades exactly that FindService — so it is now
// observed rather than assumed. When it does not arrive the Stop is not sent:
// with no search to stop, the absence phase would grade nothing, and the run is
// reported as a stimulus that could not be performed.
//
// Reference: PRS_SOMEIPSD_00351 / PRS_SOMEIPSD_00363.
template <>
struct TestCaseTraits<cases::SomeipEts101SM> : SomeIpAnyBase<cases::SomeipEts101SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_101";
    static constexpr std::string_view kDescription =
        "Client Mode StopOfferService stops DUT FindService for the bounced Service+Instance";

    // SERVICE-ID-2: the service the activated client searches for, and the one
    // the Stop withdraws. The same literal as the SCXML's phase-2 guard.
    static constexpr std::uint16_t kSearchedServiceId = 0xF4E8;

    // How long the runner's first FindService may take after activation. The same
    // allowance the SCXML gives it (listening_phase2_first_find's 5 s deadline);
    // an SCXML delay is a string literal, so the two are kept equal by hand.
    static constexpr std::chrono::milliseconds kFirstFindBound{5000};

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        ::tc8::stimulus::emitFindServiceBoot(ctx.iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::SomeIpRpcMessage target{};
        target.method_id    = 0x002F;
        target.message_type = ::tc8::someip::MessageType::REQUEST_NO_RETURN;
        target.payload      = {0x00};
        // Marked before the activation, so a FindService the runner sends while
        // the request is still being emitted counts.
        const ::tc8::sce::ObservationCursor activated = ctx.observer.mark();
        ::tc8::stimulus::emitMethodRequestAfter(ctx.iface, target, {},
                                                ::tc8::sce::someipUdpMethodDest(cfg));
        const auto first_find = ctx.observer.awaitObservation(
            "dut_client_first_find_service", activated,
            ::tc8::sce::dutSdFirstEntry(cfg.dut.ip, ::tc8::sd_entry_type::kFindService,
                                        kSearchedServiceId),
            kFirstFindBound);
        if (!first_find) {
            return;
        }
        ::tc8::stimulus::OfferServiceTarget stop{};
        stop.ttl        = 0;            // ttl == 0 -> StopOfferService.
        stop.session_id = 0x0001;
        ::tc8::stimulus::emitOfferServiceMulticast(ctx.iface, stop,
                                                   std::chrono::milliseconds(0));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts101SM, someip_ets_101)
