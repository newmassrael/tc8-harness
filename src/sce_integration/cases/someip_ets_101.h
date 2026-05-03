#pragma once

#include <chrono>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
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
//   3. emitOfferServiceMulticast(ttl=0) — StopOfferService for SERVICE-ID-2.
//      Sleeps 500 ms first so the runner has at least one FindService on
//      the wire before the Stop arrives.
//
// Reference: PRS_SOMEIPSD_00351 / PRS_SOMEIPSD_00363.
template <>
struct TestCaseTraits<cases::SomeipEts101SM> : SomeIpAnyBase<cases::SomeipEts101SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_101";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "Client Mode StopOfferService stops DUT FindService for the bounced Service+Instance";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id    = 0x002F;
        target.message_type = 0x01;
        target.payload      = {0x00};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
        ::tc8::stimulus::OfferServiceTarget stop{};
        stop.ttl        = 0;            // ttl == 0 -> StopOfferService.
        stop.session_id = 0x0001;
        ::tc8::stimulus::emitOfferServiceMulticast(iface, stop,
                                                   std::chrono::milliseconds(500));
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                              return "pass";
            case State::Fail_phase1_no_offer:                              return "fail:no_offer_service_within_listen_window";
            case State::Fail_phase2_no_findservice:                        return "fail:no_dut_findservice_during_start_phase";
            case State::Fail_phase4_findservice_after_stop_offer:          return "fail:dut_findservice_after_stop_offer_service";
            default:                                                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts101SM, someip_ets_101)
