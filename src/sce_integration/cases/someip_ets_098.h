#pragma once

#include <chrono>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_098_sm.h"

namespace tc8::sce::cases {

using SomeipEts098SM = ::SCE::Generated::someip_ets_098::someip_ets_098;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_098 — SD_ClientService_subscribe_without_method_
// call. After Client Mode is activated WITHOUT the matching
// `clientServiceSubscribeEventgroup` trigger, the DUT must NOT subscribe
// to incoming OfferService Messages on its client-side target. The DUT
// firmware's `ClientModeRunner` does not auto-subscribe by design — its
// only client-side action is FindService emission — so the absence verdict
// holds end-to-end.
//
// Stimulus chain:
//   1. emitFindServiceBoot — wakes vsomeip server-side.
//   2. emitMethodRequestAfter(clientServiceActivate) — DUT enters Client
//      Mode and starts FindService emit thread.
//   3. emitOfferServiceMulticast(SERVICE-ID-2, ttl=3) — tester pretends to
//      offer SERVICE-ID-2 the DUT is searching for. Wire-correct stimulus
//      so the test can be tightened in the future without rewriting traits.
//
// Reference: PRS_SOMEIPSD_00386.
template <>
struct TestCaseTraits<cases::SomeipEts098SM> : SomeIpAnyBase<cases::SomeipEts098SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_098";
    static constexpr std::string_view kDescription =
        "Client Mode without explicit Subscribe trigger -- DUT must not auto-subscribe";

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
        ::tc8::stimulus::OfferServiceTarget offer{};
        offer.ttl        = 3;        // OfferService (vs StopOfferService when ttl=0).
        offer.session_id = 0x0001;
        ::tc8::stimulus::emitOfferServiceMulticast(iface, offer,
                                                   std::chrono::milliseconds(500));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts098SM, someip_ets_098)
