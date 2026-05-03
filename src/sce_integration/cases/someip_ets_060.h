#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_060_sm.h"

namespace tc8::sce::cases {

using SomeipEts060SM = ::SCE::Generated::someip_ets_060::someip_ets_060;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_060 — SD_Discover_Port_and_IP.
// Tester emits a multicast FindService (224.244.224.245:30490) for
// SERVICE-ID-1; the DUT shall reply with a unicast OfferService
// listing all IPs and ports needed to fulfill any SOME/IP
// communication with the offered service. Per
// PRS_SOMEIPSD_00310/00357/00358/00361/00362 the OfferService
// MUST carry one IPv4 Endpoint Option per L4 protocol the service
// is reachable on; tc8-dut declares both `SomeIpUnreliableUnicastPort`
// (UDP 30502) and `SomeIpReliableUnicastPort` (TCP 30501) in
// ets.fdepl, so the OfferService must list two IPv4 Endpoint
// options (type 0x04) — one with l4 == UDP (0x11), one with l4 ==
// TCP (0x06). `emitFindServiceBoot` already binds source port 30490
// per the vsomeip "SD source port equals SD port" rule (see
// `reference_subscribe_sd_port`). Single-phase verdict — phase 1
// terminal IS the pass terminal because a compliant OfferService
// is the only payload we need to observe.
template <>
struct TestCaseTraits<cases::SomeipEts060SM> : SomeIpAnyBase<cases::SomeipEts060SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_060";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "SD multicast FindService — DUT unicast OfferService lists UDP+TCP IPv4 Endpoint Options";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                return "pass";
            case State::Fail_phase1_no_offer_with_endpoints: return "fail:no_offer_service_with_udp_and_tcp_endpoints_within_listen_window";
            default:                                         return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts060SM, someip_ets_060)
