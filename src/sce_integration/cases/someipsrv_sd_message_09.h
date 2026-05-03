#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_sd_message_09_sm.h"

namespace tc8::sce::cases {

using SdMessage09SM =
    ::SCE::Generated::someipsrv_sd_message_09::someipsrv_sd_message_09;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.3.9 SOMEIPSRV_SD_MESSAGE_09: The IP addresses and
// port numbers of the Endpoint Options shall also be used for
// transporting events and notification events. In the case of UDP this
// information is used for the source address and the source port of
// the events and notification events. (TR_SOMEIP_00360 / 00361.)
//
// Three-phase observation (mirrors BASIC_03 stimulus shape):
//   Phase 1: DUT emits OfferService for SERVICE-ID-1 with >= 1 IPv4
//            Endpoint Option. fillSomeIpCapturedFromFrame caches the
//            advertised UDP endpoint port into
//            `captured.cached_offer_endpoint_udp_port` so Phase 3 can
//            cross-reference without a SCXML datamodel.
//   Phase 2: DUT replies to the tester's SubscribeEventgroup with a
//            SubscribeEventgroupAck (entry type 0x07, ttl > 0).
//   Phase 3: DUT emits a Notification on the subscribed eventgroup;
//            the spec assertion is that the Notification's UDP source
//            port matches the OfferService's advertised endpoint port.
//
// SOMEIP_BASIC_03 already drives the FindService → OfferService →
// Subscribe → Ack → Notification chain on eventgroup 0x0002; this
// case reuses the same stimulus shape. The verdict differs: BASIC_03
// asserts the Notification's method_id MSB; SD_MESSAGE_09 asserts the
// Notification's UDP src_port matches the OfferService Endpoint
// Option port (TR_SOMEIP_00361's underlying transport invariant).
template <>
struct TestCaseTraits<cases::SdMessage09SM>
    : SomeIpAnyBase<cases::SdMessage09SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_SD_MESSAGE_09";
    static constexpr std::string_view kSpecSection = "5.1.5.3.9";
    static constexpr std::string_view kDescription =
        "Notification UDP src_port shall match OfferService "
        "Endpoint Option port (TR_SOMEIP_00360 / 00361)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        // Phase 1: drive OfferService via FindService boot.
        ::tc8::stimulus::emitFindServiceBoot(
            iface, ::tc8::stimulus::FindServiceTarget{},
            cfg.stimulus_timing);
        // Phase 2/3: subscribe to TestEventUINT8's eventgroup (0x0002,
        // declared in dut/ets/ets.fdepl + dut/dut_service/vsomeip.json).
        // vsomeip Acks once the events block is wired; the DUT's cyclic
        // fireTestEventUINT8Event call (dut_main 250 ms cadence) then
        // delivers Notifications from the configured UDP server endpoint
        // (vsomeip.json `unreliable: 30502`).
        ::tc8::stimulus::SubscribeEventgroupTarget subscribe{};
        subscribe.eventgroup_id = 0x0002;
        ::tc8::stimulus::emitSubscribeEventgroupBoot(
            iface, subscribe, cfg.stimulus_timing);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                  return "pass";
            case State::Fail_phase1_no_offer_with_endpoint:    return "fail:no_offer_service_with_ipv4_endpoint_within_listen_window";
            case State::Fail_phase2_subscribe_nacked:          return "fail:subscribe_eventgroup_nacked_ttl_zero";
            case State::Fail_phase2_no_subscribe_ack:          return "fail:no_subscribe_ack_within_listen_window";
            case State::Fail_phase3_no_notification:           return "fail:no_notification_within_listen_window";
            case State::Fail_phase3_src_port_mismatch:         return "fail:notification_src_port_does_not_match_offer_endpoint_port";
            default:                                           return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SdMessage09SM, someipsrv_sd_message_09)
