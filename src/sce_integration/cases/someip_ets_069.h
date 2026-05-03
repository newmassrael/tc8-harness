#pragma once

#include <chrono>
#include <string_view>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_069_sm.h"

namespace tc8::sce::cases {

using SomeipEts069SM = ::SCE::Generated::someip_ets_069::someip_ets_069;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_069 — Unaligned_SOMEIP_Messages_overUDP.
// Tester packs 3 echoUINT8Array Method Requests into a single UDP
// datagram via emitBundledMethodRequestsUdp. Message 1 carries a
// 1-byte UInt8Array (5-byte payload) so its on-wire size is 21 bytes
// — leaves messages 2 and 3 starting at offsets 21 and 45, neither
// 4-byte-aligned within the bundle. Per PRS_SOMEIP_00142 /
// PRS_SOMEIP_00569 the DUT must walk the bundle by per-message
// Length header and respond to every Request. Bundle wire bytes:
// [hdr1 (16 B) | 00 00 00 01 42 | hdr2 (16 B) | 00 00 00 04 10 11 12 13
//  | hdr3 (16 B) | 00 00 00 04 20 21 22 23] = 69 B total.
template <>
struct TestCaseTraits<cases::SomeipEts069SM> : SomeIpAnyBase<cases::SomeipEts069SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_069";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "Unaligned 3-message SOME/IP bundle over UDP — DUT echoes each Request";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::vector<::tc8::stimulus::MethodRequestTarget> bundle;
        bundle.reserve(3);

        ::tc8::stimulus::MethodRequestTarget m1{};
        m1.method_id  = 0x0009;
        m1.session_id = 0x0001;
        // 32-bit BE array length = 1, single-byte element 0x42 → 5-byte
        // SOME/IP payload, 21-byte on-wire size (NOT 4-byte aligned).
        m1.payload    = {0x00, 0x00, 0x00, 0x01, 0x42};
        bundle.push_back(m1);

        ::tc8::stimulus::MethodRequestTarget m2{};
        m2.method_id  = 0x0009;
        m2.session_id = 0x0002;
        m2.payload    = {0x00, 0x00, 0x00, 0x04, 0x10, 0x11, 0x12, 0x13};
        bundle.push_back(m2);

        ::tc8::stimulus::MethodRequestTarget m3{};
        m3.method_id  = 0x0009;
        m3.session_id = 0x0003;
        m3.payload    = {0x00, 0x00, 0x00, 0x04, 0x20, 0x21, 0x22, 0x23};
        bundle.push_back(m3);

        ::tc8::stimulus::emitBundledMethodRequestsUdp(iface, bundle,
                                                     std::chrono::milliseconds(500));
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                              return "pass";
            case State::Fail_phase1_no_offer:              return "fail:no_offer_service_within_listen_window";
            case State::Fail_phase2_response_missing:      return "fail:dut_did_not_respond_to_every_message_in_bundle";
            default:                                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts069SM, someip_ets_069)
