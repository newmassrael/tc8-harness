#pragma once

#include <chrono>
#include <string_view>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_068_sm.h"

namespace tc8::sce::cases {

using SomeipEts068SM = ::SCE::Generated::someip_ets_068::someip_ets_068;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_068 — Unaligned_SOMEIP_Messages_overTCP.
// Tester packs 3 echoUINT8RELIABLE Method Requests (METHOD-ID 0x000A,
// 1-byte UInt8 payload each) into a single TCP send() via
// emitBundledMethodRequestsTcp. Per-message wire size = 17 bytes
// (16 header + 1 payload), so the bundle lands at TCP-stream offsets
// 0/17/34 — none 4-byte-aligned. Spec body names "method
// echoUINT8array" but tc8-dut only declares array methods on UDP
// (SomeIpReliable=false in ets.fdepl); the test invariant is the
// 3-message TCP-bundle / unaligned axis, so the per-method type is
// substituted with the only available reliable echo method.
// Per PRS_SOMEIP_00142 / PRS_SOMEIP_00569 the DUT must walk the
// stream by per-message Length header and respond to every Request
// on the same TCP connection.
template <>
struct TestCaseTraits<cases::SomeipEts068SM> : SomeIpAnyBase<cases::SomeipEts068SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_068";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "Unaligned 3-message SOME/IP bundle over TCP — DUT echoes each Request";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::vector<::tc8::stimulus::MethodRequestTarget> bundle;
        bundle.reserve(3);

        ::tc8::stimulus::MethodRequestTarget m1{};
        m1.method_id  = 0x000A;
        m1.session_id = 0x0001;
        m1.payload    = {0x42};
        bundle.push_back(m1);

        ::tc8::stimulus::MethodRequestTarget m2{};
        m2.method_id  = 0x000A;
        m2.session_id = 0x0002;
        m2.payload    = {0x43};
        bundle.push_back(m2);

        ::tc8::stimulus::MethodRequestTarget m3{};
        m3.method_id  = 0x000A;
        m3.session_id = 0x0003;
        m3.payload    = {0x44};
        bundle.push_back(m3);

        // tc8-dut SERVICE-ID-1 instance 0x0001 reliable endpoint
        // (vsomeip.json reliable.port = 30501).
        ::tc8::stimulus::MethodRequestDestination dest{};
        dest.port = 30501;
        ::tc8::stimulus::emitBundledMethodRequestsTcp(iface, bundle,
                                                     std::chrono::milliseconds(500),
                                                     dest,
                                                     std::chrono::milliseconds(800));
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                              return "pass";
            case State::Fail_phase1_no_offer:              return "fail:no_offer_service_within_listen_window";
            case State::Fail_phase2_response_missing:      return "fail:dut_did_not_respond_to_every_message_in_tcp_bundle";
            default:                                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts068SM, someip_ets_068)
