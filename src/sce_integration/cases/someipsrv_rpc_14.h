#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_rpc_14_sm.h"

namespace tc8::sce::cases {

using Rpc14SM = ::SCE::Generated::someipsrv_rpc_14::someipsrv_rpc_14;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.7.14 — Different instances of the same service use
// different ports. Stimulus chain: FindService → wait for two-entry
// OfferService → Method Request to instance 1 UDP port (30502) → wait
// for Response → Method Request to instance 2 UDP port (30504).
template <>
struct TestCaseTraits<cases::Rpc14SM> : SomeIpAnyBase<cases::Rpc14SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_RPC_14";
    static constexpr std::string_view kSpecSection = "5.1.5.7.14";
    static constexpr std::string_view kDescription =
        "Multi-instance Method Responses sourced from distinct per-instance UDP ports";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& /*cfg*/,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{});

        ::tc8::stimulus::MethodRequestTarget req{};
        req.service_id = 0xF4E7;
        req.method_id = 0x0008;  // METHOD-ID-1-SI-1 (echoUINT8 — UDP)
        req.payload = {0x42};

        ::tc8::stimulus::MethodRequestDestination dest1{};
        dest1.port = 30502;  // SERVICE-ID-1 instance 0x0001 unreliable
        ::tc8::stimulus::emitMethodRequestAfter(iface, req,
                                                ::tc8::stimulus::MethodRequestTiming{}, dest1);

        ::tc8::stimulus::MethodRequestTarget req2 = req;
        req2.session_id = 0x0002;
        ::tc8::stimulus::MethodRequestDestination dest2{};
        dest2.port = 30504;  // SERVICE-ID-1 instance 0x0002 unreliable (vsomeip-multi-instance.json)
        ::tc8::stimulus::MethodRequestTiming late{};
        late.pre_emit_wait = std::chrono::milliseconds{800};
        ::tc8::stimulus::emitMethodRequestAfter(iface, req2, late, dest2);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:
                return "pass";
            case State::Fail_phase1_no_offer:
                return "fail:no_two_entry_offer_with_distinct_udp_ports_within_listen_window";
            case State::Fail_phase2_no_response_from_instance_1:
                return "fail:no_response_from_instance_1_udp_port_30502";
            case State::Fail_phase3_no_response_from_instance_2:
                return "fail:no_response_from_instance_2_udp_port_30504";
            default:
                return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Rpc14SM, someipsrv_rpc_14)
