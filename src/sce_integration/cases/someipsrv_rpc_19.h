#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_rpc_19_sm.h"

namespace tc8::sce::cases {

using Rpc19SM = ::SCE::Generated::someipsrv_rpc_19::someipsrv_rpc_19;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.7.19 — Error frame copies SOME/IP Request ID
// (Client ID + Session ID) from the request. Tester sends a Method
// Request to UNKNOWN-METHOD-ID-SI-1 with non-default Request ID
// sentinels (client_id = 0xCAFE, session_id = 0x1234) so the echo
// assertion can't false-pass against the tester's normal default
// (0x0000 / 0x0001). Pass requires the resulting Error frame's
// client_id and session_id to match the sentinels exactly.
template <>
struct TestCaseTraits<cases::Rpc19SM> : SomeIpAnyBase<cases::Rpc19SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_RPC_19";
    static constexpr std::string_view kSpecSection = "5.1.5.7.19";
    static constexpr std::string_view kDescription =
        "Error message echoes Request ID (Client ID + Session ID)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = ::tc8::sd_test_unknown::kMethodId;
        target.client_id = 0xCAFE;
        target.session_id = 0x1234;
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                              return "pass";
            case State::Fail_phase1_no_offer:              return "fail:no_offer_service_within_listen_window";
            case State::Fail_phase2_request_id_mismatch:   return "fail:error_message_did_not_echo_request_id";
            case State::Fail_phase2_no_error:              return "fail:no_error_message_within_listen_window";
            default:                                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Rpc19SM, someipsrv_rpc_19)
