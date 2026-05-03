#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_077_sm.h"

namespace tc8::sce::cases {

using SomeipEts077SM = ::SCE::Generated::someip_ets_077::someip_ets_077;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_077 — Wrong_Service_ID.
// Tester sends Method Request with service_id 0x9999 (unknown).
// vsomeip's routing manager silent-drops at the routing layer;
// ETS_001-style lenient 4-path verdict — phase 2 cond watches
// any non-SD service_id with method_id 0x0008. Method Request
// destination port stays 30502 (tc8-dut's UDP unicast endpoint
// for the genuine service_id 0xF4E7); vsomeip parses the SOME/IP
// header and rejects on service_id mismatch.
template <>
struct TestCaseTraits<cases::SomeipEts077SM> : SomeIpAnyBase<cases::SomeipEts077SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_077";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "Wrong Service ID (0x9999 unknown) — DUT must reject or ignore";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.service_id = 0x9999;  // Unknown service
        target.method_id = 0x0008;
        target.payload = {0x42};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                                return "pass";
            case State::Fail_phase1_no_offer:                                return "fail:no_offer_service_within_listen_window";
            case State::Fail_phase2_dut_accepted_wrong_service_id:           return "fail:dut_returned_ok_response_for_wrong_service_id";
            default:                                                         return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts077SM, someip_ets_077)
