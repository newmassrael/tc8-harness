#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_003_sm.h"

namespace tc8::sce::cases {

using SomeipEts003SM = ::SCE::Generated::someip_ets_003::someip_ets_003;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_003 — DUT must strip the response payload
// (empty body) when the Request's Array Length is shorter than the
// actual array. Tester sends an echoUINT8 Request with no payload at
// all — `target.payload = {}`, length self-computed = 0x08. CommonAPI's
// UInt8 deserializer hits EOF on the input stream; the spec mandates
// the DUT respond with a Method Response carrying a stripped (empty)
// payload, but an Error Response (MALFORMED_MESSAGE) is also accepted
// since it equally prevents propagation of malformed input.
template <>
struct TestCaseTraits<cases::SomeipEts003SM> : SomeIpAnyBase<cases::SomeipEts003SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_003";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "Empty echoUINT8 Request payload — DUT must reply with stripped payload";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0008;
        // Empty payload — Length self-computes to 0x08 (header-only,
        // no UInt8 body). CommonAPI deserializer hits EOF.
        target.payload = {};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                              return "pass";
            case State::Fail_phase1_no_offer:              return "fail:no_offer_service_within_listen_window";
            case State::Fail_phase2_payload_not_stripped:  return "fail:dut_response_payload_was_not_stripped_for_short_array_length";
            case State::Fail_phase2_no_response:           return "fail:no_method_response_within_listen_window";
            default:                                       return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts003SM, someip_ets_003)
