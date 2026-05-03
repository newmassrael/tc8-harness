#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_onwire_06_sm.h"

namespace tc8::sce::cases {

using Onwire06SM = ::SCE::Generated::someipsrv_onwire_06::someipsrv_onwire_06;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.6.6 — Interface Version 8-bit field carries the
// Major Version of the Service Interface. Tester invokes echoUINT8;
// pass requires the matched Response carries interface_version ==
// expected.major_version (configured via --expect major_version=N).
template <>
struct TestCaseTraits<cases::Onwire06SM> : SomeIpAnyBase<cases::Onwire06SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_ONWIRE_06";
    static constexpr std::string_view kSpecSection = "5.1.5.6.6";
    static constexpr std::string_view kDescription =
        "Method Response carries Interface Version equal to Service Interface Major Version";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.payload = {0x42};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }

    static std::string_view verdictFor(State s) {
        switch (s) {
            case State::Pass:                                        return "pass";
            case State::Fail_phase1_no_offer:                        return "fail:no_offer_service_within_listen_window";
            case State::Fail_phase2_interface_version_mismatch:      return "fail:response_interface_version_not_configured_major";
            case State::Fail_phase2_no_response:                     return "fail:no_response_within_listen_window";
            default:                                                 return "running";
        }
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Onwire06SM, someipsrv_onwire_06)
