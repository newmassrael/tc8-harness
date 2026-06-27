#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_onwire_12_sm.h"

namespace tc8::sce::cases {

using Onwire12SM = ::SCE::Generated::someipsrv_onwire_12::someipsrv_onwire_12;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.6.12 — UNKNOWN-METHOD-ID Request elicits
// SOMEIP_MSG_TYPE_ERROR with return_code == E_UNKNOWN_METHOD (0x03).
// Tester sends a Request to SERVICE-ID-1 with method_id ==
// kMethodId sentinel (0xFFFE); pass requires the matched Error
// carries message_type=0x81 AND return_code=0x03 AND echoes the
// unknown method_id.
template <>
struct TestCaseTraits<cases::Onwire12SM> : SomeIpAnyBase<cases::Onwire12SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_ONWIRE_12";
    static constexpr std::string_view kDescription =
        "Error message for UNKNOWN-METHOD-ID Request carries return_code E_UNKNOWN_METHOD";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = ::tc8::sd_test_unknown::kMethodId;
        target.payload = {0x42};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Onwire12SM, someipsrv_onwire_12)
