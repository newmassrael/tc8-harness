#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_rpc_06_sm.h"

namespace tc8::sce::cases {

using Rpc06SM = ::SCE::Generated::someipsrv_rpc_06::someipsrv_rpc_06;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.7.6 — Std_returnType: the two most significant bits
// of the Return Code are reserved and shall be set to 0. Tester sends
// a Method Request to UNKNOWN-METHOD-ID-SI-1 to drive a SOMEIP_MSG_
// TYPE_ERROR; pass requires (return_code & 0xC0) == 0 on the Error.
template <>
struct TestCaseTraits<cases::Rpc06SM> : SomeIpAnyBase<cases::Rpc06SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_RPC_06";
    static constexpr std::string_view kDescription =
        "Error return_code top 2 bits reserved and set to 0";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = ::tc8::sd_test_unknown::kMethodId;
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Rpc06SM, someipsrv_rpc_06)
