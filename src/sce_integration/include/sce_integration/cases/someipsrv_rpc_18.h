#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_rpc_18_sm.h"

namespace tc8::sce::cases {

using Rpc18SM = ::SCE::Generated::someipsrv_rpc_18::someipsrv_rpc_18;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.7.18 — Error frame copies SOME/IP Message ID
// (Service ID + Method ID) from the request. Tester sends a Method
// Request to UNKNOWN-METHOD-ID-SI-1 (sentinel kMethodId = 0xFFFE);
// pass requires the resulting Error frame's service_id ==
// expected.service_id AND method_id == kMethodId.
template <>
struct TestCaseTraits<cases::Rpc18SM> : SomeIpAnyBase<cases::Rpc18SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_RPC_18";
    static constexpr std::string_view kDescription =
        "Error message echoes Request Message ID (Service ID + Method ID)";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::SomeIpRpcMessage target{};
        target.method_id = ::tc8::sd_test_unknown::kMethodId;
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Rpc18SM, someipsrv_rpc_18)
