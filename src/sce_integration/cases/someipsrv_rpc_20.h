#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_rpc_20_sm.h"

namespace tc8::sce::cases {

using Rpc20SM = ::SCE::Generated::someipsrv_rpc_20::someipsrv_rpc_20;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.7.20 — Error frame copies SOME/IP Interface Version
// from the request. Tester sends a Method Request to UNKNOWN-METHOD-
// ID-SI-1 with interface_version == SERVICE-ID-1-INTF-VER-MAJ
// (default 0x01, mirroring expected.major_version configured via
// --expect); pass requires the Error frame's interface_version to
// match.
template <>
struct TestCaseTraits<cases::Rpc20SM> : SomeIpAnyBase<cases::Rpc20SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_RPC_20";
    static constexpr std::string_view kDescription =
        "Error message echoes Request Interface Version";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::SomeIpRpcMessage target{};
        target.method_id = ::tc8::sd_test_unknown::kMethodId;
        // interface_version default 0x01 already matches expected.major_
        // version configured by smoke-test.sh (--expect major_version=1).
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Rpc20SM, someipsrv_rpc_20)
