#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_rpc_09_sm.h"

namespace tc8::sce::cases {

using Rpc09SM = ::SCE::Generated::someipsrv_rpc_09::someipsrv_rpc_09;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.7.9 — Error message has no payload. Tester sends a
// Method Request to UNKNOWN-METHOD-ID-SI-1; pass requires the resulting
// SOMEIP_MSG_TYPE_ERROR frame to carry payload_len == 0 (header length
// field == 8, the bare 4-byte Request ID + 4-byte proto/iface/msg_type/
// return_code with no payload).
template <>
struct TestCaseTraits<cases::Rpc09SM> : SomeIpAnyBase<cases::Rpc09SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_RPC_09";
    static constexpr std::string_view kSpecSection = "5.1.5.7.9";
    static constexpr std::string_view kDescription =
        "Error message carries no payload (length field = 8)";

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

TC8_REGISTER_CASE(::tc8::sce::cases::Rpc09SM, someipsrv_rpc_09)
