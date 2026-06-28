#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_rpc_05_sm.h"

namespace tc8::sce::cases {

using Rpc05SM = ::SCE::Generated::someipsrv_rpc_05::someipsrv_rpc_05;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.7.5 — Fire&Forget Requests must not return an Error.
// Tester sends SOMEIP_MSG_TYPE_REQUEST_NO_RETURN (0x01) to UNKNOWN-
// METHOD-ID-SI-1 (sentinel 0xFFFE); the DUT receives a F&F invocation
// of a non-existent method and per spec must NOT send Error.
template <>
struct TestCaseTraits<cases::Rpc05SM> : SomeIpAnyBase<cases::Rpc05SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_RPC_05";
    static constexpr std::string_view kDescription =
        "Fire&Forget to unknown method must not return an Error";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::SomeIpRpcMessage target{};
        target.message_type = ::tc8::someip::MessageType::REQUEST_NO_RETURN;     // REQUEST_NO_RETURN
        target.method_id = ::tc8::sd_test_unknown::kMethodId;
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Rpc05SM, someipsrv_rpc_05)
