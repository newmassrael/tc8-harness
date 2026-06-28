#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_rpc_10_sm.h"

namespace tc8::sce::cases {

using Rpc10SM = ::SCE::Generated::someipsrv_rpc_10::someipsrv_rpc_10;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.7.10 — Implementation must not return an Error for
// fire&forget methods invoked with the wrong message_type. Tester
// sends a regular Request (msg_type = 0x00) to METHOD-ID-FIRE-FORGET-
// SI-1 (resetInterface = 0x01, declared `fireAndForget` in
// dut/ets/ets.fidl); the DUT must NOT reply with SOMEIP_MSG_TYPE_ERROR
// even though the message_type is the wrong shape for the targeted
// method.
template <>
struct TestCaseTraits<cases::Rpc10SM> : SomeIpAnyBase<cases::Rpc10SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_RPC_10";
    static constexpr std::string_view kDescription =
        "Wrong message_type to fire&forget method must not return an Error";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::SomeIpRpcMessage target{};
        // METHOD-ID-FIRE-FORGET-SI-1: resetInterface (0x01) — declared
        // fireAndForget in ets.fidl. Tester drives it with msg_type =
        // 0x00 (Request) — the wrong shape per the spec note.
        target.method_id = 0x0001;
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Rpc10SM, someipsrv_rpc_10)
