#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_rpc_08_sm.h"

namespace tc8::sce::cases {

using Rpc08SM = ::SCE::Generated::someipsrv_rpc_08::someipsrv_rpc_08;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.7.8 — Implementations shall not answer with errors
// to SOME/IP messages that already carry an error (return_code 0x01..
// 0x1F). Tester sends two Method Requests to METHOD-ID-1-SI-1
// (echoUINT8 = 0x08): the first with return_code = 0x01, the second
// (after the builder's retry interval) with return_code = 0x1F. DUT
// must NOT respond with SOMEIP_MSG_TYPE_ERROR (0x81) for either
// Request. Successful echo Responses are allowed and silently
// ignored — the SCXML only fails on Error frames.
template <>
struct TestCaseTraits<cases::Rpc08SM> : SomeIpAnyBase<cases::Rpc08SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_RPC_08";
    static constexpr std::string_view kSpecSection = "5.1.5.7.8";
    static constexpr std::string_view kDescription =
        "DUT must not return Error for Requests already carrying an error code";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        // First Request — return_code = 0x01 (E_NOT_OK). Payload is a
        // valid 1-byte UInt8 so the dispatcher does not emit
        // E_MALFORMED_MESSAGE on its own; the spec is testing the
        // return_code path, not the malformed-payload path.
        ::tc8::stimulus::MethodRequestTarget t1{};
        t1.return_code = 0x01;
        t1.session_id = 0x0001;
        t1.payload = {0x42};
        ::tc8::stimulus::emitMethodRequestAfter(iface, t1);
        // Second Request — return_code = 0x1F (top end of the
        // already-error range). Distinct session_id keeps the two
        // streams independent on the wire.
        ::tc8::stimulus::MethodRequestTarget t2{};
        t2.return_code = 0x1F;
        t2.session_id = 0x0002;
        t2.payload = {0x42};
        ::tc8::stimulus::MethodRequestTiming timing{};
        timing.pre_emit_wait = std::chrono::milliseconds{200};
        ::tc8::stimulus::emitMethodRequestAfter(iface, t2, timing);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Rpc08SM, someipsrv_rpc_08)
