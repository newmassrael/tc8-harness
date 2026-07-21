#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_rpc_14_sm.h"

namespace tc8::sce::cases {

using Rpc14SM = ::SCE::Generated::someipsrv_rpc_14::someipsrv_rpc_14;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.7.14 — Different instances of the same service use
// different ports. Stimulus chain: FindService → wait for two-entry
// OfferService → Method Request to instance 1 UDP port (30502) → wait
// for Response → Method Request to instance 2 UDP port (30504).
template <>
struct TestCaseTraits<cases::Rpc14SM> : SomeIpAnyBase<cases::Rpc14SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_RPC_14";
    static constexpr std::string_view kDescription =
        "Multi-instance Method Responses sourced from distinct per-instance UDP ports";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{});

        ::tc8::stimulus::SomeIpRpcMessage req{};
        req.service_id = 0xF4E7;
        req.method_id = 0x0008;  // METHOD-ID-1-SI-1 (echoUINT8 — UDP)
        req.payload = {0x42};

        // instance 0x0001 unreliable = the configured services[0] endpoint.
        ::tc8::stimulus::emitMethodRequestAfter(iface, req, {},
                                                ::tc8::sce::someipUdpMethodDest(cfg));

        ::tc8::stimulus::SomeIpRpcMessage req2 = req;
        req2.session_id = 0x0002;
        ::tc8::stimulus::MethodRequestTiming late{};
        late.pre_emit_wait = std::chrono::milliseconds{800};
        // instance 0x0002 unreliable (vsomeip-multi-instance.json) — not the
        // base services[0] endpoint, so name the port explicitly.
        ::tc8::stimulus::emitMethodRequestAfter(iface, req2, late,
                                                ::tc8::sce::someipUdpMethodDest(cfg, ::tc8::sce::someip::kSi1Inst2UdpPort));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Rpc14SM, someipsrv_rpc_14)
