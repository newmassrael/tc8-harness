#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_rpc_17_sm.h"

namespace tc8::sce::cases {

using Rpc17SM = ::SCE::Generated::someipsrv_rpc_17::someipsrv_rpc_17;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.7.17 — Multiple instances use multiple TCP connections.
// Stimulus chain: FindService → wait for two-entry OfferService → TCP
// Method Request to instance 1 reliable port (30501) → wait for
// Response → TCP Method Request to instance 2 reliable port (30503).
// Method ID is echoUINT8RELIABLE (0x0A) per ets.fdepl SomeIpReliable=true.
template <>
struct TestCaseTraits<cases::Rpc17SM> : SomeIpAnyBase<cases::Rpc17SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_RPC_17";
    static constexpr std::string_view kDescription =
        "Multi-instance Method Responses sourced from distinct per-instance TCP ports";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{});

        ::tc8::stimulus::MethodRequestTarget req{};
        req.service_id = 0xF4E7;
        req.method_id = 0x000A;  // METHOD-ID-1-SI-1 (echoUINT8RELIABLE — TCP)
        req.payload = {0x42};

        // instance 0x0001 reliable = the configured services[0] TCP endpoint.
        ::tc8::stimulus::emitMethodRequestTcpAfter(iface, req,
                                                   ::tc8::stimulus::MethodRequestTiming{},
                                                   ::tc8::sce::someipTcpMethodDest(cfg));

        ::tc8::stimulus::MethodRequestTarget req2 = req;
        req2.session_id = 0x0002;
        ::tc8::stimulus::MethodRequestTiming late{};
        late.pre_emit_wait = std::chrono::milliseconds{500};
        // instance 0x0002 reliable — not the base services[0] endpoint, so
        // name the port explicitly.
        ::tc8::stimulus::emitMethodRequestTcpAfter(iface, req2, late,
                                                   ::tc8::sce::someipTcpMethodDest(cfg, 30503));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Rpc17SM, someipsrv_rpc_17)
