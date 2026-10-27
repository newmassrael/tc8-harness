#pragma once

#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/reliable_method_request.h"
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
// Stimulus chain: FindService → one held TCP connection to each instance's
// reliable port (30501, 30503), each carrying one Method Request. The runner
// holds both connections for the whole run, so a Response the DUT sends at
// any point in the window travels a connection the tester has not closed.
// Method ID is echoUINT8RELIABLE (0x0A) per ets.fdepl SomeIpReliable=true.
template <>
struct TestCaseTraits<cases::Rpc17SM> : SomeIpAnyBase<cases::Rpc17SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_RPC_17";
    static constexpr std::string_view kDescription =
        "Multi-instance Method Responses sourced from distinct per-instance TCP ports";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         ::tc8::sce::StimulusContext& ctx) {
        ::tc8::stimulus::emitFindServiceBoot(ctx.iface, ::tc8::stimulus::FindServiceTarget{});
        // The OfferService cycle is under way when the boot returns; the gap is the
        // one emitMethodRequestAfter keeps before a Request.
        std::this_thread::sleep_for(::tc8::stimulus::MethodRequestTiming{}.pre_emit_wait);

        ::tc8::stimulus::SomeIpRpcMessage req{};
        req.service_id = 0xF4E7;
        req.method_id = 0x000A;  // METHOD-ID-1-SI-1 (echoUINT8RELIABLE — TCP)
        req.payload = {0x42};

        // instance 0x0001 reliable = the configured services[0] TCP endpoint.
        ::tc8::sce::sendOnHeldReliableConnection(ctx, ::tc8::sce::someipTcpMethodDest(cfg), {req});

        ::tc8::stimulus::SomeIpRpcMessage req2 = req;
        req2.session_id = 0x0002;
        // instance 0x0002 reliable — not the base services[0] endpoint, so
        // name the port explicitly.
        ::tc8::sce::sendOnHeldReliableConnection(
            ctx, ::tc8::sce::someipTcpMethodDest(cfg, ::tc8::sce::someip::kSi1Inst2TcpPort), {req2});
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Rpc17SM, someipsrv_rpc_17)
