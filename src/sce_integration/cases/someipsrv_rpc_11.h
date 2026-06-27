#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_rpc_11_sm.h"

namespace tc8::sce::cases {

using Rpc11SM = ::SCE::Generated::someipsrv_rpc_11::someipsrv_rpc_11;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.7.11 — Field setter is a request/response call. The
// request payload carries the value to set and the response payload
// carries the value that was set. Tester sends a Method Request to the
// fieldA setter (METHOD-ID-2-SI-1 = 0x42, declared in dut/ets/ets.
// fdepl — relocated from 0x41 because spec table p401-420 reserves
// 0x41 for echoBitfields) with payload [0x42]; pass requires a
// Response (msg_type 0x80) with return_code = E_OK and the first
// payload byte == 0x42.
template <>
struct TestCaseTraits<cases::Rpc11SM> : SomeIpAnyBase<cases::Rpc11SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_RPC_11";
    static constexpr std::string_view kDescription =
        "Field setter — Request payload sets value, Response payload echoes set value";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0042;
        target.payload = {0x42};
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Rpc11SM, someipsrv_rpc_11)
