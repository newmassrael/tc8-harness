#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_035_sm.h"

namespace tc8::sce::cases {

using SomeipEts035SM = ::SCE::Generated::someip_ets_035::someip_ets_035;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_035 — echoUINT8RELIABLE over TCP.
// Same wire shape as ETS_027 / BASIC_01 echo, but transport is TCP
// (vsomeip "reliable" endpoint at port 30501 per ets.fdepl
// SomeIpReliableUnicastPort). Pass requires the Response method_id
// 0x000A, payload echo of 0x42, AND src_port == expected.tcp_port —
// the latter pins the reply to vsomeip's TCP server endpoint, the
// reliable-transport axis the spec body asserts.
template <>
struct TestCaseTraits<cases::SomeipEts035SM> : SomeIpAnyBase<cases::SomeipEts035SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_035";
    static constexpr std::string_view kDescription =
        "echoUINT8RELIABLE — DUT echoes UInt8 over the SOME/IP TCP reliable transport";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{});

        ::tc8::stimulus::MethodRequestTarget req{};
        req.method_id = 0x000A;  // METHOD-ID echoUINT8RELIABLE (TCP)
        req.payload = {0x42};

        // tc8-dut SERVICE-ID-1 instance 0x0001 reliable endpoint — the
        // configured services[0] TCP port (vsomeip.json reliable.port).
        ::tc8::stimulus::emitMethodRequestTcpAfter(iface, req,
                                                    ::tc8::stimulus::MethodRequestTiming{},
                                                    ::tc8::sce::someipTcpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts035SM, someip_ets_035)
