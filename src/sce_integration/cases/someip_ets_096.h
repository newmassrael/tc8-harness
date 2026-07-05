#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_096_sm.h"

namespace tc8::sce::cases {

using SomeipEts096SM = ::SCE::Generated::someip_ets_096::someip_ets_096;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_096 — SD_Check_TCP_Connection_before_SubscribeEventgroup.
// Tester emits a SubscribeEventgroup on eg 0x0002 whose IPv4 Endpoint
// Option declares TCP (l4proto 0x06) without pre-establishing the
// referenced TCP connection. Per PRS_SOMEIPSD_00362 the DUT must reject
// the request with a SubscribeEventgroupNack (Type 0x07 entry, ttl == 0).
template <>
struct TestCaseTraits<cases::SomeipEts096SM> : SomeIpAnyBase<cases::SomeipEts096SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_096";
    static constexpr std::string_view kDescription =
        "Subscribe with TCP Endpoint option and no live TCP connection — "
        "DUT must respond with SubscribeEventgroupNack";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        // eg 0x0002 is mixed-reliability. Advertise a VALID UDP + TCP option pair
        // but do NOT open the TCP connection: the reliability check passes, so the
        // DUT reaches the connection check and Nacks for the MISSING TCP connection
        // — the case's intent — rather than an option-set mismatch. (No held
        // SubscribeEventgroupTcpSession: the absent connection is the point.)
        ::tc8::stimulus::SubscribeEventgroupParams params{};
        params.target.eventgroup_id = 0x0002;
        ::tc8::stimulus::setDualEndpointSubscribe(
            params, ::tc8::stimulus::Ipv4Endpoint{cfg.ipv4.tester_ip, 30501, 0x06});
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts096SM, someip_ets_096)
