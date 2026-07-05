#pragma once

#include <chrono>
#include <memory>
#include <string_view>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/someip_method_dest.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"
#include "stimulus/subscribe_tcp_session.h"

#include "someip_ets_088_sm.h"

namespace tc8::sce::cases {

using SomeipEts088SM = ::SCE::Generated::someip_ets_088::someip_ets_088;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_088 — SD_Answer_multiple_subscribes_together.
// Tester sends a single SD message carrying 3 Type 2 SubscribeEventgroup
// entries (eg 0x02, 0x05, 0x06) via emitMultiSubscribeEventgroup. Per
// PRS_SOMEIPSD_00263 the DUT must respond to each entry — Ack with
// ttl > 0 for the configured eventgroups (0x02, 0x05) and Nack with
// ttl == 0 for 0x06 (not in tc8-dut's vsomeip.json). Phase 2c
// accepts any response on eg 0x06 (Ack OR Nack) per the lenient
// spec invariant "DUT responds to each entry".
template <>
struct TestCaseTraits<cases::SomeipEts088SM> : SomeIpAnyBase<cases::SomeipEts088SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_088";
    static constexpr std::string_view kDescription =
        "Multi-entry Subscribe (eg 0x02 + 0x05 + 0x06) — DUT acks/nacks each entry";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IBackgroundServiceOwner& owner) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::vector<::tc8::stimulus::SubscribeEventgroupTarget> entries;
        entries.reserve(3);

        ::tc8::stimulus::SubscribeEventgroupTarget e1{};
        e1.eventgroup_id = 0x0002;
        entries.push_back(e1);

        ::tc8::stimulus::SubscribeEventgroupTarget e2{};
        e2.eventgroup_id = 0x0005;
        entries.push_back(e2);

        ::tc8::stimulus::SubscribeEventgroupTarget e3{};
        e3.eventgroup_id = 0x0006;
        entries.push_back(e3);

        // eg 0x0002 in the bundle is mixed-reliability: hold a TCP connection so
        // vsomeip Acks that entry. The bundle advertises a UDP + TCP option pair
        // and every entry references both.
        auto session = std::make_unique<::tc8::stimulus::SubscribeEventgroupTcpSession>(
            iface, ::tc8::sce::someipTcpMethodDest(cfg));
        ::tc8::stimulus::SubscribeDestination sd_dest{};
        sd_dest.ipv4_be = cfg.someip.dut_iface_ip;
        session->subscribeMultiDual(entries, sd_dest);
        owner.adoptService(std::move(session));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts088SM, someip_ets_088)
