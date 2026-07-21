#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/someip_method_dest.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"
#include "stimulus/subscribe_tcp_session.h"

#include "someip_ets_120_sm.h"

namespace tc8::sce::cases {

using SomeipEts120SM = ::SCE::Generated::someip_ets_120::someip_ets_120;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_120 — Subscribe carrying an IPv4 Endpoint
// option whose IP/port differs from the tester's actual UDP source. Per
// PRS_SOMEIPSD_00386 / 00387 / 00391 the DUT shall Ack the Subscribe and
// route initial fields to the option's IP/port.
//
// Wire shape: tester source = 172.16.0.3:30490 (canonical SD source).
// Endpoint option advertises 172.16.0.4:12345 (different IP/port). DUT
// must process the Subscribe and emit an Ack to the actual SD source
// (no observable difference vs canonical Subscribe at the Ack layer);
// initial-fields routing to the alternate destination is a DUT-internal
// decision not directly observable by the tester (the alternate IP is
// not bound on the tester veth, so the Notification packet, if emitted,
// goes to the wire and is dropped by the kernel — pcap may or may not
// see it depending on the routing path). Verdict pins the observable
// half: phase 2 = Ack-on-altered-Subscribe.
template <>
struct TestCaseTraits<cases::SomeipEts120SM> : SomeIpAnyBase<cases::SomeipEts120SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_120";
    static constexpr std::string_view kDescription =
        "Subscribe with Endpoint Option != tester source — DUT Acks";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IBackgroundServiceOwner& owner) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        // eg 0x0002 is mixed-reliability: hold a TCP connection so vsomeip Acks
        // the dual-option Subscribe. Option 0 (UDP) advertises a DISTINCT
        // endpoint (172.16.0.4:12345, not the SD source) — the point of the case
        // — while option 1 is this session's held TCP endpoint.
        auto session = std::make_unique<::tc8::stimulus::SubscribeEventgroupTcpSession>(
            iface, ::tc8::sce::someipTcpMethodDest(cfg));
        ::tc8::stimulus::SubscribeEventgroupParams params{};
        params.target.eventgroup_id = 0x0002;
        params.session_id = 0x0001;
        // Endpoint Option advertises 172.16.0.4 (tester's subnet but un-bound
        // IP) on port 12345. Caller-set ipv4_be != 0 keeps subscribeDualParams
        // from auto-filling the UDP option, so port + l4proto are set explicitly.
        params.tester_endpoint.ipv4_be = 0x040010ACU;  // 172.16.0.4
        params.tester_endpoint.port = 12345U;
        params.tester_endpoint.l4proto = 0x11;  // UDP
        ::tc8::stimulus::SubscribeDestination sd_dest{};
        sd_dest.ipv4_be = cfg.someip.dut_iface_ip;
        session->subscribeDualParams(params, sd_dest);
        owner.adoptService(std::move(session));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts120SM, someip_ets_120)
