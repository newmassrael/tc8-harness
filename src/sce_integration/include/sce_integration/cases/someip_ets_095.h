#pragma once

#include <memory>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/someip_method_dest.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"
#include "stimulus/subscribe_tcp_session.h"

#include "someip_ets_095_sm.h"

namespace tc8::sce::cases {

using SomeipEts095SM = ::SCE::Generated::someip_ets_095::someip_ets_095;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_095 — SD_Check_subscribe_eventgroup_ttl_expired.
// Tester subscribes to eg 0x02 with ttl = 3 seconds, observes the
// Ack, then waits past ttl expiry. tc8-dut's dut_main fires
// TestEventUINT8 every 250 ms to currently-subscribed clients via
// CommonAPI; once vsomeip drops the subscription on ttl expiry the
// cyclic firing stops reaching the tester. Per PRS_SOMEIPSD_00386
// the absence of further Notifications after expiry is the spec
// invariant. Phase 3 uses a 4 s wait then a 2 s absence-check
// window; CASE_TIMEOUT_SEC envelope is 22 s for both positive and
// negative tables to cover stimulus chain + SCXML phases.
template <>
struct TestCaseTraits<cases::SomeipEts095SM> : SomeIpAnyBase<cases::SomeipEts095SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_095";
    static constexpr std::string_view kDescription =
        "Subscribe ttl=3 then wait past expiry — DUT must stop emitting events";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IBackgroundServiceOwner& owner) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        // eg 0x0002 is mixed-reliability: hold a TCP connection so vsomeip Acks
        // the dual-option Subscribe. ttl=3 is the point of the case — the
        // subscription (both transports) expires and the DUT stops emitting.
        auto session = std::make_unique<::tc8::stimulus::SubscribeEventgroupTcpSession>(
            iface, ::tc8::sce::someipTcpMethodDest(cfg));
        ::tc8::stimulus::SubscribeEventgroupTarget subscribe{};
        subscribe.eventgroup_id = 0x0002;
        subscribe.ttl = 3;
        ::tc8::stimulus::SubscribeDestination sd_dest{};
        sd_dest.ipv4_be = cfg.someip.dut_iface_ip;
        session->subscribeDual(subscribe, sd_dest);
        owner.adoptService(std::move(session));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts095SM, someip_ets_095)
