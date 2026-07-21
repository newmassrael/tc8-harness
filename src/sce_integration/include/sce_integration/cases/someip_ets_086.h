#pragma once

#include <memory>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/someip_method_dest.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"
#include "stimulus/subscribe_tcp_session.h"

#include "someip_ets_086_sm.h"

namespace tc8::sce::cases {

using SomeipEts086SM = ::SCE::Generated::someip_ets_086::someip_ets_086;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_086 — Eventgroup_EventsAndFieldsAll_2_TCP.
// Tester subscribes to eventgroup 0x02 on SERVICE-ID-1; DUT must Ack
// the Subscribe and emit at least one Notification with MSB-set
// method-ID. Stimulus mirrors §5.1.5.5 BASIC_03 verbatim — both
// cases land on the same Subscribe-and-listen surface, eventgroup_id
// is the differentiator. The spec body lists method-IDs 0x8005..0x8008
// for eg 0x02; tc8-dut's vsomeip.json maps only TestEventUINT8 (0x8001)
// to this eventgroup, so the observable Notification surface is the
// MSB-set bit pattern alone. The "TCP" axis in the case name is not
// separately observable on this DUT (event 0x8001 is is_reliable=false
// in vsomeip.json); the lenient interpretation matches BASIC_03's
// approach.
template <>
struct TestCaseTraits<cases::SomeipEts086SM> : SomeIpAnyBase<cases::SomeipEts086SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_086";
    static constexpr std::string_view kDescription =
        "Subscribe to eventgroup 0x02 — DUT Ack + initial event observation";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IBackgroundServiceOwner& owner) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        // eg 0x0002 is mixed-reliability (carries reliable 0x8003) per the
        // reference: vsomeip Acks the Subscribe only if it advertises a UDP +
        // TCP endpoint pair AND holds an established TCP connection. The events
        // observed here are UNRELIABLE (over UDP); the TCP connection is held
        // solely to satisfy the mixed-eventgroup Ack.
        auto session = std::make_unique<::tc8::stimulus::SubscribeEventgroupTcpSession>(
            iface, ::tc8::sce::someipTcpMethodDest(cfg));
        ::tc8::stimulus::SubscribeEventgroupTarget subscribe{};
        subscribe.eventgroup_id = 0x0002;
        subscribe.ttl = ::tc8::stimulus::kSubscribeOutlastTtl;
        ::tc8::stimulus::SubscribeDestination sd_dest{};
        sd_dest.ipv4_be = cfg.someip.dut_iface_ip;
        session->subscribeDual(subscribe, sd_dest);
        owner.adoptService(std::move(session));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts086SM, someip_ets_086)
