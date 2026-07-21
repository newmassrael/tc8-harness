#pragma once

#include <memory>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/someip_method_dest.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"
#include "stimulus/subscribe_tcp_session.h"

#include "someip_ets_147_sm.h"

namespace tc8::sce::cases {

using SomeipEts147SM = ::SCE::Generated::someip_ets_147::someip_ets_147;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_147 — SD_Send_triggerEventUINT8_Eventgroup_2.
// Tester subscribes to eg 0x02 then triggers triggerEventUINT8; DUT must
// Ack and emit TestEventUINT8 to the IP+port advertised in the Subscribe
// option. tc8-dut's cyclic 250 ms TestEventUINT8 fires regardless of an
// explicit trigger Method (which is not declared in ets.fdepl), so the
// Subscribe Ack + any MSB-set notification on eg 0x02 satisfies the wire
// invariant per the §5.1.5.5 BASIC_03 / §5.1.6 ETS_086 lenient pattern.
template <>
struct TestCaseTraits<cases::SomeipEts147SM> : SomeIpAnyBase<cases::SomeipEts147SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_147";
    static constexpr std::string_view kDescription =
        "Subscribe eg 0x02 + trigger triggerEventUINT8 — DUT Ack + MSB-set notification";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IBackgroundServiceOwner& owner) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        // eg 0x0002 is mixed-reliability (carries reliable 0x8003) per the
        // reference, so vsomeip NACKs a Subscribe that does not advertise a
        // UDP + TCP endpoint pair AND hold an established TCP connection. Only
        // the UNRELIABLE TestEventUINT8 (0x8001) is observed here (over UDP), so
        // the TCP connection is held solely to satisfy the mixed-eventgroup Ack.
        auto session = std::make_unique<::tc8::stimulus::SubscribeEventgroupTcpSession>(
            iface, ::tc8::sce::someipTcpMethodDest(cfg));
        ::tc8::stimulus::SubscribeEventgroupTarget subscribe{};
        subscribe.eventgroup_id = 0x0002;
        subscribe.ttl = ::tc8::stimulus::kSubscribeOutlastTtl;  // outlast capture window
        ::tc8::stimulus::SubscribeDestination sd_dest{};
        sd_dest.ipv4_be = cfg.someip.dut_iface_ip;  // DUT SD endpoint (:30490).
        session->subscribeDual(subscribe, sd_dest);
        owner.adoptService(std::move(session));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts147SM, someip_ets_147)
