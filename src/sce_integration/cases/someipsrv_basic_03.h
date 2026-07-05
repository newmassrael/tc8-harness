#pragma once

#include <memory>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/someip_method_dest.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"
#include "stimulus/subscribe_tcp_session.h"

#include "someipsrv_basic_03_sm.h"

namespace tc8::sce::cases {

using Basic03SM = ::SCE::Generated::someipsrv_basic_03::someipsrv_basic_03;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.5.3 — Method-IDs use highest bit = 0 for methods,
// highest bit = 1 for events / notifications. Three pass criteria:
//   1. DUT emits OfferService for SERVICE-ID-1 carrying >= 1 IPv4
//      Endpoint Option (FindService → OfferService cycle).
//   2. DUT replies to a SubscribeEventgroup with SubscribeEventgroupAck
//      (entry type 0x07, ttl > 0).
//   3. DUT emits a Notification whose method_id has the highest bit
//      (0x8000) set, on the eventgroup the tester subscribed to.
//
// Subscribe target is eventgroup 0x0002 — declared under
// dut/ets/ets.fdepl's TestEventUINT8 SomeIpEventGroups and exposed by
// dut/dut_service/vsomeip.json's events block. The per-case
// --expect eventgroup_id=0x0002 override (smoke-test.sh) keeps the
// SCXML eventgroup_id assertion consistent with the stimulus.
template <>
struct TestCaseTraits<cases::Basic03SM> : SomeIpAnyBase<cases::Basic03SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_BASIC_03";
    static constexpr std::string_view kDescription =
        "Method-ID highest bit = 1 for events / notifications — verified "
        "via Subscribe → Ack → Notification chain";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IBackgroundServiceOwner& owner) {
        // Phase 1: drive OfferService via FindService boot.
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        // Phase 2/3: subscribe to the eventgroup that owns
        // TestEventUINT8 (0x0002 per ets.fdepl). vsomeip Acks once the
        // events block is wired in vsomeip.json; the DUT's cyclic
        // fireTestEventUINT8Event call (dut_main) then delivers a
        // Notification to the subscribed tester endpoint.
        ::tc8::stimulus::SubscribeEventgroupTarget subscribe{};
        subscribe.eventgroup_id = 0x0002;
        // eg 0x0002 is mixed-reliability: hold a TCP connection so vsomeip Acks
        // the dual-endpoint Subscribe; the cyclic UNRELIABLE 0x8001 then arrives
        // over UDP. The TCP connection is held solely for the Ack.
        auto session = std::make_unique<::tc8::stimulus::SubscribeEventgroupTcpSession>(
            iface, ::tc8::sce::someipTcpMethodDest(cfg));
        subscribe.ttl = 16;
        ::tc8::stimulus::SubscribeDestination sd_dest{};
        sd_dest.ipv4_be = cfg.someip.dut_iface_ip;
        session->subscribeDual(subscribe, sd_dest);
        owner.adoptService(std::move(session));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Basic03SM, someipsrv_basic_03)
