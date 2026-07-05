#pragma once

#include <memory>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/someip_method_dest.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"
#include "stimulus/subscribe_tcp_session.h"

#include "someipsrv_format_26_sm.h"

namespace tc8::sce::cases {

using Format26SM =
    ::SCE::Generated::someipsrv_format_26::someipsrv_format_26;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.1.26 — TTL field of the Type 2 entry shall carry
// the configured timer TTL on a SubscribeEventgroupAck (Pass Criteria
// step 8 verifies "TTL set to <SERVICE-ID-1-TTL>"). The Synopsis
// carve-out for Stop / Nack entries (TTL = 0) is not exercised by
// this case — the trait stimulus subscribes to a configured
// eventgroup so vsomeip replies with an Ack carrying TTL > 0; a Nack
// (TTL = 0) lands fail_ttl, surfacing a vsomeip / configuration
// regression that the prior `or ttl == 0` accept-clause masked.
template <>
struct TestCaseTraits<cases::Format26SM>
    : SomeIpSdOnlyBase<cases::Format26SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_FORMAT_26";
    static constexpr std::string_view kDescription =
        "Type 2 entry TTL on a SubscribeEventgroupAck shall carry the configured TTL";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface,
                         ::tc8::sce::IBackgroundServiceOwner& owner) {
        // §5.1.5.1.26 exercises the Ack path: subscribe to eventgroup
        // 0x0002 (declared under TestEventUINT8 in dut/ets/ets.fdepl +
        // dut/dut_service/vsomeip.json) so DUT replies with
        // SubscribeEventgroupAck (TTL > 0) instead of Nack (TTL = 0).
        // The Type 2 entry-format invariants verified by FORMAT_19..28
        // are identical for Ack and Nack; running the Ack path
        // exercises the spec's primary case and the harness's
        // configured TTL value. eg 0x0002 is mixed-reliability, so the
        // Ack requires a dual UDP+TCP Subscribe over a held connection.
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        auto session = std::make_unique<::tc8::stimulus::SubscribeEventgroupTcpSession>(
            iface, ::tc8::sce::someipTcpMethodDest(cfg));
        // Keep the default ttl (3): FORMAT_26 asserts the Ack entry's ttl round-
        // trips the request, so it must not be overridden here.
        ::tc8::stimulus::SubscribeEventgroupTarget subscribe{};
        subscribe.eventgroup_id = 0x0002;
        ::tc8::stimulus::SubscribeDestination sd_dest{};
        sd_dest.ipv4_be = cfg.someip.dut_iface_ip;
        session->subscribeDual(subscribe, sd_dest);
        owner.adoptService(std::move(session));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Format26SM, someipsrv_format_26)
