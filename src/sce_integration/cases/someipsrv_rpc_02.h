#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someipsrv_rpc_02_sm.h"

namespace tc8::sce::cases {

using Rpc02SM = ::SCE::Generated::someipsrv_rpc_02::someipsrv_rpc_02;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.5.7.2 — single transport for all notifications of
// SERVICE-ID-2. Stimulus chain: FindService(0xF4E8) → wait for
// OfferService → Subscribe(service=0xF4E8, eventgroup=0x0003) → DUT
// Acks + cyclic Notification (impl_si2->fireTestEventUINT8Event in
// dut_main's event_thread).
template <>
struct TestCaseTraits<cases::Rpc02SM> : SomeIpAnyBase<cases::Rpc02SM> {
    static constexpr std::string_view kCaseId      = "SOMEIPSRV_RPC_02";
    static constexpr std::string_view kSpecSection = "5.1.5.7.2";
    static constexpr std::string_view kDescription =
        "Single transport for all notifications of SERVICE-ID-2";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& /*cfg*/,
                         std::string_view iface) {
        ::tc8::stimulus::FindServiceTarget find{};
        find.service_id = ::tc8::someipsrv_si2::kServiceId;
        ::tc8::stimulus::emitFindServiceBoot(iface, find);

        ::tc8::stimulus::SubscribeEventgroupTarget sub{};
        sub.service_id = ::tc8::someipsrv_si2::kServiceId;
        sub.eventgroup_id = ::tc8::someipsrv_si2::kEventGroupId;
        ::tc8::stimulus::emitSubscribeEventgroupBoot(iface, sub);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Rpc02SM, someipsrv_rpc_02)
