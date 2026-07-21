#pragma once

#include <cstdint>
#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"

#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_089_sm.h"

namespace tc8::sce::cases {

using SomeipEts089SM = ::SCE::Generated::someip_ets_089::someip_ets_089;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_089 (lite) — SD_Calling_same_ports_before_and_
// after_suspendInterface. Verdict reduces the spec's 18-step sequence to
// the wire-observable suspend cycle:
//   1. DUT cyclic OfferService observed (warm-up gate).
//   2. After tester invokes suspendInterface (Method 0x02 fire&forget,
//      args UInt32 start + UInt32 duration), DUT emits StopOfferService
//      (Type 0x01 + ttl == 0).
//   3. After the suspend duration elapses, DUT re-offers the service
//      (Type 0x01 + ttl > 0) on the same vsomeip.json-configured ports.
//
// Method 0x02 payload is two big-endian UInt32 values: { start_ms,
// duration_ms }. start_ms = 0 (immediate suspend) and duration_ms = 2000
// (resume after 2 s) keeps the SCXML phase 3 deadline (8 s) inside its
// envelope while leaving headroom for the post-resume cyclic Offer.
template <>
struct TestCaseTraits<cases::SomeipEts089SM> : SomeIpAnyBase<cases::SomeipEts089SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_089";
    static constexpr std::string_view kDescription =
        "suspendInterface — DUT emits StopOfferService then re-offers same ports";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);

        ::tc8::stimulus::SomeIpRpcMessage suspend{};
        suspend.method_id    = 0x0002;       // suspendInterface (ets.fdepl)
        suspend.message_type = ::tc8::someip::MessageType::REQUEST_NO_RETURN;         // Fire&Forget
        // Two big-endian UInt32 args: start_ms = 0, duration_ms = 2000.
        suspend.payload      = {0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x07, 0xD0};
        ::tc8::stimulus::emitMethodRequestAfter(iface, suspend, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts089SM, someip_ets_089)
