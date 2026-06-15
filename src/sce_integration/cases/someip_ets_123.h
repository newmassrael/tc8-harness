#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_123_sm.h"

namespace tc8::sce::cases {

using SomeipEts123SM = ::SCE::Generated::someip_ets_123::someip_ets_123;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_123 — SubscribeEventgroup with EntriesLen
// exceeding the SOME/IP Length field. Per PRS_SOMEIPSD_00265 / 00153 /
// 00270 the DUT must reject (Nack with ttl == 0) or silently drop. The
// SOME/IP Length stays at the canonical 48 bytes; only EntriesLen is
// inflated to a value that lies past the message boundary
// (0xFFFFFF00 — 4 GB - 256 B, far beyond any plausible message).
template <>
struct TestCaseTraits<cases::SomeipEts123SM> : SomeIpAnyBase<cases::SomeipEts123SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_123";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup EntriesLen exceeds total SOME/IP Length — DUT Nacks or ignores";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        // Brief gap so the OfferService cyclic emit has landed before the
        // malformed Subscribe lands; mirrors emitSubscribeEventgroupBoot's
        // post-FindService cadence.
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SubscribeEventgroupParams params{};
        params.target.eventgroup_id = 0x0001;
        params.session_id = 0x0001;
        // 0xFFFFFF00 lies far past the canonical 48-byte SOME/IP Length;
        // any vsomeip parser reading EntriesLen and walking that many
        // bytes hits end-of-message and rejects.
        params.entries_len_override = 0xFFFFFF00U;
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts123SM, someip_ets_123)
