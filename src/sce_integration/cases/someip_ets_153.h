#pragma once

#include <chrono>
#include <string_view>
#include <thread>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_153_sm.h"

namespace tc8::sce::cases {

using SomeipEts153SM = ::SCE::Generated::someip_ets_153::someip_ets_153;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_153 — SubscribeEventgroup whose SOME/IP
// Length field declares a value smaller than the actual on-wire size
// (Length = 16 instead of canonical 48). The OptionsLen + per-option
// Length fields stay canonical so the malformation is purely in the
// outer SOME/IP frame header. Per PRS_SOMEIP_00042 / PRS_SOMEIPSD_00393
// / PRS_SOMEIPSD_00566 the DUT must Nack or ignore. Lenient verdict
// accepts both because vsomeip's `udp_server_endpoint_impl` typically
// silent-drops on the bad-length-field gate before its SD layer can
// dispatch a Nack.
template <>
struct TestCaseTraits<cases::SomeipEts153SM> : SomeIpAnyBase<cases::SomeipEts153SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_153";
    static constexpr std::string_view kDescription =
        "SubscribeEventgroup SOME/IP Length lies smaller than actual — DUT Nacks or ignores";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        std::this_thread::sleep_for(std::chrono::milliseconds(2500));

        ::tc8::stimulus::SubscribeEventgroupParams params{};
        params.target.eventgroup_id = 0x0001;
        params.session_id = 0x0001;
        // Canonical SOME/IP Length for our 1-option Subscribe is 48
        // (= 56 datagram bytes minus the leading 8 SOME/IP header).
        // Lying with Length = 16 matches the spec's "shorter than the
        // actual length" wording while keeping every downstream length
        // field (OptionsLen, per-option Length) honest, so the
        // malformation is isolated to the outer SOME/IP header.
        params.length_override = 16U;
        ::tc8::stimulus::emitSubscribeEventgroupRaw(iface, params);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts153SM, someip_ets_153)
