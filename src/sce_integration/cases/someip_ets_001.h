#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_001_sm.h"

namespace tc8::sce::cases {

using SomeipEts001SM = ::SCE::Generated::someip_ets_001::someip_ets_001;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_001 — DUT must reject (or silently ignore)
// an echoUINT8 Request whose SOME/IP Length header lies about the
// payload size. Tester sets `length_override = 0x100` so the SOME/IP
// header claims 256 bytes follow Request ID, while the UDP datagram
// only carries 1 byte of payload (0x42). vsomeip's parser detects the
// mismatch against the received UDP size and drops the frame (or
// returns MALFORMED_MESSAGE depending on stack); both paths satisfy
// the spec pass criteria per Notes.
template <>
struct TestCaseTraits<cases::SomeipEts001SM> : SomeIpAnyBase<cases::SomeipEts001SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_001";
    static constexpr std::string_view kDescription =
        "Length field longer than UDP datagram — DUT must reject or ignore";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0008;
        target.payload = {0x42};
        // Override Length to claim 256 bytes follow Request ID — the
        // UDP datagram only carries 9 bytes after the header (16-byte
        // SOME/IP header + 1-byte payload). vsomeip's
        // udp_server_endpoint matches Length against UDP receive size
        // and rejects the frame.
        target.length_override = 0x100u;
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts001SM, someip_ets_001)
