#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_071_sm.h"

namespace tc8::sce::cases {

using SomeipEts071SM = ::SCE::Generated::someip_ets_071::someip_ets_071;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_071 — DUT must reject (or silently ignore)
// an echoUNION Request whose union-internal length prefix lies about
// how many bytes the variant value occupies. Stimulus reuses the
// ETS_038 Type 2 (uint8) baseline but corrupts payload byte 3 from
// 0x01 to 0x80 (claims 128 B of value follow the 4-byte type tag,
// while only 1 B is present). SOME/IP Length stays self-consistent so
// the frame reaches CommonAPI; the Variant decoder
// (capicxx-someip-runtime InputStream.hpp Variant read path) reads
// itsSize = 128, walks past the buffer end, trips errorOccurred_, the
// dispatcher emits Error Response. Lenient ETS_001/_002 4-path
// verdict pattern.
template <>
struct TestCaseTraits<cases::SomeipEts071SM> : SomeIpAnyBase<cases::SomeipEts071SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_071";
    static constexpr std::string_view kDescription =
        "echoUNION inner union-length too long — DUT must reject or ignore";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0019;
        target.payload = {
            // unionLength_BE = 0x00000080 (lies — claims 128 B of value
            // follow the type tag, while only 1 B is actually present)
            0x00, 0x00, 0x00, 0x80,
            // unionType_BE = 0x00000002 (Type 2 = uint8)
            0x00, 0x00, 0x00, 0x02,
            // value = 0x42 (only 1 byte, not 128 as unionLength claims)
            0x42,
        };
        ::tc8::stimulus::emitMethodRequestAfter(iface, target, {}, ::tc8::sce::someipUdpMethodDest(cfg));
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts071SM, someip_ets_071)
