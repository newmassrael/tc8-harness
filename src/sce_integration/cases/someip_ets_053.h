#pragma once

#include <string_view>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_someipsrv_traits_base.h"
#include "sce_integration/test_runner.h"
#include "stimulus/someip_rpc_builder.h"
#include "stimulus/someip_sd_builder.h"

#include "someip_ets_053_sm.h"

namespace tc8::sce::cases {

using SomeipEts053SM = ::SCE::Generated::someip_ets_053::someip_ets_053;

}  // namespace tc8::sce::cases

namespace tc8::sce {

// TC8 v3.0 §5.1.6 SOMEIP_ETS_053 — echoUTF8FIXED round-trip. Tester
// sends a CommonAPI-SOMEIP fixed-length 64-byte UTF-8 string for
// ASCII "hi" to METHOD-ID 0x0013. The on-wire shape carries no
// length prefix — `SomeIpStringLengthWidth = 0` +
// `SomeIpStringLength = 64` in ets.fdepl pin the 64-byte fixed
// payload. Layout: BOM (EF BB BF) + 'h' (68) + 'i' (69) + null (00)
// + 58 B zero padding = 64 B total. The single trailing null after
// content is required by CommonAPI's UTF-8 deserializer
// (InputStream.cpp:251); the remaining padding zeros sit beyond
// that terminator and are part of the fixed-width frame.
template <>
struct TestCaseTraits<cases::SomeipEts053SM> : SomeIpAnyBase<cases::SomeipEts053SM> {
    static constexpr std::string_view kCaseId      = "SOMEIP_ETS_053";
    static constexpr std::string_view kSpecSection = "5.1.6";
    static constexpr std::string_view kDescription =
        "echoUTF8FIXED round-trip — DUT echoes 64-byte UTF-8 BOM-prefixed \"hi\"";

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        ::tc8::stimulus::emitFindServiceBoot(iface, ::tc8::stimulus::FindServiceTarget{},
                                             cfg.stimulus_timing);
        ::tc8::stimulus::MethodRequestTarget target{};
        target.method_id = 0x0013;
        // 64 raw bytes, no length prefix. BOM + 'h' + 'i' + null +
        // 58 B zero padding.
        target.payload = std::vector<uint8_t>(64, 0x00);
        target.payload[0] = 0xEF;  // BOM byte 0
        target.payload[1] = 0xBB;  // BOM byte 1
        target.payload[2] = 0xBF;  // BOM byte 2
        target.payload[3] = 0x68;  // 'h'
        target.payload[4] = 0x69;  // 'i'
        // [5] = 0x00 (trailing null), [6..63] = 0
        ::tc8::stimulus::emitMethodRequestAfter(iface, target);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::SomeipEts053SM, someip_ets_053)
