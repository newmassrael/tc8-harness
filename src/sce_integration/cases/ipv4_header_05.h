#pragma once

#include <array>
#include <cstdint>
#include <string_view>

#include "tc8/bpf_group.h"
#include "tc8/captured_event.h"

#include "sce_integration/case_registry.h"
#include "sce_integration/icmpv4_captured.h"
#include "sce_integration/icmpv4_pilot_common.h"
#include "sce_integration/test_case_traits.h"
#include "sce_integration/test_runner.h"
#include "stimulus/icmpv4_builder.h"

#include "ipv4_header_05_sm.h"

namespace tc8::sce::cases {

using Ipv4Header05SM = ::SCE::Generated::ipv4_header_05::ipv4_header_05;

// Spec literal: "IP Total Length field set to 576" + "556 bytes data
// in IP Payload" (== 8 B ICMP header + 548 B Echo Data). RFC 791 §3.1
// MUST: every host accepts at least 576-octet datagrams.
inline constexpr std::size_t kHeader05IcmpDataLen = 548;

// Build the 548-byte ICMP Data region. Pattern is byte index lo-byte
// (0x00..0xFF cycling) — gives the dissector something distinctive
// per offset so a wire-truncation bug surfaces cleanly. The harness
// payload_snapshot only captures 64 B; the SCXML asserts the wire
// payload_len equals 548 directly without byte-equality verification.
inline std::array<std::uint8_t, kHeader05IcmpDataLen> makeHeader05Payload() {
    std::array<std::uint8_t, kHeader05IcmpDataLen> p{};
    for (std::size_t i = 0; i < p.size(); ++i) {
        p[i] = static_cast<std::uint8_t>(i & 0xFFU);
    }
    return p;
}

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::Ipv4Header05SM> {
    using SM    = cases::Ipv4Header05SM;
    using State = SM::PolicyType::State;
    using Event = SM::PolicyType::Event;

    static constexpr std::string_view kCaseId       = "IPv4_HEADER_05";
    static constexpr std::string_view kDescription  =
        "DUT accepts an IP datagram of up to 576 octets and replies "
        "without truncating the Data section (RFC 791 §3.1 MUST)";
    static constexpr bool             kDeprecated   = false;
    static constexpr int              kTopology     = 1;
    static constexpr ::tc8::BpfGroup  kBpfGroup     = ::tc8::BpfGroup::Icmpv4;

    using Captured = typename SM::CapturedType;
    using Expected = typename SM::ExpectedType;

    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        // Bypass `ipv4_pilot_common::emitStimulus` — it doesn't thread
        // payload_data/_len through, and HEADER_05's spec mandates a
        // 548 B Data region. Construct the IcmpMessageSpec inline so
        // the builder's Echo-shape body picks up the spec-literal size.
        static const auto payload = cases::makeHeader05Payload();
        ::tc8::stimulus::IcmpMessageSpec spec{};
        spec.src_ip       = cfg.icmpv4.tester_ip;
        spec.dst_ip       = cfg.icmpv4.dut_iface_ip;
        spec.echo_id      = ::tc8::stimulus::kIcmpEchoId;
        spec.echo_seq     = ::tc8::stimulus::kIcmpEchoSeq;
        spec.payload_data = payload.data();
        spec.payload_len  = static_cast<std::uint32_t>(payload.size());
        ::tc8::stimulus::emitIcmpMessage(iface, spec);
    }

    static void dispatch(Captured& c, SM& sm, const ::tc8::CapturedEvent& ev) {
        ::tc8::sce::icmpv4::dispatchAnyIcmpFrame<SM>(c, sm, ev);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::Ipv4Header05SM, ipv4_header_05)
