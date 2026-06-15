#pragma once

#include <array>
#include <cstdint>
#include <string_view>
#include <thread>
#include <vector>

#include "sce_integration/case_registry.h"
#include "sce_integration/cases/_udp_traits_base.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/udp_pilot_common.h"

#include "udp_fields_12_sm.h"

namespace tc8::sce::cases {

using UdpFields12SM = ::SCE::Generated::udp_fields_12::udp_fields_12;

// §4.6.5.4 UDP_FIELDS_12 max-length payload size. RFC 768 IPv4 payload
// max = 65 535 (IP total length) - 20 (IP hdr) - 8 (UDP hdr) = 65 507 B.
// Defined here rather than at trait scope so the smoke build's
// `--vs-spec` gap report can ground-truth-check the literal against
// the spec parameter table without grepping headers.
inline constexpr std::size_t kUdpMaxPayloadBytes = 65507U;

}  // namespace tc8::sce::cases

namespace tc8::sce {

template <>
struct TestCaseTraits<cases::UdpFields12SM>
    : UdpAnyBase<cases::UdpFields12SM> {
    static constexpr std::string_view kCaseId      = "UDP_FIELDS_12";
    static constexpr std::string_view kSpecSection = "4.6.5.4";
    static constexpr std::string_view kDescription =
        "DUT accepts a UDP datagram with maximum supported Length "
        "(65 507 B IPv4 payload; RFC 768 'Fields' MUST). Wire is "
        "split across ~45 IP fragments; DUT's IP reassembly is "
        "verified end-to-end via UT GetReceivedUdp.";

    // Build a 65 507 B payload filled with `i & 0xFF` so the wire
    // bytes are deterministic per index. The SCXML pivots on length,
    // not byte content, but a deterministic pattern makes the
    // `payload_first16` capture readable in pcap.
    static void stimulus(Captured& /*c*/,
                         const ::tc8::TestConfig& cfg,
                         std::string_view iface) {
        std::vector<std::uint8_t> payload(cases::kUdpMaxPayloadBytes);
        for (std::size_t i = 0; i < payload.size(); ++i) {
            payload[i] = static_cast<std::uint8_t>(i & 0xFFU);
        }

        ::tc8::sce::udp::emitFragmentedUdpStimulus(
            cfg, iface,
            /*dst_ip_be=*/cfg.ipv4.dut_iface_ip,
            /*src_port=*/::tc8::sce::udp::kDataPeerPort,
            /*dst_port=*/::tc8::sce::udp::kDataPort,
            payload.data(),
            payload.size(),
            cfg.dut.mac);

        // Allow DUT-side IP reassembly + data listener delivery to
        // settle before issuing the UT query. 500 ms covers Linux's
        // reassembly path (microseconds in practice) plus the data
        // listener's recvmsg + log write under workers=4 jitter.
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        ::tc8::sce::udp::emitGetReceivedUdp(
            cfg, iface,
            /*req_id=*/1,
            /*listen_port=*/::tc8::sce::udp::kDataPort,
            /*expected_dst_ip_be=*/cfg.ipv4.dut_iface_ip,
            /*tester_src_port=*/::tc8::ut::kTesterSrcPort,
            /*dut_mac=*/cfg.dut.mac);
    }
};

}  // namespace tc8::sce

TC8_REGISTER_CASE(::tc8::sce::cases::UdpFields12SM, udp_fields_12)
