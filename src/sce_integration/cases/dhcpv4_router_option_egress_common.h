#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "tc8/upper_tester_protocol.h"

#include "sce_integration/dhcpv4_default_endpoints.h"
#include "sce_integration/dhcpv4_pilot_common.h"
#include "sce_integration/dhcpv4_server_stimulus.h"
#include "sce_integration/test_case_traits.h"
#include "sce_integration/udp_pilot_common.h"

namespace tc8::sce::cases::router_option_egress {

// §4.7.6.7 CM_05/_06 / RFC 2132 §3.5 Option 3 (Router) TLV. Both
// cases inject the SAME 4-byte router address (SERVER1-IP =
// `kDefaultServerIdBe`), only the carrying BOOTP region differs.
// The TLV terminates with 0xFF END per RFC 2132 §9.3 last sentence.
inline std::vector<std::uint8_t> buildOption3RouterPayload() {
    std::vector<std::uint8_t> p;
    p.reserve(7);
    const auto* gw = reinterpret_cast<const std::uint8_t*>(
        &::tc8::sce::dhcpv4::kDefaultServerIdBe);
    p.push_back(3U);   // Option 3 (Router)
    p.push_back(4U);   // length
    p.push_back(gw[0]);
    p.push_back(gw[1]);
    p.push_back(gw[2]);
    p.push_back(gw[3]);
    p.push_back(0xFFU);  // END terminator inside the overloaded region
    return p;
}

// §4.7.6.7 CM_05/_06 wire harness. Schedules:
//   * OFFER on Listening_for_request entry (msg_type=2, with Option
//     52 = `option_52_overload` + sname/file payloads carrying
//     Option 3 Router).
//   * ACK on Listening_for_dut_udp entry (msg_type=5, same overload
//     payload — DUT extracts Router from whichever lifecycle reply
//     hit first).
//   * 400 ms after Listening_for_dut_udp entry: OpTriggerSendUdp UT
//     request driving the DUT's sendto to IP-UNUSED-ADDRESS through
//     the freshly-installed gateway.
//
// Both consumers (CM_05 / CM_06) instantiate this against their own
// `Dhcpv4ClientConstructingMessagesXXSM`; the State enum names come
// from the shared `dhcpv4_router_option_egress` SCXML template, so
// `Listening_for_request` / `Listening_for_dut_udp` resolve in both.
//
// `sname_payload` and `file_payload` are passed by value so the
// caller can move them in once and the helper threads them into
// `ServerEmulParams` for each scheduled reply. Empty for whichever
// region the case does not overload.
template <typename SM>
inline void wireRouterOverloadStimulus(
    typename SM::CapturedType&                c,
    const ::tc8::TestConfig&                  cfg,
    std::string_view                          iface,
    ::tc8::sce::IStimulusScheduler&           scheduler,
    std::uint8_t                              option_52_overload,
    std::vector<std::uint8_t>                 sname_payload,
    std::vector<std::uint8_t>                 file_payload) {
    using State = typename SM::PolicyType::State;

    ::tc8::sce::dhcpv4::emitStartDhcpClient(
        cfg, iface, cfg.dut.mac);

    ::tc8::sce::dhcpv4::ServerEmulParams params{};
    params.option_52_overload      = option_52_overload;
    params.sname_payload           = std::move(sname_payload);
    params.file_payload            = std::move(file_payload);
    params.ip_datagram_total_bytes = 576U;  // CM_05/_06 step 5 PAD target

    ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
        scheduler, static_cast<int>(State::Listening_for_request),
        iface, c.dhcpv4, /*message_type=*/2U, params);
    ::tc8::sce::dhcpv4::scheduleDhcpReplyOnStateEntry(
        scheduler, static_cast<int>(State::Listening_for_dut_udp),
        iface, c.dhcpv4, /*message_type=*/5U, params);

    // Step 9: "Externally cause DUT to send UDP to IP-UNUSED-ADDRESS"
    // — fire OpTriggerSendUdp 400 ms after entering Listening_for_
    // dut_udp so the DUT has time to ingest the ACK, install the
    // default route, and ARP-resolve the gateway via the smoke-test
    // pre-pinned permanent neigh entry.
    //
    // 1-byte payload (0xA5) — the harness pcap pipeline silently
    // drops empty UDP datagrams (libtins find_pdu<RawPDU> returns
    // null when payload_len == 0; see
    // `reference_pipeline_empty_udp_gate.md`). A single sentinel
    // byte is enough for udp_observed to fire — pass criteria are
    // L2/L3 shape, not data content.
    const auto iface_copy = std::string(iface);
    scheduler.scheduleAfterStateEntry(
        static_cast<int>(State::Listening_for_dut_udp),
        [&scheduler, iface_copy, &cfg]() {
            scheduler.schedule(
                std::chrono::milliseconds(400),
                [iface_copy, &cfg]() {
                    static constexpr std::uint8_t kProbePayload = 0xA5U;
                    ::tc8::sce::udp::emitTriggerSendUdp(
                        cfg, iface_copy,
                        /*req_id=*/2U,
                        /*dut_src_port=*/::tc8::ut::kDataPeerPort,
                        /*target_ip_be=*/
                        ::tc8::sce::dhcpv4::kUnusedRoutedIpBe,
                        /*target_port=*/::tc8::ut::kDataPort,
                        /*payload=*/&kProbePayload,
                        /*payload_len=*/1U,
                        /*tester_src_port=*/20101U,
                        cfg.dut.mac,
                        /*initial_wait=*/std::chrono::milliseconds(0));
                });
        });
}

}  // namespace tc8::sce::cases::router_option_egress
