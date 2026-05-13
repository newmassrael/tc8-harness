#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string_view>
#include <thread>
#include <vector>

#include "tc8/captured_event.h"
#include "sce_integration/test_config.h"
#include "sce_integration/udp_captured.h"
#include "stimulus/ipv4_frame_builder.h"
#include "stimulus/udp_datagram_builder.h"
#include "stimulus/upper_tester_client.h"

namespace tc8::sce::udp {

// RFC 1122 §4.4.4.5/6 UT-driven pilot. The three consumers (ADDRESSING_01,
// ADDRESSING_02, FRAGMENTS_05) share a thin helper surface so the
// per-case traits collapse to a spec-specific 5-line body.
//
// Data-plane ports are imported from `tc8/upper_tester_protocol.h`
// so tc8-dut's listener bind and the tester's stimulus target are
// one source of truth. Spec names: `<unusedUDPSrcPort>` = 20000,
// `<unusedUDPDstPort1>` = 20001 (TC8 §4.4.4.6 FRAGMENTS_05 parameter
// list, reused here for the co-located consumers).
using ::tc8::ut::kDataPeerPort;   // 20001 — tester-source / DUT-source
using ::tc8::ut::kDataPort;        // 20000 — DUT-listen / tester-target

// 8-byte Data region §4.4.4.6 FRAGMENTS_05 asserts the DUT echoes back
// unfragmented. ADDRESSING_01 reuses the same byte pattern as its
// stimulus payload so the UT log can round-trip it for diagnostic
// visibility.
inline constexpr std::array<std::uint8_t, 8> kUdpDefaultData{
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};

// §4.6.5.4 UDP_FIELDS_04/_05 Topology 2 second-host literal. RFC 768
// specifies the egress (`_04`) and ingress (`_05`) tests in terms of
// "Host-1-IP" and "Host-2-IP" — two distinct IPs reachable on the
// DUT's primary iface. Host-1 reuses cfg.ipv4.tester_ip
// (172.16.0.1); Host-2 is this fixed 172.16.0.3 NBO literal,
// chosen on the same /24 so the DUT routes directly. The harness
// pre-pins `<172.16.0.3, tester_mac> NUD_PERMANENT` on the DUT side
// at bring_up_worker so the DUT's egress ARP resolves without a
// real responder; the tester kernel never has 172.16.0.3 aliased
// (forwarding=0 silently drops the inbound IP datagram while pcap
// still observes the wire frame via AF_PACKET ETH_P_ALL).
inline constexpr std::uint32_t kUdpHost2IpBe = 0x030010ACU;  // 172.16.0.3 NBO

// §4.6.5.5 UDP_USER_INTERFACE_07/_08 caller-specified Source/Destination
// IP axis. The spec gates these on `<DUTSupportsDynamicInterface>=TRUE`
// (default FALSE — single-iface DUT auto-satisfies the axis with one
// primary IP, vacuously passing both conformant and buggy DUTs). To
// activate the axis the harness configures secondary IPs on each side:
//
//   * `kDutAliasIp4Be` (172.16.0.5) — DIface-0 alias on the DUT veth.
//     UI_07 stimulus passes this as the `src_ip_override` for the
//     OpTriggerSendUdp request; tc8-dut binds the transient socket to
//     (alias, src_port) and sends, so wire src_ip == alias proves the
//     DUT honoured the caller's choice instead of silently defaulting
//     to the primary iface IP. SCXML cond literal must match.
//   * `kTesterAliasIp4Be` (172.16.0.4) — AIface-0 alias on the tester
//     veth. UI_08 stimulus passes this as the `target_ip_be` for the
//     OpTriggerSendUdp request; tc8-dut sends to (alias, dst_port).
//     Tester is configured with the alias so its kernel resolves DUT's
//     ARP for it (single MAC across primary + alias). SCXML cond
//     literal must match.
//
// Single source of truth shared with `dut/env/setup-netns.sh` — keeping
// both ends in lockstep prevents silent drift if the addresses are ever
// retuned. Picked outside `kUdpHost2IpBe` (172.16.0.3, FIELDS_04/_05
// Host-2-IP) so the three secondary literals stay disjoint.
inline constexpr std::uint32_t kDutAliasIp4Be    = 0x050010ACU;  // 172.16.0.5 NBO
inline constexpr std::uint32_t kTesterAliasIp4Be = 0x040010ACU;  // 172.16.0.4 NBO

// Default initial-wait before the first UDP-pilot stimulus emission.
// tc8-dut's Upper Tester sockets bind after vsomeip has initialised,
// which lags the harness's pcap-open by several hundred ms on
// smoke-test workers (harness-first order + 500 ms dut-start grace).
// 1500 ms is enough for vsomeip bootstrap + UT bind + a margin of
// safety under parallel smoke-test workers on loaded CI scheduler.
// A shorter value race-loses against the UT server binding, dropping
// the probe onto a kernel ICMP port-unreachable path and starving
// the SCXML into fail_timeout despite full DUT conformance.
inline constexpr auto kUdpPilotInitialWait = std::chrono::milliseconds(1500);

// §4.6 stimulus override knobs that span both the IPv4 layer (src_ip
// override for INVALID_ADDRESSES_01/_02) and the UDP layer (length /
// checksum / truncate-to for FIELDS_08..10/15/16). Default-constructed
// = identical to the no-overrides path used by ADDRESSING_01/02.
struct UdpStimulusOverrides {
    // IPv4 src_ip override (network byte order). INVALID_ADDRESSES_01
    // passes 224.0.0.1 (multicast); _02 passes the iface bcast literal.
    // Linux's reverse-path filter typically drops martian-source
    // datagrams at the IP layer; the app silent-drops what slips
    // through. Both surfaces produce ut_received=0 for the test.
    std::optional<std::uint32_t>                       src_ip_override;
    // Ethernet dst override. UDP_INTRODUCTION_03 sets this to the DUT's
    // real MAC so the kernel's `PACKET_HOST` gate fires and the ICMP
    // Port Unreachable error path runs (Eth-broadcast would set
    // `PACKET_BROADCAST`, suppressing the error per
    // `reference_icmp_packet_host_gate.md`). Default unset → kEthBroadcast.
    std::optional<std::array<std::uint8_t, 6>>         eth_dst_override;
    ::tc8::stimulus::UdpDatagramOverrides              udp;
};

// Build + inject one UDP datagram (IPv4-layer wrapped) on `iface`.
// Caller controls `dst_ip` so the same helper emits to limited
// broadcast (ADDRESSING_01), directed broadcast (ADDRESSING_02), or
// unicast.
inline void emitUdpStimulus(const ::tc8::TestConfig& cfg,
                             std::string_view iface,
                             std::uint32_t dst_ip_be,
                             std::uint16_t src_port,
                             std::uint16_t dst_port,
                             const std::uint8_t *payload,
                             std::size_t payload_len,
                             std::chrono::milliseconds initial_wait =
                                 kUdpPilotInitialWait,
                             const UdpStimulusOverrides &ov =
                                 UdpStimulusOverrides{}) {
    const std::uint32_t src_ip_be = ov.src_ip_override.has_value()
        ? ov.src_ip_override.value()
        : cfg.ipv4.tester_ip;
    const auto udp = ::tc8::stimulus::buildUdpDatagramWithOverrides(
        src_ip_be, dst_ip_be, src_port, dst_port, payload, payload_len, ov.udp);

    ::tc8::stimulus::Ipv4FrameSpec spec{};
    // Leave `dst_mac` at Ethernet-broadcast default so limited- and
    // directed-broadcast stimuli dispatch correctly on veth pairs.
    // The DUT's kernel then classifies by IP dst — 255.255.255.255 /
    // 172.16.0.255 both reach local sockets (iface up + listening).
    if (ov.eth_dst_override.has_value()) {
        spec.dst_mac = ov.eth_dst_override.value();
    }
    spec.src_ip      = src_ip_be;
    spec.dst_ip      = dst_ip_be;
    spec.ip_protocol = ::tc8::stimulus::kIpProtoUdp;
    ::tc8::stimulus::IpBootTiming timing{};
    timing.initial_wait = initial_wait;
    ::tc8::stimulus::emitIpv4Frame(iface, spec, udp, timing);
}

// §4.6.5.4 UDP_FIELDS_12 max-length UDP stimulus. Build one full UDP
// datagram (8 B header + payload) — checksum computed over the
// reassembled body — then fragment into IP fragments at MTU-bounded
// chunk size and emit them back-to-back. The DUT's IP reassembly
// stitches the fragments and delivers the original UDP datagram to
// the data listener; the listener sees a single 65 507 B receipt
// regardless of how the wire was split.
//
// `kFragmentChunkBytes` = 1480 = MTU(1500) - IP_hdr(20). Multiple of 8
// so fragment-offset alignment is trivial. The last fragment can be
// any byte size (no MF/offset alignment requirement).
//
// Single consumer: FIELDS_12. ICMP-Echo-bodied callers continue to use
// `ipv4_fragments_common::emitFragmentPair`.
inline int emitFragmentedUdpStimulus(const ::tc8::TestConfig& cfg,
                                      std::string_view iface,
                                      std::uint32_t dst_ip_be,
                                      std::uint16_t src_port,
                                      std::uint16_t dst_port,
                                      const std::uint8_t *payload,
                                      std::size_t        payload_len,
                                      const std::array<std::uint8_t, 6>& dut_mac,
                                      std::chrono::milliseconds initial_wait =
                                          kUdpPilotInitialWait) {
    constexpr std::size_t   kFragmentChunkBytes = 1480U;
    constexpr std::uint16_t kFragmentedUdpIpId  = 0xFE12U;

    const std::uint32_t src_ip_be = cfg.ipv4.tester_ip;
    const auto udp = ::tc8::stimulus::buildUdpDatagram(
        src_ip_be, dst_ip_be, src_port, dst_port, payload, payload_len);

    if (initial_wait.count() > 0) {
        std::this_thread::sleep_for(initial_wait);
    }

    std::size_t off = 0;
    while (off < udp.size()) {
        const std::size_t remaining = udp.size() - off;
        const std::size_t chunk = std::min(kFragmentChunkBytes, remaining);
        const bool more = (off + chunk < udp.size());

        const auto begin_it = udp.begin()
            + static_cast<std::vector<std::uint8_t>::difference_type>(off);
        const auto end_it = begin_it
            + static_cast<std::vector<std::uint8_t>::difference_type>(chunk);
        std::vector<std::uint8_t> slice(begin_it, end_it);

        ::tc8::stimulus::Ipv4FrameSpec spec{};
        spec.dst_mac         = dut_mac;
        spec.src_ip          = src_ip_be;
        spec.dst_ip          = dst_ip_be;
        spec.ip_id           = kFragmentedUdpIpId;
        spec.ip_protocol     = ::tc8::stimulus::kIpProtoUdp;
        spec.more_fragments  = more;
        spec.fragment_offset = static_cast<std::uint16_t>(off / 8U);

        ::tc8::stimulus::IpBootTiming timing{};
        timing.initial_wait   = std::chrono::milliseconds{0};
        timing.post_send_wait = std::chrono::milliseconds{0};
        const int rc = ::tc8::stimulus::emitIpv4Frame(iface, spec, slice, timing);
        if (rc != 0) return rc;

        off += chunk;
    }
    return 0;
}

// Emit an Upper Tester GetReceivedUdp request. The tc8-dut's UT
// server replies on the UDP port we source from, so the tester's
// capture pipeline observes the Confirmation as a UdpFrame whose
// `has_ut_response` decodes to true.
//
// `expected_dst_ip_be` is the IP destination the original probed UDP
// carried (limited broadcast 0xFFFFFFFF for ADDRESSING_01, directed
// broadcast for ADDRESSING_02). The tc8-dut narrows its log lookup
// by that value, so ADDRESSING_02's "was it received as directed
// broadcast?" query is a structurally distinct event from a unicast
// receipt on the same port.
inline void emitGetReceivedUdp(const ::tc8::TestConfig& cfg,
                                std::string_view iface,
                                std::uint8_t  req_id,
                                std::uint16_t listen_port,
                                std::uint32_t expected_dst_ip_be,
                                std::uint16_t tester_src_port = 20100,
                                const std::array<std::uint8_t, 6>& dut_mac = {},
                                std::chrono::milliseconds initial_wait =
                                    std::chrono::milliseconds(0)) {
    if (initial_wait.count() > 0) {
        std::this_thread::sleep_for(initial_wait);
    }
    const auto req = ::tc8::stimulus::buildGetReceivedUdpRequest(
        req_id, listen_port, expected_dst_ip_be);
    ::tc8::stimulus::sendUpperTesterRequest(
        iface, cfg.ipv4.tester_ip, cfg.ipv4.dut_iface_ip, dut_mac,
        tester_src_port, req);
}

// Emit an Upper Tester CreateUdpReceivePorts request — §4.6.5.5
// UDP_USER_INTERFACE_01 procedure step 1.
inline void emitCreateUdpReceivePorts(const ::tc8::TestConfig& cfg,
                                       std::string_view iface,
                                       std::uint8_t  req_id,
                                       std::uint8_t  count,
                                       std::uint16_t tester_src_port = 20100,
                                       const std::array<std::uint8_t, 6>& dut_mac = {},
                                       std::chrono::milliseconds initial_wait =
                                           kUdpPilotInitialWait) {
    if (initial_wait.count() > 0) {
        std::this_thread::sleep_for(initial_wait);
    }
    const auto req = ::tc8::stimulus::buildCreateUdpReceivePortsRequest(
        req_id, count);
    ::tc8::stimulus::sendUpperTesterRequest(
        iface, cfg.ipv4.tester_ip, cfg.ipv4.dut_iface_ip, dut_mac,
        tester_src_port, req);
}

// Emit an Upper Tester TriggerSendUdp request — §4.4.4.6 FRAGMENTS_05
// procedure step 1, plus §4.6.5.5 UI_07's caller-specified Source IP
// axis when `dut_src_ip_override_be` is non-zero.
inline void emitTriggerSendUdp(const ::tc8::TestConfig& cfg,
                                std::string_view iface,
                                std::uint8_t  req_id,
                                std::uint16_t dut_src_port,
                                std::uint32_t target_ip_be,
                                std::uint16_t target_port,
                                const std::uint8_t *payload,
                                std::uint16_t payload_len,
                                std::uint16_t tester_src_port = 20100,
                                const std::array<std::uint8_t, 6>& dut_mac = {},
                                std::chrono::milliseconds initial_wait =
                                    kUdpPilotInitialWait,
                                std::uint32_t dut_src_ip_override_be = 0) {
    if (initial_wait.count() > 0) {
        std::this_thread::sleep_for(initial_wait);
    }
    const auto req = ::tc8::stimulus::buildTriggerSendUdpRequest(
        req_id, dut_src_port, target_ip_be, target_port, payload, payload_len,
        dut_src_ip_override_be);
    ::tc8::stimulus::sendUpperTesterRequest(
        iface, cfg.ipv4.tester_ip, cfg.ipv4.dut_iface_ip, dut_mac,
        tester_src_port, req);
}

// ADDRESSING_01/02 shared stimulus: send a UDP probe carrying
// `kUdpDefaultData` to `broadcast_ip_be` on `kDataPort`, wait 200 ms
// for the tc8-dut data listener to log the receipt (or drop it per
// directed-broadcast rule), then send a UT GetReceivedUdp query
// scoped to `(kDataPort, broadcast_ip_be)`. The two consumers differ
// only in which broadcast literal they pass and in the SCXML
// `{$expected_received}` polarity — kept here in one place so drift
// between the probe's dst_ip and the UT query's expected_dst_ip is
// impossible by construction.
inline void emitAddressingProbeAndQuery(const ::tc8::TestConfig& cfg,
                                         std::string_view iface,
                                         std::uint32_t broadcast_ip_be,
                                         const std::array<std::uint8_t, 6>& dut_mac) {
    emitUdpStimulus(
        cfg, iface,
        broadcast_ip_be,
        kDataPeerPort,
        kDataPort,
        kUdpDefaultData.data(),
        kUdpDefaultData.size());

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    emitGetReceivedUdp(
        cfg, iface,
        /*req_id=*/1,
        /*listen_port=*/kDataPort,
        /*expected_dst_ip_be=*/broadcast_ip_be,
        /*tester_src_port=*/20100,
        /*dut_mac=*/dut_mac);
}

// §4.6.5.4 / §4.6.5.7 shared "ingress check via UT" pattern. Tester
// injects ONE UDP probe (dst=DUT_IP:kDataPort) carrying `payload`
// applied through `ov` (length / checksum / truncate / src_ip
// overrides), waits 200 ms for the DUT data listener to log (or drop)
// the receipt, then issues OpGetReceivedUdp scoped to
// (kDataPort, DUT_IP). Consumer SCXML reads `ut_received` to assert
// accept / discard.
//
// Used by every C2 ingress case (FIELDS_03/_08/_09/_10/_15/_16),
// INVALID_ADDRESSES_01/_02, DatagramLength_01, MessageFormat_02, and
// USER_INTERFACE_02/_03/_04 — drift between probe dst_ip and UT query
// expected_dst_ip is impossible by construction.
inline void emitIngressProbeAndQuery(const ::tc8::TestConfig& cfg,
                                      std::string_view iface,
                                      const std::array<std::uint8_t, 6>& dut_mac,
                                      const std::uint8_t *payload,
                                      std::size_t payload_len,
                                      std::uint16_t src_port = kDataPeerPort,
                                      const UdpStimulusOverrides &ov =
                                          UdpStimulusOverrides{},
                                      std::chrono::milliseconds initial_wait =
                                          kUdpPilotInitialWait,
                                      std::uint8_t req_id = 1) {
    emitUdpStimulus(
        cfg, iface,
        cfg.ipv4.dut_iface_ip,
        src_port,
        kDataPort,
        payload,
        payload_len,
        initial_wait,
        ov);

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    emitGetReceivedUdp(
        cfg, iface,
        req_id,
        /*listen_port=*/kDataPort,
        /*expected_dst_ip_be=*/cfg.ipv4.dut_iface_ip,
        /*tester_src_port=*/20100,
        /*dut_mac=*/dut_mac);
}

// Dispatch helper: select the UdpFrame variant, mirror into `c`, raise
// `udp_observed` on the SM. Non-UDP events ignored.
//
// Inter-frame timing surface (auto-managed `prev_observed_ts_us`):
// snapshots `c.observed_ts_us` into `c.prev_observed_ts_us` only when
// the SM's current state advances after `step()` — same contract as
// `tcp_pilot_common.h::dispatchTcpFrame`. Future §4.6 SOME/IP-SD
// timing cases call `c.frame_delta_us()` from SCXML guards.
template <typename SM>
inline void dispatchUdpFrame(typename SM::CapturedType& c, SM& sm,
                              const ::tc8::CapturedEvent& ev) {
    const auto* f = std::get_if<::tc8::UdpFrame>(&ev);
    if (f == nullptr) return;
    ::tc8::fillUdpCapturedFromFrame(c, *f);
    const auto state_before = sm.getCurrentState();
    sm.raiseExternal(SM::PolicyType::Event::Udp_observed);
    sm.step();
    const auto state_after = sm.getCurrentState();
    if (state_after != state_before) {
        c.prev_observed_ts_us = c.observed_ts_us;
    }
}

}  // namespace tc8::sce::udp
