#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string_view>
#include <thread>
#include <vector>

#include "tc8/captured_event.h"
#include "tc8/unperformed_stimulus.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/test_config.h"
#include "sce_integration/udp_captured.h"
#include "sce_integration/udp_receive_answer.h"
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
// DUT's primary iface. Host-1 reuses cfg.tester.ip
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
//     The netns fixture's OWN value, and nothing on the assertion path
//     reads it: UI_07's stimulus sources its `src_ip_override` from
//     `cfg.dut.secondary_ip` (what the topology declared) and the SCXML
//     compares against `expected.dut_alias_ip`, so a site naming a real
//     DUT's alias moves the ask and the expectation together while this
//     constant keeps describing the veth it configures (TD-48).
//     tc8-dut binds the transient socket to (secondary, src_port) and
//     sends, so wire src_ip == expectation proves the DUT honoured the
//     caller's choice instead of silently defaulting to the primary IP.
//   * `kTesterAliasIp4Be` (172.16.0.4) — AIface-0 alias on the tester
//     veth. The netns fixture's OWN value, with no reader on the
//     assertion path: UI_08's stimulus sources its `target_ip_be` from
//     `cfg.tester.secondary_ip` (what the topology declared this tester
//     holds) and the SCXML compares against `expected.tester_alias_ip`,
//     so a site naming its own alias moves the ask and the expectation
//     together while this constant keeps describing the veth it
//     configures (TD-49). tc8-dut sends to (that address, dst_port); the
//     tester is configured with the alias so its kernel resolves the
//     DUT's ARP for it (single MAC across primary + alias).
//
// Single source of truth shared with `dut/env/setup-netns.sh` — keeping
// both ends in lockstep prevents silent drift if the addresses are ever
// retuned. Picked outside `kUdpHost2IpBe` (172.16.0.3, FIELDS_04/_05
// Host-2-IP) so the three secondary literals stay disjoint.
inline constexpr std::uint32_t kDutAliasIp4Be    = 0x050010ACU;  // 172.16.0.5 NBO
inline constexpr std::uint32_t kTesterAliasIp4Be = 0x040010ACU;  // 172.16.0.4 NBO

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
    // `Ipv4FrameSpec::dst_mac` in stimulus/ipv4_frame_builder.h). Default
    // unset → kEthBroadcast.
    std::optional<std::array<std::uint8_t, 6>>         eth_dst_override;
    ::tc8::stimulus::UdpDatagramOverrides              udp;
};

// Build + inject one UDP datagram (IPv4-layer wrapped) on `iface`.
// Caller controls `dst_ip` so the same helper emits to limited
// broadcast (ADDRESSING_01), directed broadcast (ADDRESSING_02), or
// unicast.
//
// No wait before the emission. The 1.5 s this family used to sleep here stood for
// "the DUT's Upper Tester has bound", which the start-order barrier now proves:
// the UDP traits base declares it required (kDutReadyBarrier, _udp_traits_base.h),
// so a run without that proof is reported as unperformed instead of racing.
inline void emitUdpStimulus(const ::tc8::TestConfig& cfg,
                             std::string_view iface,
                             std::uint32_t dst_ip_be,
                             std::uint16_t src_port,
                             std::uint16_t dst_port,
                             const std::uint8_t *payload,
                             std::size_t payload_len,
                             const UdpStimulusOverrides &ov =
                                 UdpStimulusOverrides{}) {
    const std::uint32_t src_ip_be = ov.src_ip_override.has_value()
        ? ov.src_ip_override.value()
        : cfg.tester.ip;
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
    timing.initial_wait = std::chrono::milliseconds{0};
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
                                      const std::array<std::uint8_t, 6>& dut_mac) {
    constexpr std::size_t   kFragmentChunkBytes = 1480U;
    constexpr std::uint16_t kFragmentedUdpIpId  = 0xFE12U;

    const std::uint32_t src_ip_be = cfg.tester.ip;
    const auto udp = ::tc8::stimulus::buildUdpDatagram(
        src_ip_be, dst_ip_be, src_port, dst_port, payload, payload_len);

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

// The sentinel of a receive window: one well-formed datagram to the DUT's unicast
// address and the port under test, sent after the probe. A backend that only
// reports what the socket delivered (testability) needs it to tell a discard from a
// silent forward loop; the opcode backend ignores it (IUdpReceiveControl::
// receiveUdp). It goes to the DUT's own address whatever the probe's destination
// was, so that a probe aimed at an address the DUT is expected to refuse (a
// directed broadcast, a multicast group) is still followed by a datagram it must
// accept.
inline void emitReceiveSentinel(const ::tc8::TestConfig& cfg, std::string_view iface) {
    emitUdpStimulus(cfg, iface, cfg.ipv4.dut_iface_ip, kDataPeerPort, kDataPort,
                    ::tc8::sce::kUdpReceiveSentinelPayload.data(),
                    ::tc8::sce::kUdpReceiveSentinelPayload.size());
}

// Observe what the DUT receives on `listen` while `probe` runs, and record the
// answer in `c` (udp_receive_answer.h). Routed over the Tier-2 seam; a backend
// that cannot be asked, or an answer that never came, leaves the case unanswered —
// a non-conclusion, not a verdict.
inline void observeUdpReceive(UdpCaptured& c,
                              ::tc8::sce::IDutControl& dut,
                              const ::tc8::sce::Endpoint& listen,
                              const std::function<void()>& probe,
                              const std::function<void()>& sentinel) {
    auto *rx = dut.udpReceiveControl();
    if (rx == nullptr) {
        // The selected backend has no receive sub-interface, so the DUT is never
        // asked. Naming it keeps the case from reporting a verdict about a
        // question that was not put: the gate should have skipped this case (see
        // kCapUdpReceiveControl), and if it did not, the case must not pass or
        // fail silently on a stimulus that never happened.
        ::tc8::UnperformedStimulus::record("dut_udp_receive_control_absent");
        return;
    }
    recordReceiveAnswer(c, rx->receiveUdp(listen, probe, sentinel));
}

// As observeUdpReceive, recorded as the case's second window (UDP_FIELDS_05).
inline void observeSecondUdpReceive(UdpCaptured& c,
                                    ::tc8::sce::IDutControl& dut,
                                    const ::tc8::sce::Endpoint& listen,
                                    const std::function<void()>& probe,
                                    const std::function<void()>& sentinel) {
    auto *rx = dut.udpReceiveControl();
    if (rx == nullptr) {
        ::tc8::UnperformedStimulus::record("dut_udp_receive_control_absent");
        return;
    }
    recordSecondReceiveAnswer(c, rx->receiveUdp(listen, probe, sentinel));
}

// §4.6.5.5 UDP_USER_INTERFACE_01 procedure step 1: have the DUT open `count` UDP
// receive ports, over the Tier-2 seam, and record how many it reports it opened.
inline void emitCreateUdpReceivePorts(UdpCaptured& c,
                                      ::tc8::sce::IDutControl& dut,
                                      std::uint8_t count) {
    auto *rx = dut.udpReceiveControl();
    if (rx == nullptr) {
        ::tc8::UnperformedStimulus::record("dut_udp_receive_control_absent");
        return;
    }
    recordPortsAnswer(c, rx->createReceivePorts(count));
}

// Ask the DUT to originate one UDP datagram — §4.4.4.6 FRAGMENTS_05 procedure
// step 1, plus §4.6.5.5 UI_07's caller-specified Source IP axis when
// `dut_src_ip_override_be` is non-zero.
//
// Routed over the Tier-2 seam rather than building an opcode envelope here, so
// the request reaches whichever DUT-control backend `--dut-control` selected.
// The transport, the request id and the tester's own source port are the
// backend's business and no longer appear in this signature: a case states WHAT
// the DUT should do, never how the ask is delivered.
//
// Returns false when the selected backend has no UDP control, or when the DUT
// declined the request. A false return means the stimulus did not happen, which
// is a non-conclusion rather than a DUT verdict — the awaited opcode path
// already records it as an unperformed stimulus.
inline bool emitTriggerSendUdp(::tc8::sce::IDutControl& dut,
                                std::uint16_t dut_src_port,
                                std::uint32_t target_ip_be,
                                std::uint16_t target_port,
                                const std::uint8_t *payload,
                                std::uint16_t payload_len,
                                std::uint32_t dut_src_ip_override_be = 0) {
    auto *udp = dut.udpControl();
    if (udp == nullptr) {
        ::tc8::UnperformedStimulus::record("dut_udp_control_absent");
        return false;
    }
    return udp->sendDatagram(
        ::tc8::sce::Endpoint{dut_src_ip_override_be, dut_src_port},
        ::tc8::sce::Endpoint{target_ip_be, target_port},
        std::vector<std::uint8_t>(payload, payload + payload_len));
}

// ADDRESSING_01/02 shared stimulus: a UDP probe carrying `kUdpDefaultData` to
// `broadcast_ip_be` on `kDataPort`, observed as a receive window on
// `(kDataPort, broadcast_ip_be)`. The two consumers differ only in which
// broadcast literal they pass and in the SCXML `{$expected_received}` polarity —
// kept here in one place so drift between the probe's dst_ip and the window's
// scope is impossible by construction.
// Keeps `cfg`/`iface` because the PROBE half is a tester-side wire emission, and
// takes `dut` because the WINDOW asks the DUT a question. The two halves are
// different kinds of act, which is why both stay in the signature.
inline void emitAddressingProbeAndObserve(UdpCaptured& c,
                                           const ::tc8::TestConfig& cfg,
                                           std::string_view iface,
                                           ::tc8::sce::IDutControl& dut,
                                           std::uint32_t broadcast_ip_be) {
    observeUdpReceive(
        c, dut, ::tc8::sce::Endpoint{broadcast_ip_be, kDataPort},
        [&] {
            emitUdpStimulus(cfg, iface, broadcast_ip_be, kDataPeerPort, kDataPort,
                            kUdpDefaultData.data(), kUdpDefaultData.size());
        },
        [&] { emitReceiveSentinel(cfg, iface); });
}

// §4.6.5.4 / §4.6.5.7 shared "ingress check" pattern. Tester injects ONE UDP
// probe (dst=DUT_IP:kDataPort) carrying `payload` applied through `ov` (length /
// checksum / truncate / src_ip overrides), observed as a receive window on
// (kDataPort, DUT_IP). Consumer SCXML reads `ut_received` to assert accept /
// discard.
//
// Used by every C2 ingress case (FIELDS_03/_08/_09/_10/_15/_16),
// INVALID_ADDRESSES_01/_02, DatagramLength_01, MessageFormat_02, and
// USER_INTERFACE_02/_03/_04 — drift between the probe's dst_ip and the window's
// scope is impossible by construction.
// As emitAddressingProbeAndObserve: the probe is a tester-side emission, the
// window is a question for the DUT, so the signature carries both halves' needs.
inline void emitIngressProbeAndObserve(UdpCaptured& c,
                                        const ::tc8::TestConfig& cfg,
                                        std::string_view iface,
                                        ::tc8::sce::IDutControl& dut,
                                        const std::uint8_t *payload,
                                        std::size_t payload_len,
                                        std::uint16_t src_port = kDataPeerPort,
                                        const UdpStimulusOverrides &ov =
                                            UdpStimulusOverrides{}) {
    observeUdpReceive(
        c, dut, ::tc8::sce::Endpoint{cfg.ipv4.dut_iface_ip, kDataPort},
        [&] {
            emitUdpStimulus(cfg, iface, cfg.ipv4.dut_iface_ip, src_port, kDataPort,
                            payload, payload_len, ov);
        },
        [&] { emitReceiveSentinel(cfg, iface); });
}

// Dispatch helper: select the UdpFrame variant, mirror into `c`, raise
// `udp_observed` on the SM. Non-UDP events ignored.
//
// Inter-frame timing surface: calls `c.snapshotFired()` only when the
// SM's current state advances after `step()` — same contract as
// `tcp_pilot_common.h::dispatchTcpFrame`, owned and documented by
// `CapturedFrameTiming`. §4.6 SOME/IP-SD timing cases call
// `c.frame_delta_us()` from SCXML guards.
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
        c.snapshotFired();
    }
}

}  // namespace tc8::sce::udp
