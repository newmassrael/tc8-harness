#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <string>

#include "tc8/protocol_frames/arp_frame.h"
#include "tc8/protocol_frames/udp_frame.h"

#include "sce_integration/captured_frame_timing.h"
#include "sce_integration/captured_trace.h"
#include "test_config.h"

namespace tc8 {

// SCE Named Context struct carrying fields parsed from an observed ARP
// frame. Matching SCXML declaration:
//   <sce:context id="captured" cpp:type="tc8::ArpCaptured"
//                cpp:include="sce_integration/arp_captured.h"/>
//
// Fields mirror `tc8::ArpFrame` one-for-one (no SD-style payload parsing
// to thread). `TestCaseTraits<SM>::dispatch` calls
// `fillArpCapturedFromFrame(c, frame)` after pulling the variant
// alternative; SCXML guards then compare per-field against `expected`
// (see `arp_expected.h`).
struct ArpCaptured : CapturedFrameTiming {
    std::uint16_t hw_type = 0;
    std::uint16_t proto_type = 0;
    std::uint8_t hw_addr_len = 0;
    std::uint8_t proto_addr_len = 0;
    std::uint16_t opcode = 0;
    std::array<std::uint8_t, 6> sender_hw{};
    std::uint32_t sender_proto_ip = 0;  // network byte order
    std::array<std::uint8_t, 6> target_hw{};
    std::uint32_t target_proto_ip = 0;  // network byte order
    // Encapsulating Ethernet header of the ARP frame. §4.2.4.2 ARP_43
    // verifies the Reply's Ethernet Source = DUT MAC distinctly from the
    // ARP sender_hw payload field; capturing both lets the guard pin
    // frame-level identity even when sender_hw matches by construction.
    std::array<std::uint8_t, 6> eth_src{};
    std::array<std::uint8_t, 6> eth_dst{};
    // Cross-protocol observation used by ARP_04/06: when dispatch sees a
    // `UdpFrame`, it copies the encapsulating Ethernet destination and
    // the UDP datagram's IPv4 destination here. Zero-initialised values
    // mean "no UDP observed yet" — the SCXML guard for ARP_04/06 pass
    // explicitly checks `observed_udp_dst_ip == expected.tester_ip` so
    // it never matches on the un-populated default.
    std::array<std::uint8_t, 6> observed_udp_eth_dst{};
    std::uint32_t observed_udp_dst_ip = 0;  // network byte order

    // Inter-frame timing surface (`observed_ts_us` / `prev_observed_ts_us`
    // / `frame_delta_us()`) is inherited from `CapturedFrameTiming`.
    // `fillArpCapturedFromFrame` / `fillArpCapturedFromUdpFrame` mirror
    // `observed_ts_us` on every fill. ARP cases dispatch inline (no shared
    // `dispatchArpFrame` helper), so a case that needs inter-frame delta
    // semantics must snapshot `prev_observed_ts_us = observed_ts_us`
    // itself when `sm.getCurrentState()` advances — see
    // `tcp_pilot_common.h::dispatchTcpFrame` for the auto-managed pattern.
    // No current ARP case reads the delta, but the surface is shared so
    // future §4.2.4.x ANNOUNCE_REPS gap-timing cases need no rewiring.

    // §4.5.6.2 ADDRESS_SELECTION_11/_12/_13: snapshot of the FIRST
    // DUT-emitted ARP Probe's `target_proto_ip` so the SCXML can
    // assert "DUT re-picks AFTER conflict" via `target_proto_ip !=
    // first_probe_target_proto_ip`. Set imperatively by the trait's
    // dispatch helper on the wait_probe1 → await_repick transition;
    // remains 0 outside CONFLICT cases. NBO storage matches
    // `target_proto_ip`.
    std::uint32_t first_probe_target_proto_ip = 0;

    // §4.5.6.2 ADDRESS_SELECTION_14/_15: count of conflict-ARP frames
    // the tester has emitted in response to DUT-side Probes during the
    // current case. Used by the SCXML guard to drive the cycle →
    // silence_watch transition once `tc8::rfc3927::kMaxConflicts`
    // emits have landed; the dispatch helper increments after each
    // emit. Stays at 0 outside the conflict-resolution cluster.
    std::uint32_t repeated_conflicts_emitted = 0;

    // §4.5.6.2 ADDRESS_SELECTION_16 (RFC 3927 §2.5 "the host MUST
    // respond" claim-condition): the DUT's committed LL address
    // snapshot, written by the trait's scheduled stimulus closure
    // after `OpQueryLLAddress` returns. The SCXML guard reads it as
    // the expected `sender_proto_ip` of the DUT's ARP Reply. Stays at
    // 0 outside _16; the SCXML's claim-condition guard fires only on
    // a non-zero snapshot, so a UT-query failure (returns 0) never
    // false-passes a defender-emitted Reply targeting an unrelated LL.
    // (The tester-side LL is `expected.tester_linklocal_ip` —
    // topology-pinned, lives in `ArpExpected`, not here.)
    std::uint32_t expected_responder_sender_ip_be = 0;

    // §4.5.6.2 ADDRESS_SELECTION_14/_15: target_proto_ip of the
    // previous DUT-emitted ARP Probe processed by the dispatcher.
    // The cycle (and wait_repick for _15) SCXML guards compare the
    // newly-arrived `target_proto_ip` against this snapshot to assert
    // "DUT picked a fresh LL after each conflict" — TC8 spec step 11
    // (and step 58 in _15) verify the new probe targets a different
    // LL than the immediately-prior one. Set-after-step semantics
    // (dispatcher writes AFTER raise+step) guarantee the SCXML guard
    // sees the LL_{N-1} value while comparing against LL_N. Stays at
    // 0 until the first probe is processed; the first transition
    // listening → cycle compares LL_1 against 0 which always passes.
    std::uint32_t previous_observed_probe_target_ip = 0;

    // §4.5 IPv4 Link-Local Probe predicate (RFC 3927 §2.1.1). True iff
    // the captured frame is an ARP Probe targeting the 169.254/16
    // prefix:
    //   opcode == 1 (Request)
    //   sender_proto_ip == 0 (RFC 3927 Probe distinguishing field)
    //   target_proto_ip ∈ 169.254.0.0/16
    //   eth_dst == ff:ff:ff:ff:ff:ff
    //
    // Endianness: target_proto_ip is stored NBO. On little-endian
    // hosts, the low 16 bits of the uint32 are the wire's first two
    // octets (169.254 → 0xA9 0xFE → low half 0xFEA9). The harness
    // runs only on Linux x86_64/ARM64 (both LE), same assumption as
    // the rest of the IP-stack guards.
    bool is_arp_probe() const noexcept {
        if (opcode != 1) return false;
        if (sender_proto_ip != 0) return false;
        if ((target_proto_ip & 0xFFFFU) != 0xFEA9U) return false;
        for (std::size_t i = 0; i < 6; ++i) {
            if (eth_dst[i] != 0xFFU) return false;
        }
        return true;
    }

    // §4.5.6.2 ADDRESS_SELECTION_16: opcode-2 reply predicate.
    // RFC 826 ARP Reply carries opcode 2; the RFC 826 §2.5 claim-condition
    // assertion needs only this single field to distinguish the
    // DUT's defender Reply from its prior Probes (opcode 1) and
    // Announces (opcode 1) flowing through the same SCXML listening
    // state.
    bool is_arp_reply() const noexcept { return opcode == 2; }

    // §4.7.6.9 INIT_ALLOC_08/_09/_10 / RFC 2131 §4.4.1: post-BOUND DHCP
    // Probe predicate, parameterised on the target IP. Distinct from
    // `is_arp_probe()` (which gates the LL-prefix `target_proto_ip`)
    // because the DHCPv4 client probes the OFFER-bound yiaddr, which
    // is routable (not link-local). Wire shape:
    //   * opcode = 1 (Request)
    //   * sender_proto_ip = 0
    //   * target_proto_ip == `target_ip_be` (typically expected.dhcpv4.offered_ip_be)
    //   * eth_dst = ff:ff:ff:ff:ff:ff
    bool is_dhcp_arp_probe(std::uint32_t target_ip_be) const noexcept {
        if (opcode != 1) return false;
        if (sender_proto_ip != 0) return false;
        if (target_proto_ip != target_ip_be) return false;
        return is_eth_broadcast();
    }

    // §4.7.6.9 INIT_ALLOC_10 / RFC 2131 §4.4.1 SHOULD: post-Probe
    // gratuitous ARP Reply announcing the just-bound IP. Distinct
    // from `is_arp_announce()` (which is RFC 3927 §2.4 LL-specific —
    // opcode 1 Request with sender == target both in 169.254/16) —
    // here the announce is opcode 2 (Reply) with sender_proto_ip
    // equal to the bound DHCP yiaddr, broadcast eth_dst.
    bool is_dhcp_arp_announce(std::uint32_t sender_ip_be) const noexcept {
        if (opcode != 2) return false;
        if (sender_proto_ip != sender_ip_be) return false;
        return is_eth_broadcast();
    }

    // §4.5.6.2 ADDRESS_SELECTION_16 / RFC 3927 §2.4 Announcement
    // predicate: ARP Request with sender_proto_ip == target_proto_ip
    // (both non-zero). Distinguishes the post-claim Announce from a
    // Probe (sender_proto_ip == 0). The 169.254/16 prefix check is
    // not strictly required by RFC 3927 §2.4 (a host announcing a routable
    // address would also match) but tightens the assertion against
    // ambient ARP noise on the iface.
    bool is_arp_announce() const noexcept {
        if (opcode != 1) return false;
        if (sender_proto_ip == 0) return false;
        if (sender_proto_ip != target_proto_ip) return false;
        return target_proto_ip_in_link_local_prefix();
    }

    // True iff `eth_dst == ff:ff:ff:ff:ff:ff`. Standalone helper so
    // §4.5 cases can express "the FRAME was broadcast" independently
    // of the Probe shape — useful for negative SCXML branches that
    // want to fail on "Probe-shape but not broadcast".
    bool is_eth_broadcast() const noexcept {
        for (std::size_t i = 0; i < 6; ++i) {
            if (eth_dst[i] != 0xFFU) return false;
        }
        return true;
    }

    // §4.5.6.2 ADDRESS_SELECTION_07 (RFC 3927 §2.2.1 SHOULD): the
    // target hardware address field of an ARP Probe is set to all
    // zeroes.
    bool target_hw_is_zero() const noexcept {
        for (auto b : target_hw) {
            if (b != 0) return false;
        }
        return true;
    }

    // §4.5.6.2 ADDRESS_SELECTION_08 (RFC 3927 §2.1 MUST): the target
    // proto IP is in the 169.254/16 link-local prefix. Same LE
    // assumption as `is_arp_probe()` — wire bytes A9 FE map to low
    // half 0xFEA9 on x86_64/ARM64.
    bool target_proto_ip_in_link_local_prefix() const noexcept {
        return (target_proto_ip & 0xFFFFU) == 0xFEA9U;
    }

    // §4.5.6.2 ADDRESS_SELECTION_01 (RFC 3927 §2.1 MUST): exclude
    // the first 256 (169.254.0.0/24) and last 256 (169.254.255.0/24)
    // addresses. After the prefix check, the third wire octet (X in
    // 169.254.X.Y) sits at bits 16..23 of the LE-stored uint32 and
    // must satisfy 1 <= X <= 254.
    bool target_proto_ip_in_valid_ll_range() const noexcept {
        if (!target_proto_ip_in_link_local_prefix()) return false;
        const auto third =
            static_cast<std::uint8_t>((target_proto_ip >> 16) & 0xFFU);
        return third >= 1U && third <= 254U;
    }
};

// ADL hook called by `TestRunner<SM>` at construction. No-op for captured
// because captured fields get populated from wire frames, not from CLI
// configuration; the overload exists so the uniform `applyTestConfig(c, cfg)`
// call in TestRunner compiles for every Named Context type.
inline void applyTestConfig(ArpCaptured & /*c*/, const TestConfig & /*cfg*/) {
    // captured-from-wire fields have no CLI-driven initial values.
}

inline void fillArpCapturedFromFrame(ArpCaptured &c, const ArpFrame &f) {
    c.hw_type = f.hw_type;
    c.proto_type = f.proto_type;
    c.hw_addr_len = f.hw_addr_len;
    c.proto_addr_len = f.proto_addr_len;
    c.opcode = f.opcode;
    std::copy(f.sender_hw.begin(), f.sender_hw.end(), c.sender_hw.begin());
    std::copy(f.target_hw.begin(), f.target_hw.end(), c.target_hw.begin());
    c.sender_proto_ip = f.sender_proto_ip;
    c.target_proto_ip = f.target_proto_ip;
    c.eth_src = f.eth_src;
    c.eth_dst = f.eth_dst;
    c.observed_ts_us = f.observed_ts_us;
}

// Populates the cross-protocol observation fields when a UdpFrame reaches
// dispatch. ARP §4.2.4.1 ARP_04/06 pass criterion reads "DUT sends UDP
// Message with Ethernet Destination = MAC-ADDR1 and Destination IP
// Address = HOST-1-IP"; guards compare these fields against `ArpExpected`.
inline void fillArpCapturedFromUdpFrame(ArpCaptured &c, const UdpFrame &u) {
    c.observed_udp_eth_dst = u.eth_dst;
    c.observed_udp_dst_ip = u.dst_ip;
    c.observed_ts_us = u.observed_ts_us;
}

// Trace-recording hook (Evidence Export). Resolved via ADL from
// TestRunner<SM>::dumpTraceJson(); appends a JSON object capturing the
// fields a reader of the verdict-decider case-note expects to see when
// the matching wire frame is not retained in the saved pcap. Fields are
// the same ones ARP SCXML conds typically gate on (opcode +
// sender_hw + sender/target proto IPs + observed_udp_*).
inline void appendCapturedJson(std::string &out, const ArpCaptured &c) {
    char buf[64];
    out.append("{\"opcode\":");
    std::snprintf(buf, sizeof(buf), "%u", c.opcode);
    out.append(buf);
    out.append(",\"sender_hw\":");
    ::tc8::sce::appendMacJson(out, c.sender_hw);
    out.append(",\"target_hw\":");
    ::tc8::sce::appendMacJson(out, c.target_hw);
    out.append(",\"sender_proto_ip\":");
    ::tc8::sce::appendIpv4Json(out, c.sender_proto_ip);
    out.append(",\"target_proto_ip\":");
    ::tc8::sce::appendIpv4Json(out, c.target_proto_ip);
    if (c.observed_udp_dst_ip != 0) {
        out.append(",\"observed_udp_dst_ip\":");
        ::tc8::sce::appendIpv4Json(out, c.observed_udp_dst_ip);
        out.append(",\"observed_udp_eth_dst\":");
        ::tc8::sce::appendMacJson(out, c.observed_udp_eth_dst);
    }
    out.append("}");
}

}  // namespace tc8
