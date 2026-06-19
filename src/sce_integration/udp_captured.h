#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <string>

#include "tc8/protocol_frames/udp_frame.h"
#include "tc8/upper_tester_protocol.h"

#include "sce_integration/captured_frame_timing.h"
#include "sce_integration/captured_ip_fragmentation.h"
#include "sce_integration/captured_l3_endpoints.h"
#include "sce_integration/captured_l4_ports.h"
#include "sce_integration/captured_payload_snapshot.h"
#include "sce_integration/captured_trace.h"
#include "test_config.h"
#include "wire/ip_checksum.h"

namespace tc8 {

// SCE Named Context struct carrying fields parsed from an observed UDP
// datagram (RFC 768) plus the IPv4 fragmentation knobs from the
// carrying IP header (RFC 791). Matching SCXML declaration:
//
//   <sce:context id="captured" cpp:type="tc8::UdpCaptured"
//                cpp:include="sce_integration/udp_captured.h"/>
//
// §4.4.4.6 IPv4_FRAGMENTS_05 watches `ip_flags` / `ip_fragment_offset`
// to assert MF=0 + offset=0 on a DUT-emitted UDP datagram. §4.4.4.5
// IPv4_ADDRESSING_01/02 watch the `has_ut_response` / `ut_received`
// pair to decode a §4.8.5 Confirmation from the UDP payload.
//
// UT decode: populated only when the datagram's `src_port` equals
// `ut::kPort` (tc8-dut's UT RPC port) AND `payload[0]` has the
// response bit set AND `payload_len >= 3`. The src_port gate is
// load-bearing — without it, any UDP payload whose byte 0 happens
// to have bit 7 set would false-positive `has_ut_response`. In
// particular SOME/IP SD multicast payloads start with service_id
// high byte 0xFF (service_id=0xFFFF), which DOES have bit 7 set.
// Today the SCXML guards gate further on `ut_opcode == 0x81` so
// no false-positive reaches pass/fail, but the flag's meaning
// drifts without the port gate. `src_port == ut::kPort` restores
// the invariant "has_ut_response iff this frame is a response
// from OUR UT server."
struct UdpCaptured : CapturedPayloadSnapshot, CapturedFrameTiming,
                     CapturedL3Endpoints, CapturedL4Ports,
                     CapturedIpFragmentation {
    std::uint16_t length             = 0;   // RFC 768 Length (header+payload)
    std::uint16_t checksum           = 0;

    // Encapsulating Ethernet addresses. §4.7.6.7 CM_05/_06 reads
    // `eth_dst` from the SCXML cond to verify that DUT's UDP egress to
    // an off-subnet IP-UNUSED-ADDRESS leaves with the configured
    // gateway's MAC as the L2 next hop — i.e. that the Option 3
    // (Router) ACK actually drove a routing-table install.
    std::array<std::uint8_t, 6> eth_src{};
    std::array<std::uint8_t, 6> eth_dst{};

    // Derived UT decode. Populated only when payload[0] has bit 7 set.
    bool          has_ut_response    = false;
    std::uint8_t  ut_opcode          = 0;
    std::uint8_t  ut_req_id          = 0;
    std::uint8_t  ut_status          = 0;
    std::uint8_t  ut_received        = 0;  // only valid for GetReceivedUdp resp

    // §4.6.5.5 UDP_USER_INTERFACE_02/_03/_04 ingress field readback.
    // Populated only when ut_opcode == (OpGetReceivedUdp | kResponseBit)
    // AND ut_received == 1 AND the response body carries the optional
    // trailer (src_ip:u32 + src_port:u16 + payload_len:u16 + payload[]).
    // tc8-dut emits the trailer for every populated receipt; the harness
    // surfaces it here so SCXML cond expressions can directly assert
    // "the DUT's app layer saw src_ip / src_port / payload bytes equal
    // to <expected>".
    std::uint32_t ut_recv_src_ip       = 0;   // network byte order
    std::uint16_t ut_recv_src_port     = 0;
    std::uint16_t ut_recv_payload_len  = 0;
    // §4.6.5.5 UDP_USER_INTERFACE_01 surface. Populated only when
    // ut_opcode == (OpCreateUdpReceivePorts | kResponseBit) AND the
    // response body carries the actual_count byte (status + 1 = 4
    // bytes minimum). Spec asserts the DUT created the requested
    // count of UDP receive ports; harness compares this against 10.
    std::uint8_t  ut_create_actual_count = 0;
    // First 16 B of the received payload, zero-padded if shorter. UDP
    // test cases (§4.6.5.5 _02) ship 8 B `kUdpDefaultData`; capping at
    // 16 B keeps the context POD compact while letting future cases
    // verify a 16-byte digest. Caller-side member helper
    // `ut_recv_payload_equals` does fixed-len byte equality.
    std::array<std::uint8_t, 16> ut_recv_payload_first16{};

    // The UDP-body snapshot (`payload_snapshot` / `payload_snapshot_len`,
    // capacity `kMaxPayloadSnapshot`) is inherited from
    // `CapturedPayloadSnapshot`. §4.6.5.4 UDP_FIELDS_13/_14 read it
    // through `pseudo_header_checksum_valid()` below to reconstruct the
    // wire region and run the RFC 1071 + RFC 768 1's-complement sum.

    // Inter-frame timing surface (`observed_ts_us` / `prev_observed_ts_us`
    // / `frame_delta_us()`) is inherited from `CapturedFrameTiming`. UDP
    // cases dispatch via `dispatchUdpFrame`, which auto-snapshots prev on
    // fired-transition frames; first-transition guards must NOT depend on
    // `frame_delta_us()`. §4.6 SOME/IP-SD Initial-Wait-Phase /
    // Repetitions-Phase timing cases (when they land) read it for
    // inter-message delta assertions.

    // §4.7.6.7 CM_05/_06 / §4.2 Group D: byte-equal MAC comparison
    // helpers. Defined here (member predicates) rather than relying
    // on `std::array::operator==` inside the SCXML cond so the SCE
    // `cpp:captured.X` → `this->captured_->X` rewrite covers each
    // check uniformly. Same pattern as
    // `Dhcpv4Captured::chaddr_matches_dut_mac()`.
    bool eth_dst_equals(
        const std::array<std::uint8_t, 6>& expected) const noexcept {
        for (std::size_t i = 0; i < 6; ++i) {
            if (eth_dst[i] != expected[i]) return false;
        }
        return true;
    }
    bool eth_src_equals(
        const std::array<std::uint8_t, 6>& expected) const noexcept {
        for (std::size_t i = 0; i < 6; ++i) {
            if (eth_src[i] != expected[i]) return false;
        }
        return true;
    }

    // §4.6.5.5 UDP_USER_INTERFACE_02 payload-equality predicate.
    // Compares the first `len` bytes of `ut_recv_payload_first16` with
    // `expected`. `len` is bounded by the array size; callers guard
    // upstream that `ut_recv_payload_len >= len`. Member rather than
    // free function so SCE's `cpp:captured.X` rewrite passes through —
    // same pattern as `eth_dst_equals`.
    bool ut_recv_payload_equals(const std::uint8_t *expected,
                                 std::size_t        len) const noexcept {
        if (len > ut_recv_payload_first16.size()) return false;
        for (std::size_t i = 0; i < len; ++i) {
            if (ut_recv_payload_first16[i] != expected[i]) return false;
        }
        return true;
    }

    // §4.6.5.4 UDP_FIELDS_13/_14 RFC 1071 + RFC 768 pseudo-header sum
    // validity check. Reconstructs the 8 B UDP header from scalar
    // fields, appends the captured payload snapshot, and compares the
    // wire `checksum` against `udpChecksum`'s computed value.
    //
    // Returns false (rather than asserting) when:
    //   * the wire's `length` field disagrees with `8 + payload_snapshot_len`
    //     (the snapshot would be incomplete or the wire field is malformed),
    //   * `payload_snapshot_len` exceeds `kMaxPayloadSnapshot` minus header
    //     headroom (i.e. body was too large to capture in full).
    //
    // `udpChecksum` returns the on-wire form (0x0000 → 0xFFFF), so a
    // valid datagram either matches the captured value byte-for-byte or
    // matches with the 0x0000/0xFFFF sentinel-fold equivalence.
    // Member-method shape per the SCE codegen rewrite of
    // `cpp:captured.X` → `this->captured_->X`.
    bool pseudo_header_checksum_valid() const noexcept {
        const std::size_t udp_len = 8U + payload_snapshot_len;
        if (length != static_cast<std::uint16_t>(udp_len)) return false;
        if (payload_snapshot_len + 8U > payload_snapshot.size() + 8U) return false;
        if (udp_len > 65535U) return false;

        // Reconstruct UDP region: 8 B header (with cksum field zeroed)
        // + payload snapshot bytes.
        std::array<std::uint8_t, 8U + kMaxPayloadSnapshot> region{};
        region[0] = static_cast<std::uint8_t>((src_port >> 8) & 0xFFU);
        region[1] = static_cast<std::uint8_t>(src_port & 0xFFU);
        region[2] = static_cast<std::uint8_t>((dst_port >> 8) & 0xFFU);
        region[3] = static_cast<std::uint8_t>(dst_port & 0xFFU);
        region[4] = static_cast<std::uint8_t>((length >> 8) & 0xFFU);
        region[5] = static_cast<std::uint8_t>(length & 0xFFU);
        region[6] = 0;
        region[7] = 0;
        for (std::size_t i = 0; i < payload_snapshot_len; ++i) {
            region[8 + i] = payload_snapshot[i];
        }
        const std::uint16_t computed = ::tc8::wire::udpChecksum(
            src_ip, dst_ip, region.data(), udp_len);
        if (computed == checksum) return true;
        // RFC 768 0x0000/0xFFFF sentinel equivalence: both fold to the
        // same one's-complement zero, so accept either form.
        if ((computed == 0x0000U && checksum == 0xFFFFU) ||
            (computed == 0xFFFFU && checksum == 0x0000U)) {
            return true;
        }
        return false;
    }
};

// ADL hook for TestRunner<SM>. Captured context fields come from wire
// frames, not CLI — this is a no-op for symmetry with the other
// Named Contexts.
inline void applyTestConfig(UdpCaptured & /*c*/, const TestConfig & /*cfg*/) {}

inline void fillUdpCapturedFromFrame(UdpCaptured &c, const UdpFrame &f) {
    c.src_ip             = f.src_ip;
    c.dst_ip             = f.dst_ip;
    c.src_port           = f.src_port;
    c.dst_port           = f.dst_port;
    c.length             = f.length;
    c.checksum           = f.checksum;
    c.ip_flags           = f.ip_flags;
    c.ip_fragment_offset = f.ip_fragment_offset;
    c.eth_src            = f.eth_src;
    c.eth_dst            = f.eth_dst;
    c.observed_ts_us     = f.observed_ts_us;

    c.has_ut_response = false;
    c.ut_opcode       = 0;
    c.ut_req_id       = 0;
    c.ut_status       = 0;
    c.ut_received     = 0;

    c.ut_recv_src_ip      = 0;
    c.ut_recv_src_port    = 0;
    c.ut_recv_payload_len = 0;
    c.ut_recv_payload_first16.fill(0);
    c.ut_create_actual_count = 0;

    // Snapshot the leading payload bytes for §4.6.5.4 UDP_FIELDS_13/_14
    // pseudo-header checksum reconstruction — shared bounded copy from
    // the base. Larger payloads disable the validator (it returns false
    // rather than asserting) because the captured length then trails the
    // wire `length` field.
    c.fillPayloadSnapshot(f.payload_data, f.payload_len);

    if (f.src_port == ut::kPort &&
        f.payload_data != nullptr && f.payload_len >= 3U &&
        (f.payload_data[0] & ut::kResponseBit) != 0U) {
        c.has_ut_response = true;
        c.ut_opcode       = f.payload_data[0];
        c.ut_req_id       = f.payload_data[1];
        c.ut_status       = f.payload_data[2];
        // GetReceivedUdp response body first byte is `received`; other
        // opcodes don't populate this field but leaving it zero is
        // safe — consumers gate on `ut_opcode == 0x81` before reading.
        if (c.ut_opcode == static_cast<std::uint8_t>(ut::OpCreateUdpReceivePorts |
                                                      ut::kResponseBit) &&
            f.payload_len >= 4U) {
            c.ut_create_actual_count = f.payload_data[3];
        }
        if (c.ut_opcode == static_cast<std::uint8_t>(ut::OpGetReceivedUdp |
                                                      ut::kResponseBit) &&
            f.payload_len >= 4U) {
            c.ut_received = f.payload_data[3];

            // Optional trailer (populated when ut_received == 1 and the
            // body carries at least 4 + 2 + 2 = 8 trailer bytes after
            // payload[3]). tc8-dut serialises:
            //   <src_ip:u32 BE> <src_port:u16 BE>
            //   <payload_len:u16 BE> <payload[]>
            // starting at f.payload_data[4].
            if (c.ut_received == 1U && f.payload_len >= 12U) {
                const std::uint8_t *t = f.payload_data + 4;
                c.ut_recv_src_ip =
                      (static_cast<std::uint32_t>(t[0]))
                    | (static_cast<std::uint32_t>(t[1]) << 8)
                    | (static_cast<std::uint32_t>(t[2]) << 16)
                    | (static_cast<std::uint32_t>(t[3]) << 24);
                c.ut_recv_src_port = static_cast<std::uint16_t>(
                    (static_cast<std::uint16_t>(t[4]) << 8) | t[5]);
                c.ut_recv_payload_len = static_cast<std::uint16_t>(
                    (static_cast<std::uint16_t>(t[6]) << 8) | t[7]);
                const std::size_t copy_len = std::min<std::size_t>(
                    {static_cast<std::size_t>(c.ut_recv_payload_len),
                     c.ut_recv_payload_first16.size(),
                     static_cast<std::size_t>(f.payload_len) - 12U});
                for (std::size_t i = 0; i < copy_len; ++i) {
                    c.ut_recv_payload_first16[i] = t[8 + i];
                }
            }
        }
    }
}

// Trace-recording hook (Evidence Export). See arp_captured.h for the
// design overview; this overload exposes the UDP cond-gating subset
// (4-tuple + length/checksum + UT opcode/req/status when present).
inline void appendCapturedJson(std::string &out, const UdpCaptured &c) {
    out.append("{");
    ::tc8::sce::appendL3EndpointsJson(out, c);
    ::tc8::sce::appendL4PortsJson(out, c);
    ::tc8::sce::appendUintJson(out, ",\"length\":", c.length);
    ::tc8::sce::appendUintJson(out, ",\"checksum\":", c.checksum);
    if (c.ut_opcode != 0 || c.ut_req_id != 0) {
        ::tc8::sce::appendUintJson(out, ",\"ut_opcode\":", c.ut_opcode);
        ::tc8::sce::appendUintJson(out, ",\"ut_req_id\":", c.ut_req_id);
        ::tc8::sce::appendUintJson(out, ",\"ut_status\":", c.ut_status);
    }
    ::tc8::sce::appendTimingJson(out, c);
    out.append("}");
}

}  // namespace tc8
