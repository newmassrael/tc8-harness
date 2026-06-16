#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include "stimulus/arp_builder.h"  // kEthBroadcast, sendRawEthernet

namespace tc8::stimulus {

// IPv4 Protocol byte values the builder and its callers reference by
// name. Kept in the shared header because §4.4.4.6 FRAGMENTS_04 needs
// the TCP literal on a non-TCP callsite (it mis-tags frag 1's protocol
// to prove the DUT rejects reassembly when the fragments' tuple differs
// on protocol). IANA assigned numbers: 1 = ICMP, 6 = TCP, 17 = UDP.
inline constexpr std::uint8_t kIpProtoIcmp = 0x01;
inline constexpr std::uint8_t kIpProtoTcp  = 0x06;
inline constexpr std::uint8_t kIpProtoUdp  = 0x11;

// Timing envelope for an IPv4-layer stimulus emission. `initial_wait`
// defers the first send until the DUT's stack is ready (mirror of the
// ARP/ICMP builders' equivalent field). `post_send_wait` blocks AFTER
// the last frame is injected but BEFORE the emit call returns —
// §4.3.3.2 TYPE_04 and §4.4.4.6 FRAGMENTS_02/03/04 use it to hold off
// opening the SCXML listen window until the DUT's IP fragment
// reassembly timer has expired (spec's `<ipIniReassembleTimeout>`;
// Linux `net.ipv4.ipfrag_time` default 30 s, or 3 s when smoke-test.sh
// lowers it per netns). TestRunner arms SCXML deadline timers only
// after `kickStimulus` returns, so the wait shifts the listen window
// forward without eroding it.
//
// `post_send_wait` is `std::chrono::milliseconds` so subsecond waits
// compose cleanly with Linux's 1-second `ipfrag_time` resolution — a
// 4500 ms wait pairs with `ipfrag_time=3` + margin. `std::chrono::
// seconds{N}` converts implicitly, so existing TYPE_04 callers are
// untouched.
struct IpBootTiming {
    std::chrono::milliseconds initial_wait{200};
    std::chrono::milliseconds post_send_wait{0};
};

// Specification of an Ethernet-II + IPv4 frame. Carries only IP-layer
// concerns; L4 content is supplied as an opaque `ip_payload` byte
// vector at call time. The builder prepends the 14 B Ethernet header
// and the 20 + options_len B IPv4 header, computes the IPv4 header
// checksum, and concatenates the payload verbatim.
//
// `src_mac` defaults to all-zeroes. AF_PACKET SOCK_RAW sends the frame
// bytes verbatim — the kernel does not overwrite the Ethernet source —
// so frames go on the wire with src_mac 00:00:00:00:00:00. Linux
// dispatches IP by dst_ip regardless of the frame-level source MAC.
// Set explicitly to a locally-administered literal if a future case
// observes DUT behaviour keyed on IP source MAC.
//
// `dst_mac` defaults to Ethernet broadcast so the pilot cases don't
// have to thread the DUT MAC through TestConfig just to send an IPv4
// frame. Linux dispatches ICMP / IP by dst_ip regardless of the
// frame-level Ethernet destination on veth pairs. Error-class ICMP
// replies (Parameter Problem, Time Exceeded, Destination Unreachable)
// require PACKET_HOST dispatch so callers emitting those stimuli must
// set this to the DUT MAC — see `reference_icmp_packet_host_gate.md`.
struct Ipv4FrameSpec {
    std::array<std::uint8_t, 6> src_mac{};            // zero by default
    std::array<std::uint8_t, 6> dst_mac = kEthBroadcast;
    std::uint32_t src_ip = 0;                         // network byte order
    std::uint32_t dst_ip = 0;                         // network byte order
    std::uint8_t  ttl    = 64;                        // RFC 1122 §3.2.1.7 default
    std::uint16_t ip_id  = 0x4242;                    // arbitrary per-boot

    // IANA Protocol byte. Default ICMP matches the §4.3 pilot; §4.4.4.6
    // FRAGMENTS_04 sets it to `kIpProtoTcp` on frag 1 to prove the DUT
    // rejects reassembly when the fragments' tuple differs on protocol.
    std::uint8_t  ip_protocol = kIpProtoIcmp;

    // IPv4 options to inject between the fixed 20 B header and the
    // L4 payload. Raw option bytes — the caller encodes per RFC 791.
    // Builder appends EOL (0x00) padding so the options segment is
    // 4-byte aligned, recomputes IHL = (20 + options_len + padding) / 4
    // and total_length accordingly, and includes options + padding in
    // the IPv4 header checksum. Empty default keeps IHL=5.
    std::vector<std::uint8_t> ip_options;

    // IPv4 fragmentation knobs. `fragment_offset` is in 8-octet units
    // per RFC 791 §3.1 (13-bit field). The builder encodes
    // byte[6] = (MF << 5) | ((offset >> 8) & 0x1F) and byte[7] =
    // offset & 0xFF, preserving the reserved+DF bits as 0.
    bool          more_fragments  = false;
    std::uint16_t fragment_offset = 0;

    // Per-field overrides applied BEFORE the IPv4 header checksum is
    // computed, so the resulting header carries a valid checksum over
    // the overridden bytes — §4.4.4.1 HEADER_02 / HEADER_08 / HEADER_09
    // and §4.4.4.4 VERSION_04 need this so the DUT's drop reason is
    // the header-field invariant being tested, not a checksum artefact.
    std::optional<std::uint8_t>  version_override;       // byte[0] high nibble
    std::optional<std::uint8_t>  ihl_override;           // byte[0] low nibble
    std::optional<std::uint16_t> total_length_override;  // bytes[2..3]

    // Flip one bit of the IPv4 header checksum AFTER computation.
    // §4.4.4.2 CHECKSUM_02 uses this to assert the DUT's receive-side
    // IP checksum discard path (RFC 1122 §3.2.1.2).
    bool corrupt_ip_checksum = false;
};

// Build an Ethernet-II + IPv4 frame carrying `ip_payload` as the IP-
// layer body. `ip_payload` bytes are placed verbatim after the 20 +
// options_len B IPv4 header — the builder does not parse or mutate
// them, so callers can compose any L4 (ICMP, TCP, UDP, raw bytes)
// via prebuilt buffers. Used by §4.3 ICMPv4 cases (ICMP body from
// `buildIcmpEchoRequestBody`), §4.4.4.6 FRAGMENTS (ICMP body split
// across two calls), and any future IPv4-stimulus case.
std::vector<std::uint8_t> buildIpv4Frame(const Ipv4FrameSpec &spec,
                                         const std::vector<std::uint8_t> &ip_payload);

// High-level TESTER emit of one IPv4 frame. Sleeps `timing.initial_wait`,
// builds via `buildIpv4Frame`, injects via `sendRawEthernet`, then
// sleeps `timing.post_send_wait` before returning. Blocks at least
// `initial_wait + post_send_wait` milliseconds.
int emitIpv4Frame(std::string_view iface,
                  const Ipv4FrameSpec &spec,
                  const std::vector<std::uint8_t> &ip_payload,
                  const IpBootTiming &timing = {});

// The ICMP Echo Request body builder moved to the shared wire layer
// (tc8::wire::buildIcmpEchoRequestBody, "wire/icmp_echo.h") so the DUT-side
// testability endpoint frames echoes from the same source — ICMP-body callers
// include that header.

// RFC 792 p17 ICMP Timestamp / Timestamp Reply (type=13 / type=14) body
// builder. Wire layout is the canonical 8-byte ICMP header (Type, Code,
// Checksum, Identifier, Sequence Number) followed by three 32-bit big-
// endian timestamp slots: Originate, Receive, Transmit. Total body is
// 20 bytes (no payload tail — RFC 792 fixes the size).
//
// `type` defaults to 13 (Timestamp). The override is exposed for symmetry
// with `buildIcmpEchoRequestBody`; §4.3.3.2 TYPE_11 / TYPE_12 send the
// canonical Timestamp Request and observe the DUT's Timestamp Reply, so
// neither case currently overrides type or code. Checksum is computed
// over the full 20 B region per RFC 1071, matching the Echo body
// computation surface.
std::vector<std::uint8_t> buildIcmpTimestampRequestBody(
    std::uint16_t id,
    std::uint16_t seq,
    std::uint32_t originate_timestamp,
    std::uint32_t receive_timestamp,
    std::uint32_t transmit_timestamp,
    std::optional<std::uint8_t> type_override = std::nullopt,
    std::optional<std::uint8_t> code_override = std::nullopt,
    bool          corrupt_checksum = false);

}  // namespace tc8::stimulus
