#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include "stimulus/arp_builder.h"  // kEthBroadcast

namespace tc8::stimulus {

// §4.3.3.2 ICMPv4_TYPE_09 identifier the tester injects into every Echo
// Request of the pilot case set. Hardcoded (not read from
// `TestConfig::icmpv4`) for the same drift-safety reason as
// `kTesterInjectedMac`: `smoke-test.sh --negative` can flip the
// *expected* value alone and prove the SCXML mismatch path without also
// changing what the stimulus sends.
//
// `smoke-test.sh`'s ICMPV4 `--expect icmpv4.echo_id=...` must carry the
// same value; any drift silently turns the positive TYPE_09 row into a
// false pass, so edit both together. The 0x1234 / 0x5678 values are
// arbitrary but non-zero so an unset CLI expectation falls into the
// fail sink instead of matching by accident.
inline constexpr std::uint16_t kIcmpEchoId  = 0x1234;
inline constexpr std::uint16_t kIcmpEchoSeq = 0x5678;

// TC8 v3.0 §4.3.3.2 ICMPv4_TYPE_11 / TYPE_12 — Originate Timestamp the
// TESTER injects into the Timestamp Request body. RFC 792 p17 defines
// this slot as "the time the sender last touched the message before
// sending it" in 32 bits of milliseconds since midnight UT. The spec
// places no constraint on the literal value (the test asserts only
// that the DUT's Reply echoes it verbatim), so the harness uses an
// arbitrary non-zero non-rollover sentinel: 0x12345678 ms (~3.4 hours
// past UT midnight).
//
// Hardcoded for the same drift-safety reason as `kIcmpEchoId`: the
// stimulus side and the SCXML guard both reference this constant, so
// `--negative` rows can flip an expected-context value alone to prove
// the SCXML mismatch path without also changing what the stimulus
// sends. Non-zero matters: the spec's pass criterion for TYPE_11 is
// "Receive Timestamp != 0 AND Transmit Timestamp != 0" — keeping the
// originate non-zero too guards against a DUT that mirrors the
// originate slot into one of those fields and accidentally satisfies
// the != 0 constraint without computing a real time.
inline constexpr std::uint32_t kIcmpTimestampOriginate = 0x12345678U;

// TC8 v3.0 §4.3.3.2 TYPE_05 / §4.3.3.1 ERROR_04 / §4.3.3.1 ERROR_02
// Internet Timestamp IP option bytes the TESTER injects. The option's
// `length` byte claims 10 while the body on the wire is 8 B — that
// size mismatch is the header parameter problem under test (RFC 791
// §3.1 requires length = total option bytes, pointer = next-write
// offset ≤ length + 1). ERROR_02 additionally exercises the
// Parameter Problem pointer=22 reply path: IP header length (20) +
// offset of the pointer field within the option (byte 2, 0-indexed) =
// 22 in 1-indexed octet-from-start-of-datagram coordinates.
// RFC 791 §3.1 Internet Timestamp layout:
//   byte 0  = option type     = 0x44 (copy=0, class=2 debug, number=4)
//   byte 1  = length field    = 0x0A (10; intentionally ≠ 8 on wire)
//   byte 2  = pointer         = 0x09 (malformed: > length + 1 would be 11)
//   byte 3  = overflow + flag = 0x00 (flag=0 "timestamps only")
//   bytes 4..7 = one 32-bit timestamp value = 0
// 8 bytes already 4-byte aligned → builder adds zero EOL padding,
// IHL becomes 7 (20 + 8) / 4. Single source of truth: the case
// traits reference this constant, unit tests assert shape against
// it, smoke-test does not duplicate the literal.
inline constexpr std::array<std::uint8_t, 8> kIcmpv4TimestampOptionMalformed{
    0x44, 0x0A, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00};

// §4.3.3.1 ERROR_03 frag-0 Internet Timestamp option — distinct from
// the length-10 literal above: length field = 12, pointer = 9, one
// timestamp value, flag=0 "timestamps only". Under flag=0 each slot
// is 4 B, so length=12 = 4 B option header + 4 B timestamp slot 1 +
// 4 B timestamp slot 2 = two slots; pointer=9 means "next free byte
// is offset 9" i.e. slot 1 is filled (bytes 5..8) and slot 2 is free
// (bytes 9..12). The option is WELL-FORMED on frag 0. The test
// invariant is kernel-level: a conformant DUT must not parse options
// on fragments with offset != 0, so the malformed length-10 option
// on frag 1 never elicits a Parameter Problem even though it would
// on a non-fragmented packet.
//
// 12 bytes already 4-byte aligned → builder adds zero EOL padding,
// IHL becomes 8 (20 + 12) / 4. Single source of truth for the
// length-12 variant; frag 1 of ERROR_03 reuses the length-10 literal
// above (same defect class as TYPE_05 / ERROR_04).
inline constexpr std::array<std::uint8_t, 12> kIcmpv4TimestampOptionLen12{
    0x44, 0x0C, 0x09, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};

// §4.3.3.1 ERROR_03 frag-split and §4.3.3.2 TYPE_04 sole-fragment
// "constructed ICMP packet" — 16 B total so each half is 8 B, the
// smallest value that's a valid IP fragment boundary (offsets must
// be multiples of 8 octets for any fragment with MF=1). The byte
// content is arbitrary: ERROR_03's pass criterion observes absence
// of Parameter Problem from the DUT (independent of reassembly
// output), and TYPE_04's pass criterion observes absence of Time
// Exceeded after the DUT's reassembly timer elapses (the fragment's
// own bytes are never parsed as ICMP because fragment 0 is missing).
// Zeros keep the stimulus byte-shape deterministic without
// pretending the bytes carry semantics.
//
// §4.3.3.1 ERROR_02 does NOT use this literal — its stimulus takes
// the canonical ICMP-synthesis path so the wire carries a valid
// Echo Request header (type=8, code=0, id/seq, checksum) in fragment
// 0. The spec's "first half of the constructed ICMP packet" clause
// reduces to the 8 B ICMP header alone when the Echo Request has
// zero payload, which is what ERROR_02 constructs.
inline constexpr std::array<std::uint8_t, 16> kIcmpv4FragmentStimulusPacket{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// Timing envelope for the tester-side ICMPv4 stimulus. Mirrors
// `ArpBootTiming` — ICMP Echo Request delivery is a one-shot send; no
// retry loop is needed because the DUT's kernel reply is deterministic
// for valid checksums and the absence-path TYPE_10 case explicitly
// asserts no reply.
//
// `post_send_wait` blocks AFTER the stimulus frame is injected but
// BEFORE `emitIcmpMessage` returns. Consumers: §4.3.3.2 TYPE_04 and
// §4.4.4.6 FRAGMENTS_02/03/04 both wait for the DUT's IP fragment
// reassembly timer to expire (spec `<ipIniReassembleTimeout>`; Linux
// `net.ipv4.ipfrag_time` default 30 s, lowered to 3 s per netns via
// smoke-test.sh for fragment-heavy cases) before the SCXML listen
// window opens, so any DUT-emitted Time Exceeded reply — which the
// test asserts does NOT appear — has had its natural opportunity to
// emerge. TestRunner arms SCXML deadline timers only after
// `kickStimulus` returns, so blocking here shifts the listen window
// forward without eroding it. Default `0` preserves the pre-fragment
// stimulus shape for every other case.
//
// `std::chrono::milliseconds` so FRAGMENTS_02/03/04 can pair their
// phase-gap wait with a `ipfrag_time=3 s` sysctl + sub-second margin
// (e.g. 4500 ms = 3 s reassembly + 1.5 s safety). `std::chrono::
// seconds{N}` converts implicitly, so TYPE_04 and any future second-
// granularity caller need no adjustment.
struct IcmpBootTiming {
    std::chrono::milliseconds initial_wait{200};
    std::chrono::milliseconds post_send_wait{0};
};

// Specification of an Ethernet-II + IPv4 + ICMP message frame. The
// builder defaults to Echo Request (type=8/code=0), but
// `icmp_type_override` / `icmp_code_override` lets callers send any
// 8-byte-header ICMP message — TYPE_16 ships an Information Request
// (type=15); future TYPE_18 will ship a Destination Unreachable
// (type=3). Fields track the wire layout so per-case stimuli can
// vary one knob (checksum corruption for TYPE_10, payload bytes for
// TYPE_08, type override for TYPE_16) while keeping the rest at
// tester-topology defaults.
//
// `src_mac` defaults to all-zeroes. AF_PACKET SOCK_RAW sends the frame
// bytes verbatim — the kernel does not overwrite the Ethernet source —
// so ICMP frames go on the wire with src_mac 00:00:00:00:00:00. Linux
// dispatches ICMP by `dst_ip` regardless of the frame-level source MAC,
// and ICMP has no cache-learning analogue of ARP §4.2.4.1, so test
// semantics are unaffected. If a future case observes DUT behaviour
// keyed on ICMP source MAC (none in the current spec), set this
// explicitly to a locally-administered literal like the ARP stimuli
// use `kTesterInjectedMac`.
struct IcmpMessageSpec {
    std::array<std::uint8_t, 6> src_mac{};            // zero by default; see header note above
    // Default to Ethernet broadcast so the pilot cases don't have to
    // thread the DUT MAC through TestConfig just to send Echo Request:
    // Linux dispatches ICMP by dst_ip regardless of the frame-level
    // Ethernet destination on veth pairs, and a zero-MAC default was
    // silently dropped by the kernel before the stimulus reached the
    // DUT. `net.ipv4.icmp_echo_ignore_broadcasts` gates IP-broadcast
    // destinations (255.255.255.255 / subnet broadcast) only, not
    // Eth-broadcast frames whose IP dst is a unicast host address.
    std::array<std::uint8_t, 6> dst_mac = kEthBroadcast;
    std::uint32_t src_ip = 0;                         // tester IP, NBO
    std::uint32_t dst_ip = 0;                         // DUT iface IP, NBO
    std::uint8_t  ttl    = 64;               // RFC 1122 §3.2.1.7 default
    std::uint16_t ip_id  = 0x4242;           // IP Identification (arbitrary, per-boot)
    std::uint16_t echo_id  = kIcmpEchoId;
    std::uint16_t echo_seq = kIcmpEchoSeq;

    // If true, flip one bit of the ICMP checksum after computing it.
    // Used by §4.3.3.2 TYPE_10 to send a malformed Echo Request; the
    // DUT's kernel drops bad-checksum ICMP silently per RFC 1122.
    bool corrupt_icmp_checksum = false;

    // Replace the ICMP Type / Code bytes written into the outgoing
    // frame. Unset keeps Type=8 / Code=0 (Echo Request) per the
    // pilot default. §4.3.3.2 TYPE_16 uses Type=15 (Information
    // Request) to test that the DUT SHOULD NOT reply with Type=16
    // per RFC 1122 §3.2.2.7. The 8-byte ICMP header layout is
    // identical across these types (identifier + sequence in the
    // rest-of-header slots), so the same builder serves both.
    // Checksum is recomputed over the effective Type/Code, so the
    // resulting frame carries a valid checksum for whichever type
    // is wired.
    std::optional<std::uint8_t> icmp_type_override;
    std::optional<std::uint8_t> icmp_code_override;

    // If true, flip one bit of the IPv4 header checksum after computing
    // it. Used by §4.4.4.2 CHECKSUM_02 to assert DUT's receive-side IP
    // checksum discard path (RFC 1122 §3.2.1.2). Parallels
    // `corrupt_icmp_checksum` above; both applied post-compute so the
    // underlying header bytes are otherwise well-formed.
    bool corrupt_ip_checksum = false;

    // Per-field overrides for IPv4 header bytes the standard compute
    // path would otherwise fill with the canonical value. Unset keeps
    // the default (Version=4, IHL=5, total_length computed from payload
    // size, Protocol=1 ICMP). Overrides are applied BEFORE checksum
    // computation so the resulting header carries a valid checksum
    // over the overridden bytes — §4.4.4.1 HEADER_02 / HEADER_08 /
    // HEADER_09 and §4.4.4.4 VERSION_04 need this so the DUT's drop
    // reason is the header-field invariant being tested, not a
    // checksum mismatch masking it.
    //
    // `ip_protocol_override` carries an IPv4 Protocol the DUT has no
    // L4 handler for — §4.3.3.2 TYPE_18 uses it to stimulate an ICMP
    // Destination Unreachable / Protocol Unreachable reply per
    // RFC 1122 §3.2.2.1. The ICMP body bytes below are still emitted
    // because that's what the builder produces today; the DUT drops
    // the packet at IP-layer protocol lookup before any L4 parsing,
    // so body shape is irrelevant to the test semantic.
    std::optional<std::uint8_t>  version_override;       // replaces byte[0] high nibble
    std::optional<std::uint8_t>  ihl_override;           // replaces byte[0] low nibble
    std::optional<std::uint16_t> total_length_override;  // replaces bytes[2..3]
    std::optional<std::uint8_t>  ip_protocol_override;   // replaces byte[9]

    // IPv4 options to inject between the fixed 20 B header and the
    // ICMP body. Raw option bytes — the caller encodes per RFC 791.
    // Builder appends EOL (0x00) padding so the options segment is
    // 4-byte aligned, recomputes IHL = (20 + options_len + padding) / 4
    // and total_length accordingly, and includes options + padding in
    // the IPv4 header checksum. §4.3.3.2 TYPE_05 / §4.3.3.1 ERROR_04
    // use `kIcmpv4TimestampOptionMalformed` (8 B, already aligned →
    // IHL=7). Empty default (no options) keeps IHL=5 for all other
    // callers; `DefaultSpecLeavesOverrideFieldsUnset` pins that the
    // empty-options path does not drift.
    std::vector<std::uint8_t> ip_options;

    // IPv4 fragmentation knobs. §4.3.3.1 ERROR_02/03 + §4.3.3.2 TYPE_04
    // stimuli are the sole consumers; every other §4.3/§4.4 case uses
    // the defaults (MF=0, offset=0) which emit a non-fragmented
    // datagram. `fragment_offset` is in 8-octet units per RFC 791 §3.1
    // (13-bit field, max 8191 = 65528 octets). The builder encodes
    // byte[6] = (MF << 5) | ((offset >> 8) & 0x1F) and byte[7] =
    // offset & 0xFF, preserving the reserved+DF bits as 0 — the
    // version / IHL / total_length override knobs above exercise the
    // other invariants independently.
    bool          more_fragments  = false;
    std::uint16_t fragment_offset = 0;

    // Replaces the builder's ICMP header + payload synthesis path.
    // When non-empty, the bytes are placed directly into the IP
    // payload slot (after the 20 B header + options + padding), no
    // ICMP checksum is computed, and `payload_data` / `payload_len` /
    // `echo_id` / `echo_seq` / `icmp_type_override` /
    // `icmp_code_override` / `corrupt_icmp_checksum` are ignored. Sole
    // consumer is §4.3.3.1 ERROR_03's frag-1 and §4.3.3.2 TYPE_04's
    // sole fragment: each carries a slice of the "constructed ICMP
    // packet" with no ICMP header of its own — that header lives
    // (notionally) in frag 0, and the DUT's options parser gates on
    // fragment_offset != 0 without ever reaching the ICMP layer, so
    // a checksumless payload is exactly what the wire requires. Empty
    // default preserves the ICMP-synthesis path for every other
    // caller.
    std::vector<std::uint8_t> raw_ip_payload;

    // Payload bytes. Empty for TYPE_09 / TYPE_10, 27 B for TYPE_08's
    // spec literal `kIcmpv4EchoPayloadType08`. Caller owns the storage.
    const std::uint8_t* payload_data = nullptr;
    std::uint32_t       payload_len  = 0;

    // §4.3.3.2 TYPE_11 / TYPE_12 — RFC 792 p17 ICMP Timestamp Request
    // body. When `icmp_type_override == 13` the builder emits a 20 B
    // Timestamp Request body (8 B header + 3 × 4 B timestamps) instead
    // of the 8 B Echo Request body. `payload_data` / `payload_len` /
    // `corrupt_icmp_checksum` are reused for the Timestamp body; the
    // three slots below carry the wire values. RFC 792 p17 sets
    // Receive / Transmit to zero on the request side and lets the
    // responder fill them with its own clock readings, so defaults
    // mirror that — only `timestamp_originate` is meaningful for the
    // Tester. Single-sourced via `kIcmpTimestampOriginate` so the
    // SCXML pass-guard literal matches the stimulus byte-for-byte.
    std::uint32_t timestamp_originate = 0;
    std::uint32_t timestamp_receive   = 0;
    std::uint32_t timestamp_transmit  = 0;
};

// Build an Ethernet-II + IPv4 + ICMP message frame from `spec`.
// Frame size depends on `payload_len` — base is 14 B Ethernet + 20 B
// IPv4 (no options) + 8 B ICMP header = 42 B, plus payload. IPv4 and
// ICMP checksums are computed per RFC 1071 one's-complement sum; the
// builder does not zero-pad odd-length payloads (callers pass
// even-length data in the pilot cases). ICMP Type/Code default to
// Echo Request (8/0); override via `spec.icmp_type_override` /
// `spec.icmp_code_override` for Information Request, Destination
// Unreachable, etc.
std::vector<std::uint8_t> buildIcmpMessage(const IcmpMessageSpec &spec);

// High-level TESTER boot-time emit of one ICMP message used by §4.3
// cases. Sleeps `initial_wait`, then builds and injects `spec`. The
// DUT's reaction (reply presence/absence per spec row) is observed
// by the SCXML guards.
//
// Blocks for `timing.initial_wait`. Returns 0 on success or a negative
// sentinel from `sendRawEthernet`.
int emitIcmpMessage(std::string_view iface,
                    const IcmpMessageSpec &spec,
                    const IcmpBootTiming &timing = {});

}  // namespace tc8::stimulus
