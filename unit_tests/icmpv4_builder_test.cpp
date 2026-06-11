#include <array>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#include "sce_integration/icmpv4_captured.h"
#include "stimulus/icmpv4_builder.h"

namespace tc8::stimulus {
namespace {

// 172.16.0.1 in network byte order (inet_pton encoding on LE host):
// 0xAC 0x10 0x00 0x01 → uint32 0x010010AC. Same convention as
// arp_builder_test — if smoke-test topology changes, both tests need
// to flip together.
constexpr std::uint32_t kTesterIpBe = 0x010010AC;
constexpr std::uint32_t kDutIpBe    = 0x020010AC;
constexpr std::array<std::uint8_t, 6> kDstMac{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};

IcmpMessageSpec makeBaseSpec() {
    IcmpMessageSpec s{};
    s.dst_mac = kDstMac;
    s.src_ip  = kTesterIpBe;
    s.dst_ip  = kDutIpBe;
    // echo_id / echo_seq default to kIcmpEchoId / kIcmpEchoSeq via the
    // struct's in-class initialisers.
    return s;
}

// RFC 1071 one's-complement checksum re-implementation, used here only
// to independently verify the builder's IPv4/ICMP checksums land on
// bytes a conformant receiver would accept.
std::uint16_t checksumRef(const std::uint8_t *data, std::size_t len) {
    std::uint32_t sum = 0;
    std::size_t i = 0;
    for (; i + 1 < len; i += 2) {
        sum += static_cast<std::uint32_t>((data[i] << 8) | data[i + 1]);
    }
    if (i < len) {
        sum += static_cast<std::uint32_t>(data[i]) << 8;
    }
    while ((sum >> 16) != 0U) {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }
    return static_cast<std::uint16_t>(~sum & 0xFFFFU);
}

TEST(BuildIcmpMessage, EmptyPayloadSizeIs42Bytes) {
    // 14 Eth + 20 IPv4 + 8 ICMP = 42. Mirror of ARP's size invariant
    // test so future rewrites that silently change header geometry fail
    // the gate immediately.
    const auto b = buildIcmpMessage(makeBaseSpec());
    EXPECT_EQ(b.size(), 42u);
}

TEST(BuildIcmpMessage, PayloadAppendedAfterIcmpHeader) {
    auto spec = makeBaseSpec();
    constexpr std::string_view kPayload = "ECU NETWORK VALIDATION TEST";
    spec.payload_data = reinterpret_cast<const std::uint8_t *>(kPayload.data());
    spec.payload_len  = static_cast<std::uint32_t>(kPayload.size());

    const auto b = buildIcmpMessage(spec);
    // Header total = 14 Eth + 20 IP + 8 ICMP = 42; payload follows.
    ASSERT_EQ(b.size(), 42u + kPayload.size());
    EXPECT_EQ(std::memcmp(b.data() + 42, kPayload.data(), kPayload.size()), 0);
}

TEST(BuildIcmpMessage, EthernetHeaderAndEtherType) {
    const auto b = buildIcmpMessage(makeBaseSpec());
    ASSERT_GE(b.size(), 14u);
    for (int i = 0; i < 6; ++i) {
        EXPECT_EQ(b[static_cast<std::size_t>(i)], kDstMac[static_cast<std::size_t>(i)]) << "eth_dst[" << i << "]";
    }
    // Ethertype = IPv4 (0x0800).
    EXPECT_EQ(b[12], 0x08);
    EXPECT_EQ(b[13], 0x00);
}

TEST(BuildIcmpMessage, Ipv4HeaderShape) {
    const auto b = buildIcmpMessage(makeBaseSpec());
    ASSERT_GE(b.size(), 34u);
    // IPv4 starts at offset 14.
    EXPECT_EQ(b[14], 0x45);                 // version=4, IHL=5
    EXPECT_EQ(b[15], 0x00);                 // DSCP/ECN
    // Total length = 20 IP + 8 ICMP = 28.
    EXPECT_EQ(b[16], 0x00);
    EXPECT_EQ(b[17], 28);
    // Flags/Fragment = 0.
    EXPECT_EQ(b[20], 0x00);
    EXPECT_EQ(b[21], 0x00);
    // TTL = 64 (default).
    EXPECT_EQ(b[22], 64);
    // Protocol = ICMP (0x01).
    EXPECT_EQ(b[23], 0x01);
    // Source IP at [26..29] — NBO byte layout equals the inet_pton
    // result (0xAC, 0x10, 0x00, 0x01 for 172.16.0.1).
    EXPECT_EQ(b[26], 0xAC);
    EXPECT_EQ(b[27], 0x10);
    EXPECT_EQ(b[28], 0x00);
    EXPECT_EQ(b[29], 0x01);
    // Destination IP at [30..33] = 172.16.0.2.
    EXPECT_EQ(b[30], 0xAC);
    EXPECT_EQ(b[31], 0x10);
    EXPECT_EQ(b[32], 0x00);
    EXPECT_EQ(b[33], 0x02);
}

TEST(BuildIcmpMessage, IcmpHeaderEchoesIdAndSeq) {
    const auto b = buildIcmpMessage(makeBaseSpec());
    ASSERT_GE(b.size(), 42u);
    // ICMP starts at offset 34.
    EXPECT_EQ(b[34], 8);  // type = Echo Request
    EXPECT_EQ(b[35], 0);  // code
    // Identifier at [38..39] — big-endian kIcmpEchoId (0x1234 by default).
    EXPECT_EQ(b[38], 0x12);
    EXPECT_EQ(b[39], 0x34);
    // Sequence at [40..41] — 0x5678 by default.
    EXPECT_EQ(b[40], 0x56);
    EXPECT_EQ(b[41], 0x78);
}

TEST(BuildIcmpMessage, Ipv4ChecksumIsValidForValidFrame) {
    // RFC 1071: running the one's-complement sum across the header
    // (including the checksum field in its final-computed position)
    // returns 0. Any non-zero result means the builder produced a
    // header a conformant receiver would reject.
    const auto b = buildIcmpMessage(makeBaseSpec());
    ASSERT_GE(b.size(), 34u);
    EXPECT_EQ(checksumRef(b.data() + 14, 20), 0u);
}

TEST(BuildIcmpMessage, IcmpChecksumIsValidForValidFrame) {
    const auto b = buildIcmpMessage(makeBaseSpec());
    ASSERT_GE(b.size(), 42u);
    // ICMP checksum covers the ICMP header + payload; no pseudo-header
    // (unlike UDP/TCP). Reference sum over [34..end) must be zero.
    EXPECT_EQ(checksumRef(b.data() + 34, b.size() - 34), 0u);
}

TEST(BuildIcmpMessage, CorruptFlagProducesNonZeroIcmpChecksum) {
    auto spec = makeBaseSpec();
    spec.corrupt_icmp_checksum = true;
    const auto b = buildIcmpMessage(spec);
    ASSERT_GE(b.size(), 42u);
    // Corrupted frame's running-sum over the ICMP region must be
    // non-zero — that's exactly what the DUT kernel uses to reject
    // the frame in §4.3.3.2 TYPE_10.
    EXPECT_NE(checksumRef(b.data() + 34, b.size() - 34), 0u);
}

TEST(FillIcmpv4CapturedFromFrame, PayloadSnapshotCopiesBytes) {
    // Round-trip: build a frame, pull the payload pointer out by hand,
    // feed it through the fill helper, assert the snapshot matches.
    // Guards against future changes where snapshot_len drifts from the
    // actual copy size (e.g. off-by-one on kMaxPayloadSnapshot).
    constexpr std::string_view kPayload{"ECU NETWORK VALIDATION TEST"};
    ::tc8::Icmpv4Frame f{};
    f.type = 0;
    f.code = 0;
    f.rest_of_header = (static_cast<std::uint32_t>(0x1234U) << 16) | 0x5678U;
    f.payload_data = reinterpret_cast<const std::uint8_t *>(kPayload.data());
    f.payload_len  = static_cast<std::uint32_t>(kPayload.size());

    ::tc8::Icmpv4Captured c{};
    ::tc8::fillIcmpv4CapturedFromFrame(c, f);

    EXPECT_EQ(c.type, 0);
    EXPECT_EQ(c.echo_id, 0x1234);
    EXPECT_EQ(c.echo_seq, 0x5678);
    EXPECT_EQ(c.payload_snapshot_len, kPayload.size());
    EXPECT_EQ(std::memcmp(c.payload_snapshot.data(), kPayload.data(), kPayload.size()), 0);
    EXPECT_TRUE(c.payload_equals(::tc8::kIcmpv4EchoPayloadType08));
}

TEST(PayloadEquals, ExactMatchReturnsTrue) {
    // The SCXML guard for §4.3.3.2 TYPE_08 routes through this method.
    // A silent break here would false-pass the case, so the shape (len
    // match + byte memcmp) is pinned independently of the fill helper.
    ::tc8::Icmpv4Captured c{};
    c.payload_snapshot_len = static_cast<std::uint32_t>(::tc8::kIcmpv4EchoPayloadType08.size());
    std::memcpy(c.payload_snapshot.data(),
                ::tc8::kIcmpv4EchoPayloadType08.data(),
                ::tc8::kIcmpv4EchoPayloadType08.size());
    EXPECT_TRUE(c.payload_equals(::tc8::kIcmpv4EchoPayloadType08));
}

TEST(PayloadEquals, LengthMismatchReturnsFalse) {
    ::tc8::Icmpv4Captured c{};
    constexpr std::string_view kRef{"ECU NETWORK VALIDATION TEST"};
    // Populate 26 bytes — one short — and the method must say NO even
    // though every byte covered so far matches. Guards against a
    // future refactor that forgets the length check and memcmps a
    // shorter buffer.
    c.payload_snapshot_len = 26;
    std::memcpy(c.payload_snapshot.data(), kRef.data(), 26);
    EXPECT_FALSE(c.payload_equals(kRef));
}

TEST(PayloadEquals, ByteFlipReturnsFalse) {
    // One-byte flip at a middle offset must fail — exactly the
    // discrimination property the spec requires ("received in the echo
    // message must be returned in the echo reply"). If this test ever
    // passes the method has silently regressed to an always-true stub.
    ::tc8::Icmpv4Captured c{};
    c.payload_snapshot_len = static_cast<std::uint32_t>(::tc8::kIcmpv4EchoPayloadType08.size());
    std::memcpy(c.payload_snapshot.data(),
                ::tc8::kIcmpv4EchoPayloadType08.data(),
                ::tc8::kIcmpv4EchoPayloadType08.size());
    c.payload_snapshot[10] = static_cast<std::uint8_t>(c.payload_snapshot[10] ^ 0x01U);
    EXPECT_FALSE(c.payload_equals(::tc8::kIcmpv4EchoPayloadType08));
}

TEST(BuildIcmpMessage, VersionOverrideReplacesHighNibbleButKeepsIhl) {
    // §4.4.4.4 VERSION_04 — wire Version != 4 while IHL stays 5 so the
    // DUT's drop reason is the version check, not a header-length
    // artefact. Mirror of the IHL override shape in the low nibble.
    auto spec = makeBaseSpec();
    spec.version_override = 6u;
    const auto b = buildIcmpMessage(spec);
    ASSERT_GE(b.size(), 34u);
    EXPECT_EQ(b[14], 0x65U);  // Version=6 (high nibble) | IHL=5 (low nibble)
}

TEST(BuildIcmpMessage, VersionOverrideKeepsValidChecksum) {
    // Override applied before checksum computation so the frame remains
    // self-consistent — VERSION_04 tests the DUT's version-based drop
    // reason, not a checksum artefact masking it.
    auto spec = makeBaseSpec();
    spec.version_override = 6u;
    const auto b = buildIcmpMessage(spec);
    ASSERT_GE(b.size(), 34u);
    EXPECT_EQ(checksumRef(b.data() + 14, 20), 0u);
}

TEST(BuildIcmpMessage, VersionAndIhlOverrideComposeIndependently) {
    // Independence check: both nibbles of byte[0] can be driven
    // separately. Guards against a future rewrite that collapses the
    // two override paths and clobbers one with the other.
    auto spec = makeBaseSpec();
    spec.version_override = 6u;
    spec.ihl_override     = 13u;
    const auto b = buildIcmpMessage(spec);
    ASSERT_GE(b.size(), 34u);
    EXPECT_EQ(b[14], 0x6DU);  // Version=6 | IHL=13
}

TEST(BuildIcmpMessage, IhlOverrideReplacesLowNibbleButKeepsVersion) {
    // §4.4.4.1 HEADER_02 / HEADER_08 need IHL != 5 while the wire still
    // claims Version=4. The override must replace the low nibble only.
    auto spec = makeBaseSpec();
    spec.ihl_override = 13u;
    const auto b = buildIcmpMessage(spec);
    ASSERT_GE(b.size(), 34u);
    EXPECT_EQ(b[14], 0x4DU);  // Version=4 (high nibble) | IHL=13 (low nibble)
}

TEST(BuildIcmpMessage, IhlOverrideKeepsValidChecksum) {
    // Override applied before checksum computation so the frame remains
    // self-consistent — HEADER_02/08 test the DUT's IHL-based drop
    // reason, not a checksum artefact masking it.
    auto spec = makeBaseSpec();
    spec.ihl_override = 4u;
    const auto b = buildIcmpMessage(spec);
    ASSERT_GE(b.size(), 34u);
    EXPECT_EQ(checksumRef(b.data() + 14, 20), 0u);
}

TEST(BuildIcmpMessage, TotalLengthOverrideReplacesBytes2And3) {
    auto spec = makeBaseSpec();
    spec.total_length_override = 48u;
    const auto b = buildIcmpMessage(spec);
    ASSERT_GE(b.size(), 34u);
    EXPECT_EQ(b[16], 0x00U);
    EXPECT_EQ(b[17], 48U);
    // Actual frame size unchanged — the wire field lies about payload
    // length; that IS the §4.4.4.1 HEADER_09 stimulus.
    EXPECT_EQ(b.size(), 42u);
}

TEST(BuildIcmpMessage, TotalLengthOverrideKeepsValidChecksum) {
    auto spec = makeBaseSpec();
    spec.total_length_override = 48u;
    const auto b = buildIcmpMessage(spec);
    ASSERT_GE(b.size(), 34u);
    EXPECT_EQ(checksumRef(b.data() + 14, 20), 0u);
}

TEST(BuildIcmpMessage, CorruptIpChecksumProducesNonZeroSum) {
    // §4.4.4.2 CHECKSUM_02 — XOR-flipped checksum must fail the RFC 1071
    // validation a conformant receiver runs. Mirror of the
    // `corrupt_icmp_checksum` regression test.
    auto spec = makeBaseSpec();
    spec.corrupt_ip_checksum = true;
    const auto b = buildIcmpMessage(spec);
    ASSERT_GE(b.size(), 34u);
    EXPECT_NE(checksumRef(b.data() + 14, 20), 0u);
}

TEST(BuildIcmpMessage, CorruptIpChecksumLeavesIcmpChecksumValid) {
    // Independence check: flipping the IP checksum must not bleed into
    // the ICMP checksum (they're computed over disjoint regions with
    // separate zero-placeholders). Protects against a future rewrite
    // that collapses both computations into one pass and accidentally
    // corrupts both regions together.
    auto spec = makeBaseSpec();
    spec.corrupt_ip_checksum = true;
    const auto b = buildIcmpMessage(spec);
    ASSERT_GE(b.size(), 42u);
    EXPECT_EQ(checksumRef(b.data() + 34, b.size() - 34), 0u);
}

TEST(BuildIcmpMessage, DefaultSpecLeavesOverrideFieldsUnset) {
    // Regression guard: default-constructed spec must NOT trigger any
    // override codepath, otherwise the pilot cases silently pick up
    // malformed frames. Version / IHL / total_length stay canonical.
    const auto b = buildIcmpMessage(IcmpMessageSpec{});
    ASSERT_GE(b.size(), 34u);
    EXPECT_EQ(b[14], 0x45U);   // Version=4, IHL=5
    EXPECT_EQ(b[16], 0x00U);   // total_length high byte
    EXPECT_EQ(b[17], 28U);     // total_length low byte (20 IP + 8 ICMP)
    EXPECT_EQ(checksumRef(b.data() + 14, 20), 0u);
}

TEST(BuildIcmpMessage, DstMacDefaultsToEthBroadcast) {
    // Regression guard for the zero-init / kernel-drop bug fixed on
    // 2026-04-22: with `dst_mac{}` as the struct default the kernel
    // silently dropped the frame (all-zero eth_dst is not a valid L2
    // address), and all three pilots failed "no_echo_reply_within_
    // listen_window". Broadcast default lets Linux dispatch by dst_ip
    // without needing TestConfig to thread the DUT MAC through.
    IcmpMessageSpec spec{};
    spec.src_ip = kTesterIpBe;
    spec.dst_ip = kDutIpBe;
    const auto b = buildIcmpMessage(spec);
    ASSERT_GE(b.size(), 6u);
    for (int i = 0; i < 6; ++i) {
        EXPECT_EQ(b[static_cast<std::size_t>(i)], 0xFFU)
            << "eth_dst[" << i << "] — a zero default silently breaks the smoke test";
    }
}

TEST(BuildIcmpMessage, IcmpTypeOverrideReplacesTypeByte) {
    // §4.3.3.2 TYPE_16 — tester sends an Information Request (type=15)
    // via the override knob. The ICMP header's first byte (offset 14
    // Eth + 20 IPv4 = 34) must carry the overridden value.
    auto spec = makeBaseSpec();
    spec.icmp_type_override = static_cast<std::uint8_t>(15);
    const auto b = buildIcmpMessage(spec);
    ASSERT_GE(b.size(), 36u);
    EXPECT_EQ(b[34], 15U);
    EXPECT_EQ(b[35], 0U);  // code unchanged
}

TEST(BuildIcmpMessage, IcmpTypeOverrideKeepsValidChecksum) {
    // Checksum is computed after the type byte is written, so an
    // Information Request still carries a valid ICMP checksum — the
    // DUT's kernel-side validation would pass; the SHOULD-NOT-reply
    // behavior under test is purely at the type-dispatch layer.
    auto spec = makeBaseSpec();
    spec.icmp_type_override = static_cast<std::uint8_t>(15);
    const auto b = buildIcmpMessage(spec);
    ASSERT_GE(b.size(), 42u);
    EXPECT_EQ(checksumRef(b.data() + 34, b.size() - 34), 0u);
}

TEST(BuildIcmpMessage, IcmpCodeOverrideReplacesCodeByte) {
    auto spec = makeBaseSpec();
    spec.icmp_type_override = static_cast<std::uint8_t>(3);  // Destination Unreachable
    spec.icmp_code_override = static_cast<std::uint8_t>(2);  // Protocol Unreachable
    const auto b = buildIcmpMessage(spec);
    ASSERT_GE(b.size(), 36u);
    EXPECT_EQ(b[34], 3U);
    EXPECT_EQ(b[35], 2U);
}

TEST(BuildIcmpMessage, DefaultSpecHasEchoRequestTypeAndCode) {
    // Default unset override must leave Type=8 / Code=0 — the pilot
    // cases rely on this to send canonical Echo Requests without
    // wiring any override explicitly.
    const auto b = buildIcmpMessage(IcmpMessageSpec{});
    ASSERT_GE(b.size(), 36u);
    EXPECT_EQ(b[34], 8U);
    EXPECT_EQ(b[35], 0U);
}

TEST(BuildIcmpMessage, IpProtocolOverrideReplacesProtocolByte) {
    // §4.3.3.2 TYPE_18 — tester injects a packet whose IPv4 Protocol
    // byte (offset 14 Eth + 9 = 23) has no L4 handler on the DUT. 253
    // is the RFC 3692 experimental protocol number; any unassigned
    // value would work, but 253 is explicitly reserved for testing.
    auto spec = makeBaseSpec();
    spec.ip_protocol_override = static_cast<std::uint8_t>(253);
    const auto b = buildIcmpMessage(spec);
    ASSERT_GE(b.size(), 24u);
    EXPECT_EQ(b[23], 253U);
}

TEST(BuildIcmpMessage, IpProtocolOverrideKeepsValidIpChecksum) {
    // Checksum is computed after the protocol byte is overwritten, so
    // the resulting IPv4 header stays internally consistent. Protects
    // the TYPE_18 stimulus against false drops on IP-layer checksum
    // mismatch — the DUT must drop on the Protocol lookup, not on a
    // corrupted header that masks the actual invariant under test.
    auto spec = makeBaseSpec();
    spec.ip_protocol_override = static_cast<std::uint8_t>(253);
    const auto b = buildIcmpMessage(spec);
    ASSERT_GE(b.size(), 34u);
    EXPECT_EQ(checksumRef(b.data() + 14, 20), 0u);
}

TEST(BuildIcmpMessage, DefaultSpecHasIcmpProtocolByte) {
    // Regression guard: default spec leaves the IPv4 Protocol byte at
    // 1 (ICMP). Without this, the pilot cases would silently start
    // shipping frames under some other protocol and the DUT would
    // never run ICMP handlers.
    const auto b = buildIcmpMessage(IcmpMessageSpec{});
    ASSERT_GE(b.size(), 24u);
    EXPECT_EQ(b[23], 1U);
}

TEST(BuildIcmpMessage, DefaultSpecHasIhlFiveAndNoOptions) {
    // Regression guard: ip_options defaults to empty, so IHL stays 5
    // and the header is the canonical 20 B. All §4.3/§4.4 cases
    // predating TYPE_05/ERROR_04 depend on this.
    const auto b = buildIcmpMessage(IcmpMessageSpec{});
    ASSERT_GE(b.size(), 34u);
    EXPECT_EQ(b[14] & 0x0FU, 5U);    // IHL nibble
    EXPECT_EQ(b[17], 28U);           // total_length = 20 IP + 8 ICMP
    EXPECT_EQ(b.size(), 42u);        // 14 Eth + 20 IP + 8 ICMP
}

TEST(BuildIcmpMessage, TimestampOptionMalformedProducesIhlSeven) {
    // §4.3.3.2 TYPE_05 / §4.3.3.1 ERROR_04 — injecting the 8 B
    // malformed Internet Timestamp option bumps the IPv4 header to
    // 28 B (IHL=7). Options length is already 4-aligned, so the
    // builder adds zero EOL padding. total_length covers IP (28) +
    // ICMP body (8).
    auto spec = makeBaseSpec();
    spec.ip_options.assign(kIcmpv4TimestampOptionMalformed.begin(),
                           kIcmpv4TimestampOptionMalformed.end());
    const auto b = buildIcmpMessage(spec);
    ASSERT_GE(b.size(), 42u);
    EXPECT_EQ(b[14] & 0x0FU, 7U);   // IHL nibble = 7 (28 / 4)
    EXPECT_EQ(b[14] & 0xF0U, 0x40U);// Version still 4
    EXPECT_EQ(b[16], 0x00U);
    EXPECT_EQ(b[17], 36U);          // 28 IP + 8 ICMP
    EXPECT_EQ(b.size(), 14u + 28u + 8u);
    // Malformed length byte (byte 1 of option = raw value 10) lands at
    // IPv4 offset 21 (14 Eth + 20 fixed + 1 index). The literal on the
    // wire must match kIcmpv4TimestampOptionMalformed exactly —
    // anything else silently reshapes the stimulus the DUT sees.
    for (std::size_t i = 0; i < kIcmpv4TimestampOptionMalformed.size(); ++i) {
        EXPECT_EQ(b[14 + 20 + i], kIcmpv4TimestampOptionMalformed[i])
            << "option byte " << i;
    }
}

TEST(BuildIcmpMessage, TimestampOptionMalformedKeepsValidIpChecksum) {
    // Checksum path covers options + padding. A conformant receiver
    // that parses IHL correctly and sums the full header must land on
    // zero; if the options bytes were not included in the sum, the
    // frame would fail checksum validation and the DUT would drop
    // for the wrong reason (masking the parameter-problem semantic
    // under test).
    auto spec = makeBaseSpec();
    spec.ip_options.assign(kIcmpv4TimestampOptionMalformed.begin(),
                           kIcmpv4TimestampOptionMalformed.end());
    const auto b = buildIcmpMessage(spec);
    ASSERT_GE(b.size(), 42u);
    EXPECT_EQ(checksumRef(b.data() + 14, 28), 0u);
}

TEST(BuildIcmpMessage, UnalignedOptionsGetEolPadding) {
    // Options segment must be 4-byte aligned in the IPv4 header. A
    // 3-byte option forces 1 EOL (0x00) byte of padding → 4 B options
    // segment → IHL=6. Independence check: the caller doesn't have
    // to pre-pad, the builder does it. EOL bytes land at the tail of
    // the options segment, right before the ICMP header.
    auto spec = makeBaseSpec();
    spec.ip_options = {0x01, 0x01, 0x01};  // 3 × No-Op (RFC 791 type 1)
    const auto b = buildIcmpMessage(spec);
    ASSERT_GE(b.size(), 42u);
    EXPECT_EQ(b[14] & 0x0FU, 6U);       // IHL = 6 (24 / 4)
    EXPECT_EQ(b[17], 32U);              // 24 IP + 8 ICMP
    EXPECT_EQ(b[14 + 20 + 0], 0x01U);   // No-Op
    EXPECT_EQ(b[14 + 20 + 1], 0x01U);
    EXPECT_EQ(b[14 + 20 + 2], 0x01U);
    EXPECT_EQ(b[14 + 20 + 3], 0x00U);   // EOL pad
    EXPECT_EQ(checksumRef(b.data() + 14, 24), 0u);
}

TEST(BuildIcmpMessage, DefaultSpecLeavesFragmentFieldsZero) {
    // Regression guard: the fragment-flags byte pair at IPv4 offset
    // 6..7 must stay 0x00 0x00 when neither `more_fragments` nor
    // `fragment_offset` is set. A silent drift here would change the
    // IP header shape for every §4.3/§4.4 caller.
    const auto b = buildIcmpMessage(IcmpMessageSpec{});
    ASSERT_GE(b.size(), 34u);
    EXPECT_EQ(b[14 + 6], 0x00U);
    EXPECT_EQ(b[14 + 7], 0x00U);
}

TEST(BuildIcmpMessage, MoreFragmentsOnlySetsMfBit) {
    // §4.3.3.1 ERROR_02 — MF=1 on a standalone fragment 0, offset=0.
    // Only bit 5 of byte[6] must flip to 1; all other flag/offset
    // bits stay 0. Anything else would bleed into the DF or offset
    // semantics and the DUT would parse the packet differently.
    auto spec = makeBaseSpec();
    spec.more_fragments = true;
    const auto b = buildIcmpMessage(spec);
    ASSERT_GE(b.size(), 34u);
    EXPECT_EQ(b[14 + 6], 0x20U);
    EXPECT_EQ(b[14 + 7], 0x00U);
}

TEST(BuildIcmpMessage, FragmentOffsetOnlyEncodesAcrossByte6and7) {
    // Offset=100 in 8-octet units → high-bit value 0, low byte 100.
    // Covers the offset>=256 low-byte-only boundary as well: the
    // offset<256 case stays entirely in byte[7], and the MF bit in
    // byte[6] remains 0.
    auto spec = makeBaseSpec();
    spec.fragment_offset = 100U;
    const auto b = buildIcmpMessage(spec);
    ASSERT_GE(b.size(), 34u);
    EXPECT_EQ(b[14 + 6], 0x00U);
    EXPECT_EQ(b[14 + 7], 100U);
}

TEST(BuildIcmpMessage, MoreFragmentsAndOffsetComposeInByte6) {
    // Typical MTU-sized offset: 1480 payload octets / 8 = 185. Fits
    // into byte[7] (< 256), so byte[6] carries MF alone. Guards
    // against a future refactor that collapses MF and offset into one
    // expression and clobbers one with the other.
    auto spec = makeBaseSpec();
    spec.more_fragments  = true;
    spec.fragment_offset = 185U;
    const auto b = buildIcmpMessage(spec);
    ASSERT_GE(b.size(), 34u);
    EXPECT_EQ(b[14 + 6], 0x20U);
    EXPECT_EQ(b[14 + 7], 185U);
}

TEST(BuildIcmpMessage, FragmentAndOptionsComposeIndependently) {
    // Cross-knob composition: MF=1 + timestamp options together,
    // which is the exact shape of §4.3.3.1 ERROR_02's wire stimulus.
    // IHL must still reflect options (=7 for the 8 B malformed
    // timestamp), MF must land in byte[6], and the IP checksum must
    // cover the full header including options + padding.
    auto spec = makeBaseSpec();
    spec.more_fragments = true;
    spec.ip_options.assign(kIcmpv4TimestampOptionMalformed.begin(),
                           kIcmpv4TimestampOptionMalformed.end());
    const auto b = buildIcmpMessage(spec);
    ASSERT_GE(b.size(), 14u + 28u + 8u);
    EXPECT_EQ(b[14] & 0x0FU, 7U);        // IHL still reflects options
    EXPECT_EQ(b[14 + 6], 0x20U);         // MF=1
    EXPECT_EQ(b[14 + 7], 0x00U);         // offset=0
    // Independent checksum validation — options + fragment flags on
    // the same frame must not corrupt the IP checksum.
    EXPECT_EQ(checksumRef(b.data() + 14, 28), 0u);
}

TEST(BuildIcmpMessage, RawIpPayloadReplacesIcmpSynthesis) {
    // §4.3.3.1 ERROR_03 frag 1 / §4.3.3.2 TYPE_04 — caller supplies
    // IP-layer payload bytes directly. Builder must not prepend an
    // ICMP header, must not compute an ICMP checksum, and must size
    // total_length to include only the raw bytes (no 8 B ICMP header
    // add-on).
    auto spec = makeBaseSpec();
    const std::array<std::uint8_t, 8> kRaw{0xA1, 0xA2, 0xA3, 0xA4,
                                           0xA5, 0xA6, 0xA7, 0xA8};
    spec.raw_ip_payload.assign(kRaw.begin(), kRaw.end());
    const auto b = buildIcmpMessage(spec);
    // 14 Eth + 20 IP + 8 raw = 42.
    EXPECT_EQ(b.size(), 42u);
    // total_length covers IP (20) + raw payload (8) = 28; same value
    // the default Echo Request path would emit, but here reached via
    // the raw path.
    EXPECT_EQ(b[16], 0x00U);
    EXPECT_EQ(b[17], 28U);
    // Payload bytes land directly after the IP header — not shifted
    // by an 8 B ICMP header. The sentinel byte pattern would be
    // overwritten with ICMP header bytes if synthesis ran.
    for (std::size_t i = 0; i < kRaw.size(); ++i) {
        EXPECT_EQ(b[14 + 20 + i], kRaw[i]) << "raw payload byte " << i;
    }
    // IP checksum path still runs (header-only, same computation as
    // non-raw). No ICMP checksum is expected or computed.
    EXPECT_EQ(checksumRef(b.data() + 14, 20), 0u);
}

TEST(BuildIcmpMessage, TimestampOptionLen12HasIhlEight) {
    // §4.3.3.1 ERROR_03 frag-0 literal: 12 B option → 20 B fixed +
    // 12 B options = 32 B header, IHL=8. Length field declares 12 on
    // the wire (byte 1 of option = 0x0C); the option itself is well-
    // formed (length=12, pointer=9, one 4 B timestamp slot filled
    // under flag=0 "timestamps only" mode).
    auto spec = makeBaseSpec();
    spec.ip_options.assign(kIcmpv4TimestampOptionLen12.begin(),
                           kIcmpv4TimestampOptionLen12.end());
    const auto b = buildIcmpMessage(spec);
    ASSERT_GE(b.size(), 14u + 32u + 8u);
    EXPECT_EQ(b[14] & 0x0FU, 8U);        // IHL = 8 (32 / 4)
    EXPECT_EQ(b[14] & 0xF0U, 0x40U);     // Version still 4
    EXPECT_EQ(b[17], 40U);                // 32 IP + 8 ICMP
    EXPECT_EQ(b[14 + 20 + 1], 0x0CU);    // option length byte on wire
    EXPECT_EQ(b[14 + 20 + 2], 0x09U);    // pointer byte on wire
    EXPECT_EQ(checksumRef(b.data() + 14, 32), 0u);
}

TEST(FillIcmpv4CapturedFromFrame, ParameterProblemPointerExtractedFromMsb) {
    // §4.3.3.1 ERROR_02 — DUT's Parameter Problem (type=12) carries
    // Pointer in byte[0] of the 4-byte rest-of-header slot, which
    // corresponds to bits [31..24] of the `rest_of_header` uint32
    // (big-endian wire interpretation). Fill helper must extract that
    // byte without touching the echo_id/echo_seq halves the test
    // would otherwise reinterpret.
    ::tc8::Icmpv4Frame f{};
    f.type = 12;
    f.code = 0;
    // Simulated wire: byte[0..3] of rest-of-header = {22, 0, 0, 0}.
    // As a big-endian uint32 this is 22 << 24 = 0x16000000.
    f.rest_of_header = static_cast<std::uint32_t>(22) << 24;

    ::tc8::Icmpv4Captured c{};
    ::tc8::fillIcmpv4CapturedFromFrame(c, f);

    EXPECT_EQ(c.type, 12U);
    EXPECT_EQ(c.icmp_pointer, 22U);
    // echo_id / echo_seq are spurious reinterpretations for non-Echo
    // types and aren't asserted here — SCXML guards for Parameter
    // Problem read `icmp_pointer`, not the Echo slots.
}

TEST(BuildIcmpMessage, TimestampRequestRoutesToTwentyByteBody) {
    // §4.3.3.2 TYPE_11 / TYPE_12 — when icmp_type_override == 13, the
    // builder emits a 20 B Timestamp Request body (8 B header + 12 B
    // timestamps) instead of the 8 B Echo Request body. Frame size =
    // 14 Eth + 20 IPv4 + 20 ICMP = 54. Total length field reflects
    // IP (20) + ICMP (20) = 40.
    auto spec = makeBaseSpec();
    spec.icmp_type_override = static_cast<std::uint8_t>(13);
    spec.timestamp_originate = 0x12345678U;
    const auto b = buildIcmpMessage(spec);
    ASSERT_EQ(b.size(), 14u + 20u + 20u);
    EXPECT_EQ(b[34], 13U);   // type = Timestamp Request
    EXPECT_EQ(b[35], 0U);    // code
    EXPECT_EQ(b[16], 0x00U);
    EXPECT_EQ(b[17], 40U);   // total_length
}

TEST(BuildIcmpMessage, TimestampRequestOriginateBeBytesAtOffset42) {
    // Originate Timestamp at IPv4 offset 22 (after 8 B ICMP header
    // 14..21) → frame offset 14+22 = 36 + 6 = wait: 14 Eth + 20 IP +
    // 8 ICMP-header = 42. Originate is the first 4 B of the timestamp
    // section, so it lands at frame offset 42..45. RFC 792 wire order
    // is big-endian per "network byte order" convention.
    auto spec = makeBaseSpec();
    spec.icmp_type_override = static_cast<std::uint8_t>(13);
    spec.timestamp_originate = 0x12345678U;
    const auto b = buildIcmpMessage(spec);
    ASSERT_GE(b.size(), 46u);
    EXPECT_EQ(b[42], 0x12U);
    EXPECT_EQ(b[43], 0x34U);
    EXPECT_EQ(b[44], 0x56U);
    EXPECT_EQ(b[45], 0x78U);
}

TEST(BuildIcmpMessage, TimestampRequestReceiveAndTransmitDefaultZero) {
    // RFC 792 p17 contract: Tester sets Receive / Transmit to zero on
    // the request side; the responder fills them with its own clock
    // readings on the reply. Builder must zero-fill those slots when
    // the spec leaves them at default.
    auto spec = makeBaseSpec();
    spec.icmp_type_override = static_cast<std::uint8_t>(13);
    spec.timestamp_originate = 0x12345678U;
    const auto b = buildIcmpMessage(spec);
    ASSERT_GE(b.size(), 54u);
    // Receive at frame offset 46..49.
    for (std::size_t i = 46; i < 50; ++i) EXPECT_EQ(b[i], 0x00U) << "recv byte " << (i - 46);
    // Transmit at frame offset 50..53.
    for (std::size_t i = 50; i < 54; ++i) EXPECT_EQ(b[i], 0x00U) << "xmit byte " << (i - 50);
}

TEST(BuildIcmpMessage, TimestampRequestChecksumIsValidForValidFrame) {
    // RFC 1071 sum across the full 20 B ICMP region must be zero.
    auto spec = makeBaseSpec();
    spec.icmp_type_override = static_cast<std::uint8_t>(13);
    spec.timestamp_originate = 0x12345678U;
    const auto b = buildIcmpMessage(spec);
    ASSERT_GE(b.size(), 54u);
    EXPECT_EQ(checksumRef(b.data() + 34, b.size() - 34), 0u);
}

TEST(BuildIcmpMessage, TimestampRequestPreservesEchoIdAndSeq) {
    // RFC 792 p17 — Identifier and Sequence Number occupy the same
    // wire positions as in the Echo body. §4.3.3.2 TYPE_12 checks
    // that the DUT echoes them; the builder must place the default
    // kIcmpEchoId / kIcmpEchoSeq at the canonical offsets so the SCXML
    // guard's `expected.echo_id` / `expected.echo_seq` comparison
    // is well-defined for the Timestamp message too.
    auto spec = makeBaseSpec();
    spec.icmp_type_override = static_cast<std::uint8_t>(13);
    spec.timestamp_originate = 0x12345678U;
    const auto b = buildIcmpMessage(spec);
    ASSERT_GE(b.size(), 42u);
    EXPECT_EQ(b[38], 0x12U);  // id hi
    EXPECT_EQ(b[39], 0x34U);  // id lo
    EXPECT_EQ(b[40], 0x56U);  // seq hi
    EXPECT_EQ(b[41], 0x78U);  // seq lo
}

TEST(FillIcmpv4CapturedFromFrame, TimestampSlotsCopiedVerbatim) {
    // Captured copy mirrors the dissector-decoded semantic uint32s —
    // host-order RFC 792 "ms since midnight UT" values. The dissector
    // is responsible for the libtins endian fixup; the fill helper
    // forwards verbatim. SCXML guards compare against host-order
    // literals (kIcmpTimestampOriginate), so the Captured field
    // shape must preserve that invariant.
    ::tc8::Icmpv4Frame f{};
    f.type = 14;
    f.originate_timestamp = 0x12345678U;
    f.receive_timestamp   = 0x030B16C3U;
    f.transmit_timestamp  = 0x030B16C4U;

    ::tc8::Icmpv4Captured c{};
    ::tc8::fillIcmpv4CapturedFromFrame(c, f);

    EXPECT_EQ(c.originate_timestamp, 0x12345678U);
    EXPECT_EQ(c.receive_timestamp,   0x030B16C3U);
    EXPECT_EQ(c.transmit_timestamp,  0x030B16C4U);
}

TEST(FillIcmpv4CapturedFromFrame, NonTimestampTypeLeavesSlotsZero) {
    // Dissector narrows the timestamp copy to type=13/14, so frames of
    // any other type land at default 0. Pin that the captured fill
    // helper does not synthesize values from `rest_of_header` — those
    // bytes carry distinct semantics for non-Timestamp types and a
    // silent reinterpretation would corrupt SCXML guards in cases
    // that don't read the timestamp slots.
    ::tc8::Icmpv4Frame f{};
    f.type = 0;  // Echo Reply
    f.originate_timestamp = 0;
    f.receive_timestamp   = 0;
    f.transmit_timestamp  = 0;

    ::tc8::Icmpv4Captured c{};
    ::tc8::fillIcmpv4CapturedFromFrame(c, f);

    EXPECT_EQ(c.originate_timestamp, 0U);
    EXPECT_EQ(c.receive_timestamp,   0U);
    EXPECT_EQ(c.transmit_timestamp,  0U);
}

TEST(FillIcmpv4CapturedFromFrame, PayloadLongerThanSnapshotIsTruncated) {
    // If a future ICMP case observes a payload > kMaxPayloadSnapshot,
    // the captured copy should truncate rather than overflow the array.
    // payload_len keeps the wire-side length so guards can notice the
    // difference.
    std::vector<std::uint8_t> big(::tc8::Icmpv4Captured::kMaxPayloadSnapshot + 16, 0xAB);
    ::tc8::Icmpv4Frame f{};
    f.payload_data = big.data();
    f.payload_len  = static_cast<std::uint32_t>(big.size());

    ::tc8::Icmpv4Captured c{};
    ::tc8::fillIcmpv4CapturedFromFrame(c, f);

    EXPECT_EQ(c.payload_len, big.size());
    EXPECT_EQ(c.payload_snapshot_len, ::tc8::Icmpv4Captured::kMaxPayloadSnapshot);
    EXPECT_EQ(c.payload_snapshot.front(), 0xABU);
    EXPECT_EQ(c.payload_snapshot.back(),  0xABU);
}

}  // namespace
}  // namespace tc8::stimulus
