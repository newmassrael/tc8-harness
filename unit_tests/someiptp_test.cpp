#include <chrono>
#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include "autosar/someiptp.h"

namespace tc8::someiptp {
namespace {

using ms = std::chrono::milliseconds;
using Status = Reassembler::Status;

std::uint32_t be32(const std::vector<std::uint8_t>& f, std::size_t off) {
    return (static_cast<std::uint32_t>(f[off]) << 24) | (static_cast<std::uint32_t>(f[off + 1]) << 16) |
           (static_cast<std::uint32_t>(f[off + 2]) << 8) | static_cast<std::uint32_t>(f[off + 3]);
}

MessageHeader hdr() {
    return MessageHeader{0x01010009, 0x00010005, 0x01, 0x01, 0x00, 0x00};
}

std::vector<std::uint8_t> ramp(std::size_t n) {
    std::vector<std::uint8_t> v(n);
    for (std::size_t i = 0; i < n; ++i) {
        v[i] = static_cast<std::uint8_t>(i & 0xFF);
    }
    return v;
}

// Build one on-wire SOME/IP-TP frame with an explicit offset/more flag — used to craft
// precise adversarial inputs the Segmenter would never emit. `tp_raw` overrides the TP
// word verbatim when set (to exercise reserved bits / misalignment).
std::vector<std::uint8_t> buildFrame(const MessageHeader& h, std::size_t offset, bool more,
                                     const std::vector<std::uint8_t>& data,
                                     std::uint32_t tp_raw = 0, bool use_raw = false) {
    std::vector<std::uint8_t> f;
    auto p32 = [&](std::uint32_t v) {
        f.push_back(static_cast<std::uint8_t>(v >> 24));
        f.push_back(static_cast<std::uint8_t>(v >> 16));
        f.push_back(static_cast<std::uint8_t>(v >> 8));
        f.push_back(static_cast<std::uint8_t>(v));
    };
    p32(h.message_id);
    p32(static_cast<std::uint32_t>(kLengthCoveredHeaderBytes + kTpHeaderLen + data.size()));
    p32(h.request_id);
    f.push_back(h.protocol_version);
    f.push_back(h.interface_version);
    f.push_back(static_cast<std::uint8_t>(h.message_type | kMessageTypeTpFlag));
    f.push_back(h.return_code);
    p32(use_raw ? tp_raw : (static_cast<std::uint32_t>(offset) | (more ? 1u : 0u)));
    f.insert(f.end(), data.begin(), data.end());
    return f;
}

Reassembler makeRe() { return Reassembler{1 << 20, 8, ms{1000}}; }

// ── Segmenter ──────────────────────────────────────────────────────────────

// PRS_SOMEIP §4.2.1.4 Example (Table 4.10): 5880-byte payload at max segment 1392 ->
// 5 segments, Offset-field values 0/87/174/261/348, More 1/1/1/1/0, Length 1404*4/324.
TEST(SomeipTpSegmenter, MatchesSpecExampleVectors) {
    const Segmenter seg{1392};
    const std::vector<std::uint8_t> payload = ramp(5880);
    const auto frames = seg.segment(hdr(), payload.data(), payload.size());

    ASSERT_EQ(frames.size(), 5u);
    const std::uint32_t want_off[5] = {0, 87, 174, 261, 348};   // Offset FIELD (byte offset / 16)
    const std::uint32_t want_len[5] = {1404, 1404, 1404, 1404, 324};
    for (std::size_t i = 0; i < 5; ++i) {
        EXPECT_EQ(be32(frames[i], 4), want_len[i]);             // SOME/IP Length field
        EXPECT_NE(frames[i][14] & kMessageTypeTpFlag, 0);       // Message Type TP-flag set
        const std::uint32_t tp = be32(frames[i], kSomeipHeaderLen);
        EXPECT_EQ(tp >> 4, want_off[i]);                        // Offset field (upper 28 bits)
        EXPECT_EQ(tp & 0xFu, i == 4 ? 0u : 1u);                 // Reserved 0 + More-Segments bit
    }
}

TEST(SomeipTpSegmenter, SingleSegmentWhenPayloadFits) {
    const Segmenter seg{64};
    const std::vector<std::uint8_t> payload = ramp(40);
    const auto frames = seg.segment(hdr(), payload.data(), payload.size());
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(be32(frames[0], kSomeipHeaderLen) & 1u, 0u);     // last segment
    EXPECT_EQ(frames[0].size(), kSegmentHeaderLen + 40u);
}

// The do/while exists so a zero-length payload still emits exactly one (empty) segment.
TEST(SomeipTpSegmenter, EmptyPayloadProducesOneEmptySegment) {
    const Segmenter seg{16};
    const auto frames = seg.segment(hdr(), nullptr, 0);
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(frames[0].size(), kSegmentHeaderLen);
    EXPECT_EQ(be32(frames[0], 4), kLengthCoveredHeaderBytes + kTpHeaderLen);  // Length = 12
    EXPECT_EQ(be32(frames[0], kSomeipHeaderLen) & 1u, 0u);     // More = 0
}

TEST(SomeipTpSegmenter, RejectsBadMaxSegment) {
    EXPECT_THROW(Segmenter{0}, std::invalid_argument);
    EXPECT_THROW(Segmenter{24}, std::invalid_argument);              // not a multiple of 16
    EXPECT_THROW(Segmenter{std::size_t{1} << 32}, std::invalid_argument);  // Length overflow
}

TEST(SomeipTpSegmenter, RejectsNullPayloadWithLen) {
    const Segmenter seg{16};
    EXPECT_THROW(seg.segment(hdr(), nullptr, 8), std::invalid_argument);
}

// ── Reassembler: round trips ────────────────────────────────────────────────

TEST(SomeipTpRoundTrip, MultiSegmentReassembles) {
    const Segmenter seg{1392};
    const std::vector<std::uint8_t> payload = ramp(5880);
    const auto frames = seg.segment(hdr(), payload.data(), payload.size());

    Reassembler re = makeRe();
    Reassembler::Result r;
    for (const auto& f : frames) {
        r = re.feed(f.data(), f.size());
    }
    ASSERT_EQ(r.status, Status::kComplete);
    EXPECT_EQ(r.payload, payload);
    EXPECT_EQ(r.header.message_id, hdr().message_id);
    EXPECT_EQ(r.header.request_id, hdr().request_id);
    EXPECT_EQ(r.header.message_type, 0x00);                    // TP-flag cleared on output
    EXPECT_EQ(re.pending(), 0u);                               // transfer released
}

TEST(SomeipTpRoundTrip, OutOfOrderReassembles) {
    const Segmenter seg{16};
    const std::vector<std::uint8_t> payload = ramp(40);        // 16 + 16 + 8
    const auto frames = seg.segment(hdr(), payload.data(), payload.size());
    ASSERT_EQ(frames.size(), 3u);

    Reassembler re = makeRe();
    EXPECT_EQ(re.feed(frames[2].data(), frames[2].size()).status, Status::kInProgress);
    EXPECT_EQ(re.feed(frames[0].data(), frames[0].size()).status, Status::kInProgress);
    const auto r = re.feed(frames[1].data(), frames[1].size());
    ASSERT_EQ(r.status, Status::kComplete);
    EXPECT_EQ(r.payload, payload);
}

TEST(SomeipTpRoundTrip, ConcurrentTransfersByRequestId) {
    const Segmenter seg{16};
    const std::vector<std::uint8_t> pa = ramp(24);
    const std::vector<std::uint8_t> pb = ramp(20);
    MessageHeader ha = hdr();
    MessageHeader hb = hdr();
    hb.request_id = 0x00010006;                               // different Session ID
    const auto fa = seg.segment(ha, pa.data(), pa.size());
    const auto fb = seg.segment(hb, pb.data(), pb.size());

    Reassembler re = makeRe();
    EXPECT_EQ(re.feed(fa[0].data(), fa[0].size()).status, Status::kInProgress);
    EXPECT_EQ(re.feed(fb[0].data(), fb[0].size()).status, Status::kInProgress);
    EXPECT_EQ(re.pending(), 2u);
    const auto rb = re.feed(fb[1].data(), fb[1].size());
    const auto ra = re.feed(fa[1].data(), fa[1].size());
    ASSERT_EQ(ra.status, Status::kComplete);
    ASSERT_EQ(rb.status, Status::kComplete);
    EXPECT_EQ(ra.payload, pa);
    EXPECT_EQ(rb.payload, pb);
}

// Reserved bits (1..3) and any low-4 offset bits must be ignored on decode
// (PRS_SOMEIP_00726): a single-segment message with junk reserved bits still completes.
TEST(SomeipTpRoundTrip, ReservedBitsIgnoredOnDecode) {
    const std::vector<std::uint8_t> data = ramp(16);
    // TP word: offset 0, reserved bits set (0b1110), More = 0.
    const auto f = buildFrame(hdr(), 0, false, data, 0x0000000Eu, true);
    Reassembler re = makeRe();
    const auto r = re.feed(f.data(), f.size());
    ASSERT_EQ(r.status, Status::kComplete);
    EXPECT_EQ(r.payload, data);
}

// ── Reassembler: malformed / adversarial ────────────────────────────────────

TEST(SomeipTpReassembler, RejectsMissingTpFlag) {
    auto f = buildFrame(hdr(), 0, false, ramp(16));
    f[14] = static_cast<std::uint8_t>(f[14] & ~kMessageTypeTpFlag);
    Reassembler re = makeRe();
    EXPECT_EQ(re.feed(f.data(), f.size()).status, Status::kError);
}

TEST(SomeipTpReassembler, RejectsUnalignedNonLastSegment) {
    const auto f = buildFrame(hdr(), 0, true, ramp(20));  // non-last, 20 bytes (not /16)
    Reassembler re = makeRe();
    EXPECT_EQ(re.feed(f.data(), f.size()).status, Status::kError);
}

TEST(SomeipTpReassembler, RejectsZeroLengthNonLast) {
    const auto f = buildFrame(hdr(), 0, true, {});  // more=1, seg_len=0
    Reassembler re = makeRe();
    EXPECT_EQ(re.feed(f.data(), f.size()).status, Status::kError);
}

TEST(SomeipTpReassembler, RejectsTruncatedHeader) {
    std::vector<std::uint8_t> tiny(kSegmentHeaderLen - 1, 0x00);
    Reassembler re = makeRe();
    EXPECT_EQ(re.feed(tiny.data(), tiny.size()).status, Status::kError);
    EXPECT_EQ(re.feed(nullptr, 0).status, Status::kError);
    EXPECT_EQ(re.pending(), 0u);
}

TEST(SomeipTpReassembler, RejectsOverflowAndLeavesNoPending) {
    const Segmenter seg{16};
    const auto frames = seg.segment(hdr(), ramp(64).data(), 64);
    Reassembler re{32, 8, ms{1000}};                          // cap below the 64-byte message
    Status last = Status::kInProgress;
    for (const auto& fr : frames) {
        last = re.feed(fr.data(), fr.size()).status;
        if (last == Status::kError) break;
    }
    EXPECT_EQ(last, Status::kError);
    EXPECT_EQ(re.pending(), 0u);
}

// PRS_SOMEIP_00731: segments must agree on the shared header; a mid-transfer segment
// with a different protocol version is malformed and drops the transfer.
TEST(SomeipTpReassembler, RejectsHeaderMismatch) {
    const auto s0 = buildFrame(hdr(), 0, true, ramp(16));
    MessageHeader spoof = hdr();
    spoof.protocol_version = 0x02;
    const auto s1 = buildFrame(spoof, 16, false, ramp(16));
    Reassembler re = makeRe();
    EXPECT_EQ(re.feed(s0.data(), s0.size()).status, Status::kInProgress);
    EXPECT_EQ(re.feed(s1.data(), s1.size()).status, Status::kError);
    EXPECT_EQ(re.pending(), 0u);
}

TEST(SomeipTpReassembler, DuplicateSegmentIsIdempotent) {
    const Segmenter seg{16};
    const auto frames = seg.segment(hdr(), ramp(32).data(), 32);  // 2 segments
    Reassembler re = makeRe();
    EXPECT_EQ(re.feed(frames[0].data(), frames[0].size()).status, Status::kInProgress);
    EXPECT_EQ(re.feed(frames[0].data(), frames[0].size()).status, Status::kInProgress);  // dup
    EXPECT_EQ(re.feed(frames[1].data(), frames[1].size()).status, Status::kComplete);
}

TEST(SomeipTpReassembler, RejectsConflictingLengthAtOffset) {
    const auto a = buildFrame(hdr(), 0, true, ramp(16));
    const auto b = buildFrame(hdr(), 0, true, ramp(32));  // same offset, different length
    Reassembler re = makeRe();
    EXPECT_EQ(re.feed(a.data(), a.size()).status, Status::kInProgress);
    EXPECT_EQ(re.feed(b.data(), b.size()).status, Status::kError);
    EXPECT_EQ(re.pending(), 0u);
}

// Regression (review bug 1): a duplicate offset with the More flag flipped must not be
// accepted as a dup — it would truncate/hijack the transfer.
TEST(SomeipTpReassembler, RejectsFlippedMoreAtOffset) {
    const auto s0 = buildFrame(hdr(), 0, true, ramp(16));    // more = 1
    const auto forged = buildFrame(hdr(), 0, false, ramp(16));  // same off/len, more = 0
    Reassembler re = makeRe();
    EXPECT_EQ(re.feed(s0.data(), s0.size()).status, Status::kInProgress);
    EXPECT_EQ(re.feed(forged.data(), forged.size()).status, Status::kError);
    EXPECT_EQ(re.pending(), 0u);
}

// Regression (review bug 2): a second, inconsistent "last" segment must not clobber the
// declared total into an uncompletable state.
TEST(SomeipTpReassembler, RejectsSecondInconsistentLast) {
    const auto last_a = buildFrame(hdr(), 32, false, ramp(16));  // total = 48
    const auto last_b = buildFrame(hdr(), 0, false, ramp(16));   // claims total = 16
    Reassembler re = makeRe();
    EXPECT_EQ(re.feed(last_a.data(), last_a.size()).status, Status::kInProgress);
    EXPECT_EQ(re.feed(last_b.data(), last_b.size()).status, Status::kError);
    EXPECT_EQ(re.pending(), 0u);
}

// Regression (review bug 3): a segment reaching past the declared total is rejected
// (here the stray arrives before the last segment fixes the total).
TEST(SomeipTpReassembler, RejectsSegmentBeyondTotal) {
    const auto stray = buildFrame(hdr(), 16, true, ramp(16));   // occupies [16, 32)
    const auto last = buildFrame(hdr(), 0, false, ramp(16));    // declares total = 16
    Reassembler re = makeRe();
    EXPECT_EQ(re.feed(stray.data(), stray.size()).status, Status::kInProgress);
    EXPECT_EQ(re.feed(last.data(), last.size()).status, Status::kError);
    EXPECT_EQ(re.pending(), 0u);
}

// max_concurrent bounds the number of in-flight transfers; the one past the cap is
// refused without growing the table.
TEST(SomeipTpReassembler, MaxConcurrentTransfersBounded) {
    Reassembler re{1 << 20, 2, ms{1000}};
    for (std::uint32_t i = 0; i < 2; ++i) {
        MessageHeader h = hdr();
        h.request_id = 0x00010000 + i;
        const auto s0 = buildFrame(h, 0, true, ramp(16));
        EXPECT_EQ(re.feed(s0.data(), s0.size()).status, Status::kInProgress);
    }
    EXPECT_EQ(re.pending(), 2u);
    MessageHeader h3 = hdr();
    h3.request_id = 0x00010099;
    const auto over = buildFrame(h3, 0, true, ramp(16));
    EXPECT_EQ(re.feed(over.data(), over.size()).status, Status::kError);  // refused
    EXPECT_EQ(re.pending(), 2u);                                          // not grown
}

// ── Reassembler: timeout ────────────────────────────────────────────────────

TEST(SomeipTpReassembler, IncompleteTransferTimesOut) {
    const Segmenter seg{16};
    const auto frames = seg.segment(hdr(), ramp(40).data(), 40);

    Reassembler re{1 << 20, 8, ms{500}};
    int dropped = 0;
    re.onTimeout = [&](const MessageHeader& h) {
        EXPECT_EQ(h.request_id, hdr().request_id);
        ++dropped;
    };

    EXPECT_EQ(re.feed(frames[0].data(), frames[0].size()).status, Status::kInProgress);
    EXPECT_EQ(re.mainFunction(ms{300}), 0u);                  // not yet expired
    EXPECT_EQ(re.feed(frames[1].data(), frames[1].size()).status, Status::kInProgress);
    EXPECT_EQ(re.mainFunction(ms{300}), 0u);                  // feed reset the age
    EXPECT_EQ(re.mainFunction(ms{500}), 1u);                  // now past timeout
    EXPECT_EQ(dropped, 1);
    EXPECT_EQ(re.pending(), 0u);
}

}  // namespace
}  // namespace tc8::someiptp
