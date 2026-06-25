#include <chrono>
#include <cstdint>
#include <numeric>
#include <vector>

#include <gtest/gtest.h>

#include "autosar/someiptp.h"

namespace tc8::someiptp {
namespace {

using ms = std::chrono::milliseconds;

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

// PRS_SOMEIP §4.2.1.4 Example (Table 4.10): a 5880-byte payload at max segment 1392
// yields 5 segments with Offset-field values 0/87/174/261/348, More-Segments
// 1/1/1/1/0, and Length 1404/1404/1404/1404/324.
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
        EXPECT_EQ(tp & 1u, i == 4 ? 0u : 1u);                   // More-Segments flag
    }
}

// A payload that fits in one segment yields a single frame with More-Segments = 0.
TEST(SomeipTpSegmenter, SingleSegmentWhenPayloadFits) {
    const Segmenter seg{64};
    const std::vector<std::uint8_t> payload = ramp(40);
    const auto frames = seg.segment(hdr(), payload.data(), payload.size());
    ASSERT_EQ(frames.size(), 1u);
    EXPECT_EQ(be32(frames[0], kSomeipHeaderLen) & 1u, 0u);     // last segment
    EXPECT_EQ(frames[0].size(), kSegmentHeaderLen + 40u);
}

TEST(SomeipTpSegmenter, RejectsBadMaxSegment) {
    EXPECT_THROW(Segmenter{0}, std::invalid_argument);
    EXPECT_THROW(Segmenter{24}, std::invalid_argument);  // not a multiple of 16
}

// segment() -> feed() reassembles the original payload and header (TP-flag cleared).
TEST(SomeipTpRoundTrip, MultiSegmentReassembles) {
    const Segmenter seg{1392};
    const std::vector<std::uint8_t> payload = ramp(5880);
    const auto frames = seg.segment(hdr(), payload.data(), payload.size());

    Reassembler re{1 << 20, ms{1000}};
    Reassembler::Result r;
    for (const auto& f : frames) {
        r = re.feed(f.data(), f.size());
    }
    ASSERT_EQ(r.status, Reassembler::Status::kComplete);
    EXPECT_EQ(r.payload, payload);
    EXPECT_EQ(r.header.message_id, hdr().message_id);
    EXPECT_EQ(r.header.request_id, hdr().request_id);
    EXPECT_EQ(r.header.message_type, 0x00);                    // TP-flag cleared on output
    EXPECT_EQ(re.pending(), 0u);                               // transfer released
}

// Segments delivered out of order still reassemble (offset-keyed placement).
TEST(SomeipTpRoundTrip, OutOfOrderReassembles) {
    const Segmenter seg{16};
    const std::vector<std::uint8_t> payload = ramp(40);       // 16 + 16 + 8
    auto frames = seg.segment(hdr(), payload.data(), payload.size());
    ASSERT_EQ(frames.size(), 3u);

    Reassembler re{1 << 20, ms{1000}};
    EXPECT_EQ(re.feed(frames[2].data(), frames[2].size()).status, Reassembler::Status::kInProgress);
    EXPECT_EQ(re.feed(frames[0].data(), frames[0].size()).status, Reassembler::Status::kInProgress);
    const auto r = re.feed(frames[1].data(), frames[1].size());
    ASSERT_EQ(r.status, Reassembler::Status::kComplete);
    EXPECT_EQ(r.payload, payload);
}

// Two transfers with distinct Request IDs reassemble independently when interleaved.
TEST(SomeipTpRoundTrip, ConcurrentTransfersByRequestId) {
    const Segmenter seg{16};
    const std::vector<std::uint8_t> pa = ramp(24);
    const std::vector<std::uint8_t> pb = ramp(20);
    MessageHeader ha = hdr();
    MessageHeader hb = hdr();
    hb.request_id = 0x00010006;                               // different Session ID
    const auto fa = seg.segment(ha, pa.data(), pa.size());
    const auto fb = seg.segment(hb, pb.data(), pb.size());
    ASSERT_EQ(fa.size(), 2u);
    ASSERT_EQ(fb.size(), 2u);

    Reassembler re{1 << 20, ms{1000}};
    EXPECT_EQ(re.feed(fa[0].data(), fa[0].size()).status, Reassembler::Status::kInProgress);
    EXPECT_EQ(re.feed(fb[0].data(), fb[0].size()).status, Reassembler::Status::kInProgress);
    EXPECT_EQ(re.pending(), 2u);
    const auto rb = re.feed(fb[1].data(), fb[1].size());
    const auto ra = re.feed(fa[1].data(), fa[1].size());
    ASSERT_EQ(ra.status, Reassembler::Status::kComplete);
    ASSERT_EQ(rb.status, Reassembler::Status::kComplete);
    EXPECT_EQ(ra.payload, pa);
    EXPECT_EQ(rb.payload, pb);
}

// A segment without the TP-flag is not a SOME/IP-TP segment.
TEST(SomeipTpReassembler, RejectsMissingTpFlag) {
    const Segmenter seg{16};
    const std::vector<std::uint8_t> payload = ramp(16);
    auto frames = seg.segment(hdr(), payload.data(), payload.size());
    frames[0][14] = static_cast<std::uint8_t>(frames[0][14] & ~kMessageTypeTpFlag);
    Reassembler re{1 << 20, ms{1000}};
    EXPECT_EQ(re.feed(frames[0].data(), frames[0].size()).status, Reassembler::Status::kError);
}

// A non-last segment whose length is not 16-aligned is malformed (PRS_SOMEIP_00729).
TEST(SomeipTpReassembler, RejectsUnalignedNonLastSegment) {
    // Hand-build a "more" segment carrying 20 payload bytes (not a multiple of 16).
    std::vector<std::uint8_t> f(kSegmentHeaderLen + 20, 0x00);
    f[4] = 0; f[5] = 0; f[6] = 0; f[7] = static_cast<std::uint8_t>(8 + kTpHeaderLen + 20);  // Length
    f[14] = kMessageTypeTpFlag;                               // TP-flag, more set below
    f[kSomeipHeaderLen + 3] = 0x01;                           // TP word low byte: More = 1, offset 0
    Reassembler re{1 << 20, ms{1000}};
    EXPECT_EQ(re.feed(f.data(), f.size()).status, Reassembler::Status::kError);
}

// A transfer larger than max_message is rejected, not buffered without bound.
TEST(SomeipTpReassembler, RejectsOverflow) {
    const Segmenter seg{16};
    const std::vector<std::uint8_t> payload = ramp(64);
    const auto frames = seg.segment(hdr(), payload.data(), payload.size());
    Reassembler re{32, ms{1000}};                            // cap below the 64-byte message
    Reassembler::Status last = Reassembler::Status::kInProgress;
    for (const auto& fr : frames) {
        last = re.feed(fr.data(), fr.size()).status;
        if (last == Reassembler::Status::kError) break;
    }
    EXPECT_EQ(last, Reassembler::Status::kError);
    EXPECT_EQ(re.pending(), 0u);
}

// An incomplete transfer is abandoned (and reported) once it ages past the timeout.
TEST(SomeipTpReassembler, IncompleteTransferTimesOut) {
    const Segmenter seg{16};
    const std::vector<std::uint8_t> payload = ramp(40);
    const auto frames = seg.segment(hdr(), payload.data(), payload.size());

    Reassembler re{1 << 20, ms{500}};
    int dropped = 0;
    re.onTimeout = [&](const MessageHeader& h) { EXPECT_EQ(h.request_id, hdr().request_id); ++dropped; };

    EXPECT_EQ(re.feed(frames[0].data(), frames[0].size()).status, Reassembler::Status::kInProgress);
    EXPECT_EQ(re.tick(ms{300}), 0u);                          // not yet expired
    EXPECT_EQ(re.feed(frames[1].data(), frames[1].size()).status, Reassembler::Status::kInProgress);
    EXPECT_EQ(re.tick(ms{300}), 0u);                          // feed reset the age
    EXPECT_EQ(re.tick(ms{500}), 1u);                          // now past timeout
    EXPECT_EQ(dropped, 1);
    EXPECT_EQ(re.pending(), 0u);
}

// A short buffer (smaller than the fixed SOME/IP + TP header) is rejected.
TEST(SomeipTpReassembler, RejectsTruncatedHeader) {
    std::vector<std::uint8_t> tiny(kSegmentHeaderLen - 1, 0x00);
    Reassembler re{1 << 20, ms{1000}};
    EXPECT_EQ(re.feed(tiny.data(), tiny.size()).status, Reassembler::Status::kError);
    EXPECT_EQ(re.feed(nullptr, 0).status, Reassembler::Status::kError);
}

}  // namespace
}  // namespace tc8::someiptp
