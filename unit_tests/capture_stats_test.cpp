// Pins the capture-loss accounting (tc8::CaptureStats + PcapSource::stats()).
//
// A verdict that measures an inter-frame gap anchors on the first frame of a
// kind it PROCESSED and treats it as the first frame the DUT SENT. Those are the
// same frame only while the capture is lossless — so a run that dropped frames
// can measure a gap short by an unknown amount and fail a healthy DUT, leaving
// no trace of its own cause. These counters are that missing evidence.
//
// The load-bearing property is the TRI-STATE, not the numbers: "complete",
// "lossy", and "not measured" must stay three distinct answers. Collapsing
// "unknown" into a zero would rebuild the exact blind spot the counters exist to
// remove, so that is what these tests guard.

#include <filesystem>

#include <gtest/gtest.h>

#include "capture/pcap_source.h"
#include "tc8/capture_stats.h"

namespace {

TEST(CaptureStats, DefaultIsNotMeasuredRatherThanClean) {
    const tc8::CaptureStats s{};
    EXPECT_FALSE(s.available);
    // The whole point: a default-constructed record must not read as "the
    // capture was fine". It has not measured anything yet.
    EXPECT_FALSE(s.lostFrames());
}

TEST(CaptureStats, UnknownNeverReportsLoss) {
    tc8::CaptureStats s{};
    s.available = false;
    // Counters left over / meaningless on an unavailable source must not be
    // promoted into a loss claim either — unknown is unknown in both directions.
    s.frames_dropped_ring = 99;
    s.frames_dropped_iface = 99;
    EXPECT_FALSE(s.lostFrames());
}

TEST(CaptureStats, MeasuredAndCleanIsNotLoss) {
    tc8::CaptureStats s{};
    s.available = true;
    s.frames_received = 1234;
    EXPECT_FALSE(s.lostFrames());
}

TEST(CaptureStats, RingDropIsLoss) {
    tc8::CaptureStats s{};
    s.available = true;
    s.frames_received = 1234;
    s.frames_dropped_ring = 1;  // the reader fell behind — the anchor may slide
    EXPECT_TRUE(s.lostFrames());
}

TEST(CaptureStats, IfaceDropIsLoss) {
    tc8::CaptureStats s{};
    s.available = true;
    s.frames_received = 1234;
    s.frames_dropped_iface = 1;  // dropped before libpcap ever saw it
    EXPECT_TRUE(s.lostFrames());
}

// A savefile has no ring to overflow and no interface, so libpcap cannot report
// counters for it. `stats()` must say "not measured" rather than hand back a
// fabricated 0/0/0 that a reader would take for a clean capture. Offline is the
// one branch reachable without privileges, so it is the real-code-path guard
// here; the live counters are exercised by an actual run (see the `capture :`
// teardown line).
TEST(PcapSourceStats, OfflineSourceReportsUnavailableNotZero) {
    const std::filesystem::path fixture =
        std::filesystem::path(TC8_FIXTURE_DIR) / "decode_pcap_sample.pcap";
    ASSERT_TRUE(std::filesystem::exists(fixture)) << fixture;

    auto src = tc8::capture::PcapSource::openOffline(fixture);
    ASSERT_NE(src, nullptr);
    ASSERT_TRUE(src->isOffline());

    const tc8::CaptureStats s = src->stats();
    EXPECT_FALSE(s.available);
    EXPECT_FALSE(s.lostFrames());
    // Still attributed, so a reader knows WHICH source could not be measured.
    EXPECT_NE(s.iface.find("decode_pcap_sample.pcap"), std::string::npos);
}

}  // namespace
