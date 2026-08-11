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

// --- Run-level predicates: the claim an absence-based verdict rests on ------
//
// A pass decided by an absence ("the DUT did not send X in the window") is only
// supported if the run observed the WHOLE window. These pin that the third state
// — unmeasured — can never masquerade as a clean capture, which is the exact way
// a false PASS would slip back in.

std::vector<tc8::CaptureStats> src(bool available, std::uint32_t ring, std::uint32_t ifd = 0) {
    tc8::CaptureStats s{};
    s.iface = "veth-tester";
    s.available = available;
    s.frames_received = 1000;
    s.frames_dropped_ring = ring;
    s.frames_dropped_iface = ifd;
    return {s};
}

TEST(CaptureStatsRunLevel, MeasuredAndCleanIsProvenComplete) {
    EXPECT_TRUE(tc8::captureProvenComplete(src(/*available=*/true, /*ring=*/0)));
    EXPECT_FALSE(tc8::anySourceLostFrames(src(true, 0)));
    EXPECT_TRUE(tc8::everySourceMeasured(src(true, 0)));
}

TEST(CaptureStatsRunLevel, ProvenLossIsNotComplete) {
    EXPECT_FALSE(tc8::captureProvenComplete(src(true, /*ring=*/114)));
    EXPECT_TRUE(tc8::anySourceLostFrames(src(true, 114)));
}

TEST(CaptureStatsRunLevel, IfaceDropAloneIsNotComplete) {
    EXPECT_FALSE(tc8::captureProvenComplete(src(true, /*ring=*/0, /*ifd=*/3)));
    EXPECT_TRUE(tc8::anySourceLostFrames(src(true, 0, 3)));
}

// THE tri-state guard: an unmeasured source must not read as a clean one.
// `lostFrames()` is false here — correctly, it did not PROVE loss — so a rule
// written on `lostFrames()` alone would call this capture complete and let the
// absence-based pass stand on evidence it never had.
TEST(CaptureStatsRunLevel, UnknownIsNotProvenComplete) {
    EXPECT_FALSE(tc8::captureProvenComplete(src(/*available=*/false, /*ring=*/0)));
    EXPECT_FALSE(tc8::anySourceLostFrames(src(false, 0)));  // unknown != lost...
    EXPECT_FALSE(tc8::everySourceMeasured(src(false, 0)));  // ...and != measured
}

// No source reporting at all is an absence of evidence, not evidence of a clean
// capture — the same reason the `available` flag exists.
TEST(CaptureStatsRunLevel, NoSourcesIsNotProvenComplete) {
    EXPECT_FALSE(tc8::captureProvenComplete({}));
    EXPECT_FALSE(tc8::everySourceMeasured({}));
}

// A multi-source run (a second broadcast domain folded into one stream) is only
// complete when EVERY source was: loss on either one is a hole in the window.
TEST(CaptureStatsRunLevel, OneLossySourceSpoilsTheRun) {
    std::vector<tc8::CaptureStats> two = src(true, 0);
    tc8::CaptureStats secondary{};
    secondary.iface = "veth-tester2";
    secondary.available = true;
    secondary.frames_dropped_ring = 7;
    two.push_back(secondary);

    EXPECT_TRUE(tc8::anySourceLostFrames(two));
    EXPECT_FALSE(tc8::captureProvenComplete(two));
}

TEST(CaptureStatsRunLevel, OneUnmeasuredSourceSpoilsTheRun) {
    std::vector<tc8::CaptureStats> two = src(true, 0);
    tc8::CaptureStats secondary{};
    secondary.iface = "veth-tester2";
    secondary.available = false;  // could not report
    two.push_back(secondary);

    EXPECT_FALSE(tc8::everySourceMeasured(two));
    EXPECT_FALSE(tc8::captureProvenComplete(two));
}

// --- Multicast delivery: the completeness half with no counter of its own ----
//
// The counters above see loss only AFTER a frame reaches the interface. A frame
// an upstream snooping bridge pruned reaches nothing, so it is dropped by no
// ring and truncated by no snaplen — the state these pin is a source that looks
// PERFECTLY clean by every other measure and still did not represent the wire.
// Measured in the field: recv=0 drop=0 ifdrop=0 while the DUT was putting 18 SD
// frames on that wire.

TEST(CaptureStatsMulticast, NoGroupsNeededIsVacuouslyHeld) {
    // The overwhelming majority of cases ride no multicast. They must be
    // completely unaffected — this is what makes the new half additive rather
    // than a re-litigation of every existing verdict.
    tc8::CaptureStats s{};
    EXPECT_TRUE(s.multicastMembershipHeld());
    EXPECT_TRUE(tc8::captureProvenComplete(src(true, 0)));
    EXPECT_FALSE(tc8::anySourceMissingMulticastMembership(src(true, 0)));
}

TEST(CaptureStatsMulticast, HeldGroupsAreComplete) {
    std::vector<tc8::CaptureStats> one = src(true, 0);
    one[0].multicast_groups = {"224.244.224.245"};
    EXPECT_TRUE(one[0].multicastMembershipHeld());
    EXPECT_TRUE(tc8::captureProvenComplete(one));
}

TEST(CaptureStatsMulticast, UnheldGroupDefeatsAnOtherwisePerfectCapture) {
    // Every classic counter is clean: measured, zero ring drop, zero iface
    // drop. Before this half existed the run would have certified an absence on
    // a wire it had never established it could hear.
    std::vector<tc8::CaptureStats> one = src(/*available=*/true, /*ring=*/0, /*ifd=*/0);
    one[0].multicast_groups = {"224.244.224.245"};
    one[0].multicast_groups_failed = {"224.244.224.245: setsockopt(IP_ADD_MEMBERSHIP): No such device"};

    EXPECT_TRUE(tc8::everySourceMeasured(one));
    EXPECT_FALSE(tc8::anySourceLostFrames(one));
    EXPECT_TRUE(tc8::anySourceMissingMulticastMembership(one));
    EXPECT_FALSE(tc8::captureProvenComplete(one));
}

TEST(CaptureStatsMulticast, DecliningRecordsNeedRatherThanPretendingNoneExisted) {
    // `--no-multicast-membership` must not read as "this run needed nothing".
    // An empty group list would make the predicate vacuously true and quietly
    // restore the unsound behaviour the whole half exists to remove; the opt-out
    // instead records the groups as needed-and-unheld.
    std::vector<tc8::CaptureStats> declined = src(true, 0);
    declined[0].multicast_groups = {"224.244.224.245", "224.244.224.246"};
    declined[0].multicast_groups_failed = {"224.244.224.245: declined by --no-multicast-membership",
                                           "224.244.224.246: declined by --no-multicast-membership"};
    EXPECT_FALSE(tc8::captureProvenComplete(declined));

    std::vector<tc8::CaptureStats> pretended = src(true, 0);  // the wrong shape
    EXPECT_TRUE(tc8::captureProvenComplete(pretended));
}

TEST(CaptureStatsMulticast, OneSourceMissingItsGroupSpoilsTheRun) {
    // Same rule as loss: a second broadcast domain that cannot hear its group
    // makes the RUN's observation incomplete, not just that source's.
    std::vector<tc8::CaptureStats> two = src(true, 0);
    tc8::CaptureStats secondary{};
    secondary.iface = "veth-tester2";
    secondary.available = true;
    secondary.multicast_groups = {"224.244.224.246"};
    secondary.multicast_groups_failed = {"224.244.224.246: declined by --no-multicast-membership"};
    two.push_back(secondary);

    EXPECT_TRUE(tc8::everySourceMeasured(two));
    EXPECT_FALSE(tc8::anySourceLostFrames(two));
    EXPECT_FALSE(tc8::captureProvenComplete(two));
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
