// Awaiting an observation from inside a stimulus (stimulus_observation.h), and
// the owning copy of a captured event it rests on (owned_captured_event.h).
//
// The facility makes two promises and every test below is one of them: a frame
// drained early for a wait still reaches the state machine in capture order (the
// hold and its release), and a wait that is not satisfied is recorded under its
// name, never a silent fall-through (the UnperformedStimulus ledger).

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "tc8/captured_event.h"
#include "tc8/unperformed_stimulus.h"

#include "sce_integration/owned_captured_event.h"
#include "sce_integration/stimulus_observation.h"

namespace tc8::sce {
namespace {

using namespace std::chrono_literals;
using Status = ICapturePump::Status;

::tc8::CapturedEvent udpFrom(std::uint16_t src_port) {
    ::tc8::UdpFrame f{};
    f.src_port = src_port;
    return f;
}

std::uint16_t srcPortOf(const ::tc8::CapturedEvent &ev) {
    return std::get<::tc8::UdpFrame>(ev).src_port;
}

ObservationPredicate fromPort(std::uint16_t port) {
    return [port](const ::tc8::CapturedEvent &ev) {
        const auto *udp = std::get_if<::tc8::UdpFrame>(&ev);
        return udp != nullptr && udp->src_port == port;
    };
}

// Stands in for the CLI: each drain() delivers the next scripted batch into the
// observation exactly as the pipeline delivers frames to a runner that has not
// started, and time moves only when the facility waits.
class ScriptedPump final : public ICapturePump {
public:
    struct Batch {
        std::vector<::tc8::CapturedEvent> frames;
        Status status = Status::kOk;
    };

    explicit ScriptedPump(StimulusObservation &obs) : obs_(obs) {}

    void script(Batch b) {
        batches_.push_back(std::move(b));
    }

    Drained drain() override {
        ++drains;
        if (batches_.empty()) {
            return Drained{Status::kOk, 0};
        }
        Batch b = std::move(batches_.front());
        batches_.pop_front();
        for (const auto &ev : b.frames) {
            obs_.hold(ev, next_idx_++);
        }
        return Drained{b.status, b.frames.size()};
    }

    void waitForInput(std::chrono::milliseconds max) override {
        now += max;
    }

    std::chrono::steady_clock::time_point now{};
    int drains = 0;

private:
    StimulusObservation &obs_;
    std::deque<Batch> batches_;
    int next_idx_ = 0;
};

class StimulusObservationTest : public ::testing::Test {
protected:
    void SetUp() override { ::tc8::UnperformedStimulus::reset(); }
    void TearDown() override { ::tc8::UnperformedStimulus::reset(); }

    StimulusObservation obs{[this] { return pump.now; }};
    ScriptedPump pump{obs};
};

TEST_F(StimulusObservationTest, ReturnsTheFirstMatchingFrameAndHoldsEveryFrame) {
    pump.script({{udpFrom(1), udpFrom(2), udpFrom(3)}});
    obs.bindPump(&pump);

    const auto seen = obs.awaitObservation("x", ObservationCursor{}, fromPort(2), 100ms);

    ASSERT_TRUE(seen.has_value());
    EXPECT_EQ(srcPortOf(seen->view()), 2);
    // Nothing is consumed by the wait: all three frames are still owed to the
    // state machine, the one that satisfied the wait included.
    EXPECT_EQ(obs.heldCount(), 3U);
    EXPECT_FALSE(::tc8::UnperformedStimulus::any());
}

// The cursor is the arm point: a frame the DUT sent before it cannot satisfy a
// wait from it, even though the frame matches.
TEST_F(StimulusObservationTest, AFrameCapturedBeforeTheCursorDoesNotCount) {
    ::tc8::CapturedEvent before = udpFrom(7);
    std::get<::tc8::UdpFrame>(before).dst_port = 100;
    ::tc8::CapturedEvent after = udpFrom(7);
    std::get<::tc8::UdpFrame>(after).dst_port = 200;
    pump.script({{before}});  // already on the wire when the cursor is taken
    pump.script({{after}});   // sent after it
    obs.bindPump(&pump);

    const ObservationCursor from = obs.mark();
    const auto seen = obs.awaitObservation("x", from, fromPort(7), 100ms);

    ASSERT_TRUE(seen.has_value());
    EXPECT_EQ(std::get<::tc8::UdpFrame>(seen->view()).dst_port, 200);
    // The earlier frame is still held — it is owed to the state machine — it
    // just could not satisfy a wait armed after it.
    EXPECT_EQ(obs.heldCount(), 2U);
}

// Why the cursor is taken before the provoking step: a frame that arrives while
// that step is still blocking has to count, and the wait only starts after it.
TEST_F(StimulusObservationTest, AFrameArrivingBeforeTheWaitBeginsStillCounts) {
    obs.bindPump(&pump);
    const ObservationCursor from = obs.mark();          // nothing on the wire yet
    pump.script({{udpFrom(9)}});                          // the DUT answers "during" the step
    const auto seen = obs.awaitObservation("x", from, fromPort(9), 0ms);
    EXPECT_TRUE(seen.has_value()) << "a zero bound still examines what already arrived";
}

TEST_F(StimulusObservationTest, AnElapsedBoundIsRecordedUnderTheWaitsName) {
    obs.bindPump(&pump);
    const auto seen = obs.awaitObservation("dut_find_service", fromPort(1), 100ms);

    EXPECT_FALSE(seen.has_value());
    EXPECT_TRUE(::tc8::UnperformedStimulus::any());
    EXPECT_EQ(::tc8::UnperformedStimulus::reason(),
              "stimulus_dut_find_service_not_performed");
    // It waited the bound and no longer: the fake clock moved only by waits.
    EXPECT_GE(pump.now.time_since_epoch(), 100ms);
    EXPECT_LT(pump.now.time_since_epoch(), 100ms + 20ms);
}

TEST_F(StimulusObservationTest, TheEndOfAnOfflineCaptureIsNotASilentPass) {
    pump.script({{udpFrom(1)}, Status::kEndOfCapture});
    obs.bindPump(&pump);
    EXPECT_FALSE(obs.awaitObservation("x", ObservationCursor{}, fromPort(2), 1000ms));
    EXPECT_EQ(::tc8::UnperformedStimulus::reason(), "stimulus_x_not_performed");
}

TEST_F(StimulusObservationTest, AFailedCaptureIsRecorded) {
    pump.script({{}, Status::kError});
    obs.bindPump(&pump);
    EXPECT_FALSE(obs.awaitObservation("x", ObservationCursor{}, fromPort(2), 1000ms));
    EXPECT_TRUE(::tc8::UnperformedStimulus::any());
}

// An interrupted run reports error:interrupted, which outranks a precondition
// note, so the wait records nothing of its own.
TEST_F(StimulusObservationTest, AnInterruptedRunRecordsNothing) {
    pump.script({{}, Status::kStopped});
    obs.bindPump(&pump);
    EXPECT_FALSE(obs.awaitObservation("x", ObservationCursor{}, fromPort(2), 1000ms));
    EXPECT_FALSE(::tc8::UnperformedStimulus::any());
}

// The replay is the other half of the promise: frames and markers come back in
// the order they were captured, each under its own saved-pcap index.
TEST_F(StimulusObservationTest, ReleaseReplaysFramesAndMarkersInCaptureOrder) {
    obs.hold(udpFrom(1), 0);
    obs.holdMarker("ack", 1);
    obs.hold(udpFrom(2), 2);

    std::vector<std::string> order;
    obs.release([&](const StimulusObservation::Held &h) {
        if (const auto *ev = std::get_if<OwnedCapturedEvent>(&h.item)) {
            order.push_back("udp" + std::to_string(srcPortOf(ev->view())) + "@" +
                            std::to_string(h.pcap_frame_idx));
        } else {
            order.push_back(std::get<StimulusObservation::Marker>(h.item).name + "@" +
                            std::to_string(h.pcap_frame_idx));
        }
    });

    EXPECT_EQ(order, (std::vector<std::string>{"udp1@0", "ack@1", "udp2@2"}));
    EXPECT_EQ(obs.heldCount(), 0U) << "released items are not delivered twice";
}

TEST(StimulusObservationDeathTest, AWaitOutsideTheStimulusIsRefused) {
    StimulusObservation obs;  // no pump bound: the stimulus has returned
    EXPECT_DEATH((void)obs.awaitObservation("late", fromPort(1), 10ms),
                 "requested outside the stimulus");
}

// --- OwnedCapturedEvent -------------------------------------------------------

// The reason the type exists: a copy of the view keeps pointing into the
// pipeline's buffer, and after that buffer is reused the held frame still decodes
// — to the NEXT frame's bytes.
TEST(OwnedCapturedEvent, SurvivesTheBufferItWasDecodedFrom) {
    std::vector<std::uint8_t> pipeline_buffer = {0xAA, 0xBB, 0xCC};
    ::tc8::SomeIpFrame f{};
    f.payload_data = pipeline_buffer.data();
    f.payload_len = 3;

    const OwnedCapturedEvent owned{::tc8::CapturedEvent{f}};
    pipeline_buffer.assign({0x00, 0x00, 0x00});  // the next frame reuses the buffer

    const auto &held = std::get<::tc8::SomeIpFrame>(owned.view());
    ASSERT_NE(held.payload_data, pipeline_buffer.data());
    EXPECT_EQ(std::vector<std::uint8_t>(held.payload_data, held.payload_data + held.payload_len),
              (std::vector<std::uint8_t>{0xAA, 0xBB, 0xCC}));
}

TEST(OwnedCapturedEvent, OwnsBothRegionsOfATcpFrameAndSurvivesAMove) {
    std::vector<std::uint8_t> options = {2, 4, 0x05, 0xB4};
    std::vector<std::uint8_t> payload = {'h', 'i'};
    ::tc8::TcpFrame f{};
    f.options_data = options.data();
    f.options_len = 4;
    f.payload_data = payload.data();
    f.payload_len = 2;

    OwnedCapturedEvent first{::tc8::CapturedEvent{f}};
    const OwnedCapturedEvent moved{std::move(first)};
    options.assign(4, 0);
    payload.assign(2, 0);

    const auto &t = std::get<::tc8::TcpFrame>(moved.view());
    EXPECT_EQ(std::vector<std::uint8_t>(t.options_data, t.options_data + t.options_len),
              (std::vector<std::uint8_t>{2, 4, 0x05, 0xB4}));
    EXPECT_EQ(std::vector<std::uint8_t>(t.payload_data, t.payload_data + t.payload_len),
              (std::vector<std::uint8_t>{'h', 'i'}));
}

// "Absent" is an answer the frame's readers act on; owning must not turn a null
// region into an empty-but-present one.
TEST(OwnedCapturedEvent, AnAbsentRegionStaysAbsent) {
    ::tc8::UdpFrame f{};
    const OwnedCapturedEvent owned{::tc8::CapturedEvent{f}};
    EXPECT_EQ(std::get<::tc8::UdpFrame>(owned.view()).payload_data, nullptr);
}

}  // namespace
}  // namespace tc8::sce
