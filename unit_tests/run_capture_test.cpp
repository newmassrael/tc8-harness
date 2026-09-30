// What an adopted background service sees while a stimulus awaits an observation,
// pinned through the production path: the CLI's capture pump (RunCapture), the
// real packet pipeline, and a TestRunner over a test-only state machine
// (fixtures/services_during_await.scxml), fed by a committed pcap.
//
// The contract under test is tc8/pollable_service.h's. A consumer's responder once
// anchored on its first onReadable() as "the window opened", and moved 16 verdicts
// when an await began to drain services before the window. Nothing in-tree both
// adopts a service and awaits, so without this test the behaviour that consumer
// depends on had no exerciser here at all.

#include <chrono>
#include <cstddef>
#include <memory>
#include <string_view>
#include <variant>

#include <gtest/gtest.h>

#include "capture/pcap_source.h"
#include "cli/run_capture.h"
#include "dissect/packet_pipeline.h"
#include "sce_integration/captured_frame_observer.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/stimulus_context.h"
#include "sce_integration/stimulus_observation.h"
#include "sce_integration/test_runner.h"
#include "tc8/captured_event.h"
#include "tc8/unperformed_stimulus.h"

#include "services_during_await_sm.h"

namespace {

using ServicesDuringAwaitSM = ::SCE::Generated::services_during_await::services_during_await;

// Counts what the runner gives it, standing in for a reacting responder.
class CountingService final : public ::tc8::sce::IFrameObservingService {
public:
    int pollFd() const override { return -1; }
    void onReadable() override { ++reads_; }
    void onCapturedFrame(const ::tc8::CapturedEvent &ev) override {
        if (std::holds_alternative<::tc8::ArpFrame>(ev)) {
            ++arp_frames_;
        }
    }

    int         reads() const { return reads_; }
    std::size_t arpFrames() const { return arp_frames_; }

private:
    int         reads_      = 0;
    std::size_t arp_frames_ = 0;
};

// What the stimulus saw, read by the test after kickStimulus returns.
struct Probe {
    CountingService *service              = nullptr;
    int              reads_before_await   = -1;
    int              reads_after_await    = -1;
    std::size_t      arp_seen_after_await = 0;
    bool             reply_awaited        = false;
};
Probe g_probe;

bool isArpReply(const ::tc8::CapturedEvent &ev) {
    const auto *arp = std::get_if<::tc8::ArpFrame>(&ev);
    return arp != nullptr && arp->opcode == 2;
}

class NoDutControl final : public ::tc8::sce::IDutControl {
public:
    bool probe() override { return true; }
    bool startTest() override { return true; }
    bool endTest() override { return true; }
    const char *backendName() const override { return "unit-test-none"; }
    std::uint16_t controlPort() const override { return 0; }
    ::tc8::sce::DutCapabilities capabilities() const override { return {}; }
};

}  // namespace

namespace tc8::sce {

template <>
struct TestCaseTraits<ServicesDuringAwaitSM> : ArpAnyBase<ServicesDuringAwaitSM> {
    static constexpr std::string_view kCaseId = "SERVICES_DURING_AWAIT";

    // Adopt a service, then await the DUT's ARP Reply from the start of the
    // capture: the fixture delivers its whole file on the first drain, so a cursor
    // taken now would already sit past the Reply.
    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig & /*cfg*/,
                         StimulusContext &ctx) {
        auto service = std::make_unique<CountingService>();
        g_probe.service = service.get();
        ctx.services.adoptObservingService(std::move(service));
        g_probe.reads_before_await = g_probe.service->reads();
        const auto reply = ctx.observer.awaitObservation(
            "dut_arp_reply", ObservationCursor{}, isArpReply, std::chrono::seconds(2));
        g_probe.reply_awaited        = reply.has_value();
        g_probe.reads_after_await    = g_probe.service->reads();
        g_probe.arp_seen_after_await = g_probe.service->arpFrames();
    }
};

}  // namespace tc8::sce

namespace {

TEST(RunCaptureDuringAwait, AServiceIsDrainedAndSeesFramesBeforeTheWindowOpens) {
    ::tc8::UnperformedStimulus::reset();
    g_probe = Probe{};

    auto src = ::tc8::capture::PcapSource::openOffline(TC8_FIXTURE_DIR "/decode_pcap_sample.pcap");
    ASSERT_NE(src, nullptr);
    ::tc8::sce::TestRunner<ServicesDuringAwaitSM> runner;
    ::tc8::dissect::PacketPipeline pipeline(
        [&runner](const ::tc8::CapturedEvent &ev) { runner.onCaptured(ev); });
    ::tc8::cli::RunCapture capture(*src, src->datalink(), nullptr, 0, nullptr, pipeline, runner);
    NoDutControl dut;

    runner.kickStimulus("unit-test", dut, capture);

    ASSERT_TRUE(g_probe.reply_awaited) << "the fixture's ARP Reply was never awaited";
    // Adoption alone drains nothing; the await's drains are what polled it.
    EXPECT_EQ(g_probe.reads_before_await, 0);
    EXPECT_GT(g_probe.reads_after_await, 0)
        << "the capture pump did not drain an adopted service while the stimulus "
           "awaited, which tc8/pollable_service.h says it does";
    // The fixture holds one ARP Request and one Reply; both reached the observer
    // when they were drained, before any state machine was running.
    EXPECT_EQ(g_probe.arp_seen_after_await, 2u);

    runner.start();

    // The held frames reach the machine at start(): the Reply decides the case.
    EXPECT_EQ(runner.verdict().cls, ::tc8::sce::VerdictClass::Pass) << runner.verdict().str();
    // The replay is for the machine only. An observer already saw each frame live
    // and must not be told again, or a reaction would fire twice.
    EXPECT_EQ(g_probe.service->arpFrames(), 2u);
    EXPECT_FALSE(::tc8::UnperformedStimulus::any()) << ::tc8::UnperformedStimulus::reason();
}

}  // namespace
