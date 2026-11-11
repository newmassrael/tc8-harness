// A live capture source across a link outage (needs CAP_NET_ADMIN and CAP_NET_RAW; run
// under scripts/run-netns-test.sh). RunCapture treats a dispatch that fails while the
// link is down as the outage and keeps polling the same handle. The first test pins the
// premise that makes that sound: once the link is back up, the handle delivers again
// without being reopened. The second drives the whole path a case would take: a
// stimulus bounces the capture link with bounceTesterLink and awaits a frame through
// the runner, the capture loop restores the link from its own poll and records the
// outage.
#include <arpa/inet.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <variant>
#include <vector>

#include <gtest/gtest.h>

#include "capture/pcap_source.h"
#include "cli/run_capture.h"
#include "dissect/packet_pipeline.h"
#include "netns_test_util.h"
#include "sce_integration/cases/_arp_traits_base.h"
#include "sce_integration/dut_control.h"
#include "sce_integration/stimulus_context.h"
#include "sce_integration/stimulus_observation.h"
#include "sce_integration/test_runner.h"
#include "sce_integration/tester_link.h"
#include "stimulus/arp_builder.h"
#include "tc8/link_outage_tracker.h"
#include "tc8/net/link_control.h"
#include "tc8/pollable_service.h"
#include "tc8/unperformed_stimulus.h"

#include "link_bounce_during_capture_sm.h"

namespace {

using namespace tc8::testutil;
using namespace std::chrono_literals;

std::uint32_t ipBe(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
    return htonl((static_cast<std::uint32_t>(a) << 24) | (static_cast<std::uint32_t>(b) << 16) |
                 (static_cast<std::uint32_t>(c) << 8) | d);
}

bool carriesTraffic(const char *iface) {
    const auto state = tc8::net::readLinkState(iface);
    return state.has_value() && state->admin_up && state->carrier;
}

// Send a frame from `from` until `source` delivers one, for at most `bound`.
bool deliversAFrame(tc8::capture::PcapSource &source, const char *from, std::chrono::milliseconds bound) {
    const auto frame = tc8::stimulus::buildArpRequest({0x02, 0, 0, 0, 0, 0xB0}, ipBe(172, 16, 9, 2),
                                                      ipBe(172, 16, 9, 1));
    const auto deadline = std::chrono::steady_clock::now() + bound;
    while (std::chrono::steady_clock::now() < deadline) {
        tc8::stimulus::sendRawEthernet(frame, from);
        int frames = 0;
        for (int i = 0; i < 10 && frames == 0; ++i) {
            const int n = source.dispatch(-1, [&frames](const pcap_pkthdr &, const u_char *) { ++frames; });
            if (n < 0) {
                break;  // reported below by the caller's next attempt
            }
            std::this_thread::sleep_for(10ms);
        }
        if (frames > 0) {
            return true;
        }
    }
    return false;
}

TEST(CaptureLinkOutage, TheSameHandleDeliversAgainOnceTheLinkIsBack) {
    if (!hasNetAdmin()) {
        GTEST_SKIP() << "needs CAP_NET_ADMIN (run under run-netns-test.sh)";
    }
    constexpr const char *kA = "tc8loa";  // the capture side, whose link goes down
    constexpr const char *kB = "tc8lob";  // the sender
    deleteIface(kA);
    if (!createVethPair(kA, kB)) {
        GTEST_SKIP() << "veth pair unavailable on this kernel";
    }
    ScopeExit pair_cleanup([&] { deleteIface(kA); });
    ASSERT_EQ(tc8::net::awaitCarrier(kA, true, 2s), tc8::net::CarrierWait::kReached);

    std::unique_ptr<tc8::capture::PcapSource> source = tc8::capture::PcapSource::openLive(kA);
    ASSERT_TRUE(source);
    ASSERT_EQ(source->tstampPrecision(), PCAP_TSTAMP_PRECISION_MICRO);  // ts.tv_usec is microseconds below
    ASSERT_TRUE(deliversAFrame(*source, kB, 3s)) << "no frame before the outage";

    tc8::LinkOutageTracker tracker;
    ASSERT_TRUE(tc8::net::setLinkState(kA, /*up=*/false));
    // Every frame captured from here on was captured with the link down. A frame the
    // handle reads now may still be one captured before: deliversAFrame stops at the
    // first frame it reads, and a probe it sent earlier can arrive after that and wait
    // in the buffer (measured: 1 run in 17 read one here). So a frame is judged by its
    // capture timestamp, which is on the clock libpcap stamps with, not by when it is read.
    const std::chrono::microseconds down_at = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch());
    tracker.observe(carriesTraffic(kA), 1);
    EXPECT_TRUE(tracker.down());
    // While the link is down a dispatch delivers nothing; whether libpcap reports the
    // down link as an error or as no frames, the handle must survive it.
    int frames_while_down = 0;
    int frames_from_before = 0;
    for (int i = 0; i < 5; ++i) {
        source->dispatch(-1, [&](const pcap_pkthdr &h, const u_char *) {
            const std::chrono::microseconds captured_at =
                std::chrono::seconds(h.ts.tv_sec) + std::chrono::microseconds(h.ts.tv_usec);
            ++(captured_at >= down_at ? frames_while_down : frames_from_before);
        });
        std::this_thread::sleep_for(10ms);
    }
    EXPECT_EQ(frames_while_down, 0) << frames_from_before << " frame(s) captured before the outage were read too";

    ASSERT_TRUE(tc8::net::setLinkState(kA, /*up=*/true));
    ASSERT_EQ(tc8::net::awaitCarrier(kA, true, 2s), tc8::net::CarrierWait::kReached);
    tracker.observe(carriesTraffic(kA), 2);
    EXPECT_FALSE(tracker.down());
    ASSERT_EQ(tracker.outages().size(), 1u);
    EXPECT_EQ(tracker.outages()[0].end_us, 2);

    EXPECT_TRUE(deliversAFrame(*source, kB, 3s)) << "the handle delivered nothing after the link came back";
}

using LinkBounceSM = ::SCE::Generated::link_bounce_during_capture::link_bounce_during_capture;

constexpr const char *kCaptureSide = "tc8lba";  // the tester's link, which the stimulus bounces
constexpr const char *kSenderSide = "tc8lbb";   // the peer leg, which keeps sending
constexpr auto kOutage = 300ms;

// Sends an ARP Request from the peer leg on every tick of its own timer, from the
// capture loop like any adopted service. Each Request carries its sequence number in
// its target address, and the sender keeps when each one went out, so the test can
// tell a frame sent after the outage from one the kernel still held from before it.
class SequencedArpSender final : public ::tc8::IPollableService {
public:
    explicit SequencedArpSender(std::chrono::milliseconds period)
        : fd_(::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC)) {
        itimerspec spec{};
        spec.it_value.tv_nsec = 1000000;  // first tick at once
        spec.it_interval.tv_sec = static_cast<time_t>(period.count() / 1000);
        spec.it_interval.tv_nsec = static_cast<long>((period.count() % 1000) * 1000000);
        ::timerfd_settime(fd_, 0, &spec, nullptr);
    }
    ~SequencedArpSender() override {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }
    SequencedArpSender(const SequencedArpSender &) = delete;
    SequencedArpSender &operator=(const SequencedArpSender &) = delete;

    int pollFd() const override {
        return fd_;
    }
    void onReadable() override {
        std::uint64_t expirations = 0;
        if (::read(fd_, &expirations, sizeof(expirations)) != static_cast<ssize_t>(sizeof(expirations))) {
            return;
        }
        const std::uint16_t seq = static_cast<std::uint16_t>(sent_at_.size());
        const auto frame = tc8::stimulus::buildArpRequest({0x02, 0, 0, 0, 0, 0xB1}, ipBe(172, 16, 9, 2),
                                                          ipBe(10, 0, static_cast<std::uint8_t>(seq >> 8),
                                                               static_cast<std::uint8_t>(seq & 0xFF)));
        sent_at_.push_back(std::chrono::steady_clock::now());
        // A send while the peer leg has no carrier fails; that is the outage, and the
        // sequence number is spent all the same.
        tc8::stimulus::sendRawEthernet(frame, kSenderSide);
    }

    // When Request `seq` was sent, or nullopt for a number this sender never used.
    std::optional<std::chrono::steady_clock::time_point> sentAt(std::uint16_t seq) const {
        if (seq >= sent_at_.size()) {
            return std::nullopt;
        }
        return sent_at_[seq];
    }

private:
    int fd_;
    std::vector<std::chrono::steady_clock::time_point> sent_at_;
};

std::chrono::nanoseconds processCpuTime() {
    timespec ts{};
    ::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    return std::chrono::seconds(ts.tv_sec) + std::chrono::nanoseconds(ts.tv_nsec);
}

// What the stimulus saw, read by the test after kickStimulus returns.
struct BounceProbe {
    SequencedArpSender *sender = nullptr;
    bool frame_before = false;
    bool bounced = false;
    std::chrono::nanoseconds bounce_call{};
    std::chrono::steady_clock::time_point restore_due{};
    bool frame_after = false;
    std::chrono::nanoseconds await_wall{};
    std::chrono::nanoseconds await_cpu{};
};
BounceProbe g_bounce;

std::optional<std::uint16_t> requestSeq(const ::tc8::CapturedEvent &ev) {
    const auto *arp = std::get_if<::tc8::ArpFrame>(&ev);
    if (arp == nullptr || arp->opcode != 1) {
        return std::nullopt;
    }
    const std::uint32_t target = ntohl(arp->target_proto_ip);
    if ((target >> 16) != 0x0A00) {  // 10.0.x.y: one of the sender's
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(target & 0xFFFF);
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
struct TestCaseTraits<LinkBounceSM> : ArpAnyBase<LinkBounceSM> {
    static constexpr std::string_view kCaseId = "LINK_BOUNCE_DURING_CAPTURE";

    static void stimulus(Captured & /*c*/, const ::tc8::TestConfig & /*cfg*/, StimulusContext &ctx) {
        auto sender = std::make_unique<SequencedArpSender>(20ms);
        g_bounce.sender = sender.get();
        ctx.services.adoptService(std::move(sender));
        const auto any_request = [](const ::tc8::CapturedEvent &ev) { return requestSeq(ev).has_value(); };
        g_bounce.frame_before = ctx.observer.awaitObservation("request_before_bounce", any_request, 2s).has_value();

        const auto call_began = std::chrono::steady_clock::now();
        g_bounce.bounced = bounceTesterLink(ctx, kOutage);
        const auto call_ended = std::chrono::steady_clock::now();
        g_bounce.bounce_call = call_ended - call_began;
        g_bounce.restore_due = call_ended + kOutage;

        // A Request the sender sent once the restore was due: only a capture that came
        // back through the outage can deliver one.
        const auto sent_after_outage = [](const ::tc8::CapturedEvent &ev) {
            const auto seq = requestSeq(ev);
            if (!seq) {
                return false;
            }
            const auto sent = g_bounce.sender->sentAt(*seq);
            return sent.has_value() && *sent >= g_bounce.restore_due;
        };
        const auto cpu0 = processCpuTime();
        const auto wall0 = std::chrono::steady_clock::now();
        g_bounce.frame_after =
            ctx.observer.awaitObservation("request_after_bounce", sent_after_outage, 3s).has_value();
        g_bounce.await_wall = std::chrono::steady_clock::now() - wall0;
        g_bounce.await_cpu = processCpuTime() - cpu0;
    }
};

}  // namespace tc8::sce

namespace {

TEST(CaptureLinkOutage, TheCaptureLoopGradesAcrossABounceItDidNotWaitFor) {
    if (!hasNetAdmin()) {
        GTEST_SKIP() << "needs CAP_NET_ADMIN (run under run-netns-test.sh)";
    }
    deleteIface(kCaptureSide);
    if (!createVethPair(kCaptureSide, kSenderSide)) {
        GTEST_SKIP() << "veth pair unavailable on this kernel";
    }
    ScopeExit pair_cleanup([&] { deleteIface(kCaptureSide); });
    ASSERT_EQ(tc8::net::awaitCarrier(kCaptureSide, true, 2s), tc8::net::CarrierWait::kReached);

    ::tc8::UnperformedStimulus::reset();
    g_bounce = BounceProbe{};
    std::unique_ptr<tc8::capture::PcapSource> source = tc8::capture::PcapSource::openLive(kCaptureSide);
    ASSERT_TRUE(source);
    ::tc8::sce::TestRunner<LinkBounceSM> runner;
    ::tc8::dissect::PacketPipeline pipeline([&runner](const ::tc8::CapturedEvent &ev) { runner.onCaptured(ev); });
    ::tc8::cli::RunCapture capture(*source, source->datalink(), nullptr, 0, nullptr, pipeline, runner);
    NoDutControl dut;

    runner.kickStimulus(kCaptureSide, dut, capture);

    ASSERT_TRUE(g_bounce.frame_before) << "no frame before the bounce";
    ASSERT_TRUE(g_bounce.bounced) << ::tc8::UnperformedStimulus::reason();
    // The bounce returns at once; the outage is the capture loop's to sit through.
    EXPECT_LT(g_bounce.bounce_call, 100ms);
    EXPECT_TRUE(g_bounce.frame_after) << "no frame sent after the outage reached the runner";
    EXPECT_TRUE(capture.error().empty()) << capture.error();
    // The await spanned the outage. A loop that spun on the down link's capture fd
    // would have spent about as much CPU as wall time.
    EXPECT_GE(g_bounce.await_wall, kOutage);
    EXPECT_LT(g_bounce.await_cpu * 2, g_bounce.await_wall)
        << "cpu " << g_bounce.await_cpu.count() << " ns over " << g_bounce.await_wall.count() << " ns";

    const auto &outages = capture.linkOutages(0);
    ASSERT_EQ(outages.size(), 1u);
    EXPECT_GT(outages[0].end_us, outages[0].begin_us) << "the outage was never closed";
    EXPECT_GE(outages[0].end_us - outages[0].begin_us, 200'000) << "shorter than the bounce";
    EXPECT_FALSE(::tc8::UnperformedStimulus::any()) << ::tc8::UnperformedStimulus::reason();

    runner.start();
    EXPECT_EQ(runner.verdict().cls, ::tc8::sce::VerdictClass::Pass) << runner.verdict().str();
}

}  // namespace
