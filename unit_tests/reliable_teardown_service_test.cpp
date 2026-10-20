// Hermetic cover for SubscribeTcpTeardownService (sce_integration/reliable_teardown_
// service.h): the wire-driven "observe the reliable event, then tear the connection
// down" logic. It uses an INERT session (constructed on a
// non-existent interface, so it never acquires an fd), which makes applyTeardown() a
// no-op — the test exercises only the observe-count-and-fire logic, no DUT, no
// network. The wire behaviour of the teardown itself (the DUT deleting the
// subscription, and the iptables/RST mechanics) is NOT covered anywhere in-tree: it
// needs a live DUT + netns-root and is exercised only by the out-of-tree OEM cases.

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sce_integration/reliable_teardown_service.h"
#include "stimulus/endpoint.h"
#include "stimulus/subscribe_tcp_session.h"
#include "stimulus/tx_observer.h"
#include "tc8/captured_event.h"

namespace {

using tc8::sce::SubscribeTcpTeardownService;
using tc8::sce::TcpTeardownMode;
using tc8::stimulus::Endpoint;
using tc8::stimulus::SubscribeEventgroupTcpSession;

constexpr std::uint16_t kService = 0xF4E7;
constexpr std::uint16_t kEvent = 0x8003;

// A session on a non-existent interface never acquires an fd (valid()==false), so the
// driver's applyTeardown() is inert — only its frame logic runs.
std::unique_ptr<SubscribeEventgroupTcpSession> makeInertSession() {
    return std::make_unique<SubscribeEventgroupTcpSession>("tc8-no-such-if", Endpoint{});
}

tc8::CapturedEvent someipNotif(std::uint16_t service, std::uint16_t event, bool is_tcp) {
    tc8::SomeIpFrame f{};
    f.is_tcp = is_tcp;
    f.service_id = service;
    f.method_id = event;
    f.message_type = 0x02;  // NOTIFICATION
    return tc8::CapturedEvent{f};
}

TEST(SubscribeTcpTeardownService, IgnoresNonMatchingFrames) {
    SubscribeTcpTeardownService drv(makeInertSession(), kService, kEvent, /*trigger_after=*/2,
                                    TcpTeardownMode::kRefuseWithRst);
    drv.onCapturedFrame(someipNotif(kService, kEvent, /*is_tcp=*/false));  // UDP transport
    drv.onCapturedFrame(someipNotif(kService, 0x8001, /*is_tcp=*/true));   // wrong event
    drv.onCapturedFrame(someipNotif(0x1234, kEvent, /*is_tcp=*/true));     // wrong service
    drv.onCapturedFrame(tc8::CapturedEvent{tc8::UdpFrame{}});              // not SOME/IP
    EXPECT_EQ(drv.observedCount(), 0);
    EXPECT_FALSE(drv.tornDown());
}

TEST(SubscribeTcpTeardownService, FiresExactlyAfterN) {
    SubscribeTcpTeardownService drv(makeInertSession(), kService, kEvent, /*trigger_after=*/3,
                                    TcpTeardownMode::kDropIncoming);
    drv.onCapturedFrame(someipNotif(kService, kEvent, /*is_tcp=*/true));
    drv.onCapturedFrame(someipNotif(kService, kEvent, /*is_tcp=*/true));
    EXPECT_FALSE(drv.tornDown());
    EXPECT_EQ(drv.observedCount(), 2);

    drv.onCapturedFrame(someipNotif(kService, kEvent, /*is_tcp=*/true));
    EXPECT_TRUE(drv.tornDown());
    EXPECT_EQ(drv.observedCount(), 3);

    // No re-count or re-fire once torn down.
    drv.onCapturedFrame(someipNotif(kService, kEvent, /*is_tcp=*/true));
    EXPECT_EQ(drv.observedCount(), 3);
}

// The teardown fires on the capture thread, where a case's TxSpecStep does not reach, so
// the step is the service's own: the RST it puts on the wire is reported under it, and
// nothing outside the teardown inherits it.
TEST(SubscribeTcpTeardownService, TheTeardownReportsUnderItsOwnStep) {
    struct Capture final : tc8::stimulus::ITxObserver {
        std::vector<std::string> transports;
        std::vector<int>         steps;
        void onTx(const tc8::stimulus::TxEvent &ev) override {
            transports.emplace_back(ev.transport);
            steps.push_back(ev.spec_step);
        }
    } capture;

    const int listener = ::socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(listener, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(::bind(listener, reinterpret_cast<sockaddr *>(&a), sizeof(a)), 0);
    ASSERT_EQ(::listen(listener, 8), 0);
    socklen_t len = sizeof(a);
    ASSERT_EQ(::getsockname(listener, reinterpret_cast<sockaddr *>(&a), &len), 0);

    auto session = std::make_unique<SubscribeEventgroupTcpSession>(
        "lo", Endpoint{htonl(INADDR_LOOPBACK), ntohs(a.sin_port)});
    ASSERT_TRUE(session->valid());
    SubscribeTcpTeardownService drv(std::move(session), kService, kEvent, /*trigger_after=*/2,
                                    TcpTeardownMode::kRefuseWithRst, /*teardown_step=*/47);

    tc8::stimulus::setTxObserver(&capture);
    drv.onCapturedFrame(someipNotif(kService, kEvent, /*is_tcp=*/true));  // counted, not yet
    drv.onCapturedFrame(someipNotif(kService, kEvent, /*is_tcp=*/true));  // fires
    // A send after the teardown, on the same thread, is not the teardown's step.
    tc8::stimulus::reportTx("udp_unicast", {}, 0, 0, 1);
    tc8::stimulus::setTxObserver(nullptr);
    ::close(listener);

    ASSERT_EQ(capture.transports.size(), 2u);
    EXPECT_EQ(capture.transports[0], "tcp_reset");
    EXPECT_EQ(capture.steps[0], 47);
    EXPECT_EQ(capture.transports[1], "udp_unicast");
    EXPECT_EQ(capture.steps[1], tc8::stimulus::kNoSpecStep);
}

}  // namespace
