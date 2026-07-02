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

#include <gtest/gtest.h>

#include "sce_integration/reliable_teardown_service.h"
#include "stimulus/endpoint.h"
#include "stimulus/subscribe_tcp_session.h"
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

}  // namespace
