#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cstdint>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "stimulus/sd_session.h"
#include "stimulus/someip_sd_builder.h"
#include "tc8/someip/sd_wire_constants.h"

namespace tc8::stimulus {
namespace {

constexpr std::uint32_t kTester = 0x0300A8C0;   // 192.168.0.3, network order
constexpr std::uint32_t kAlias  = 0x0400A8C0;   // 192.168.0.4
constexpr std::uint32_t kDut    = 0x0200A8C0;   // 192.168.0.2
constexpr std::uint32_t kGroup  = 0xF5E0F4E0;   // 224.244.224.245

class SdSessionTest : public ::testing::Test {
protected:
    void SetUp() override { resetSdSessions(); }
    void TearDown() override { resetSdSessions(); }
};

// An SD datagram as the builders lay it out, with only the fields the counter reads.
std::vector<std::uint8_t> sdDatagram(std::uint16_t session, std::uint8_t flags) {
    FindServiceParams p{};
    p.session_id = session;
    p.sd_flags = flags;
    return buildFindService(p);
}

void noteSent(std::uint32_t src, std::uint32_t dst, const std::vector<std::uint8_t> &d) {
    noteSdDatagramSent(src, dst, d.data(), d.size());
}

TEST_F(SdSessionTest, StreamStartsAtOneWithRebootAndCountsUp) {
    const SdSession a = nextSdSession(kTester, kGroup);
    const SdSession b = nextSdSession(kTester, kGroup);
    EXPECT_EQ(a.session_id, kSdSessionFirst);
    EXPECT_TRUE(a.reboot);
    EXPECT_EQ(b.session_id, 0x0002);
    EXPECT_TRUE(b.reboot);
}

// The receiver's slot is (sender, unicast | multicast): the multicast stream, each
// unicast destination and each source address count on their own.
TEST_F(SdSessionTest, StreamsAreKeyedBySourceAndDestination) {
    nextSdSession(kTester, kGroup);
    nextSdSession(kTester, kGroup);
    EXPECT_EQ(nextSdSession(kTester, kDut).session_id, kSdSessionFirst);
    EXPECT_EQ(nextSdSession(kAlias, kDut).session_id, kSdSessionFirst);
    EXPECT_EQ(nextSdSession(kTester, kGroup).session_id, 0x0003);
}

// A Session the case chose (a deliberate reboot or repeat) is sent as given, and the
// stream continues from it rather than undoing it. The first draw below is never sent
// (as when its send fails); choosing that same value later must still move the stream.
TEST_F(SdSessionTest, ChosenSessionMovesTheStream) {
    nextSdSession(kTester, kDut);
    noteSent(kTester, kDut, sdDatagram(0x0040, ::tc8::sd_flags::kRebootUnicast));
    EXPECT_EQ(nextSdSession(kTester, kDut).session_id, 0x0041);

    // Backwards on purpose: the announced reboot is honoured, the stream restarts there.
    noteSent(kTester, kDut, sdDatagram(kSdSessionFirst, ::tc8::sd_flags::kRebootUnicast));
    EXPECT_EQ(nextSdSession(kTester, kDut).session_id, 0x0002);
}

// Two senders on one stream (a case and a responder thread) draw 1 and 2 and the second
// reaches the wire first. The late report of 1 must not pull the stream back to 2.
TEST_F(SdSessionTest, LateReportOfADrawnSessionDoesNotMoveTheStreamBack) {
    const SdSession first = nextSdSession(kTester, kDut);
    const SdSession second = nextSdSession(kTester, kDut);
    noteSent(kTester, kDut, sdDatagram(second.session_id, ::tc8::sd_flags::kRebootUnicast));
    noteSent(kTester, kDut, sdDatagram(first.session_id, ::tc8::sd_flags::kRebootUnicast));
    EXPECT_EQ(nextSdSession(kTester, kDut).session_id, 0x0003);
}

// SD §4.2.1: the Session wraps 0xFFFF -> 0x0001 and the Reboot flag clears there.
TEST_F(SdSessionTest, WrapSkipsZeroAndClearsReboot) {
    noteSent(kTester, kGroup, sdDatagram(0xFFFE, ::tc8::sd_flags::kRebootUnicast));
    const SdSession last = nextSdSession(kTester, kGroup);
    const SdSession wrapped = nextSdSession(kTester, kGroup);
    EXPECT_EQ(last.session_id, 0xFFFF);
    EXPECT_TRUE(last.reboot);
    EXPECT_EQ(wrapped.session_id, kSdSessionFirst);
    EXPECT_FALSE(wrapped.reboot);
}

// A chosen Session carries its own Reboot flag into the stream (a case resuming a
// post-wrap stream sends Reboot = 0).
TEST_F(SdSessionTest, ChosenRebootFlagCarriesIntoTheStream) {
    noteSent(kTester, kDut, sdDatagram(0x0100, ::tc8::sd_flags::kUnicast));
    const SdSession next = nextSdSession(kTester, kDut);
    EXPECT_EQ(next.session_id, 0x0101);
    EXPECT_FALSE(next.reboot);
}

TEST_F(SdSessionTest, NonSdDatagramIsIgnored) {
    std::vector<std::uint8_t> d = sdDatagram(0x0040, ::tc8::sd_flags::kRebootUnicast);
    d[3] = 0x01;  // Method ID 0x8101: not SD, and not read as SD by any receiver
    noteSent(kTester, kDut, d);
    EXPECT_EQ(nextSdSession(kTester, kDut).session_id, kSdSessionFirst);
}

TEST(SdFlagsWithReboot, ReplacesOnlyTheRebootBit) {
    constexpr std::uint8_t kOther = ::tc8::sd_flags::kUnicast | 0x20;
    EXPECT_EQ(sdFlagsWithReboot(kOther, true), ::tc8::sd_flags::kReboot | kOther);
    EXPECT_EQ(sdFlagsWithReboot(::tc8::sd_flags::kReboot | kOther, false), kOther);
}

// The emitters draw from the counter end to end: two default Subscribes go out as 1
// and 2, a Subscribe the case numbers is sent as given, and the next default one
// follows on from it. Over loopback, so the Session is read from the received bytes.
class SdSessionEmitTest : public SdSessionTest {
protected:
    void SetUp() override {
        SdSessionTest::SetUp();
        rx_ = ::socket(AF_INET, SOCK_DGRAM, 0);
        ASSERT_GE(rx_, 0);
        sockaddr_in ra{};
        ra.sin_family = AF_INET;
        ra.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ASSERT_EQ(::bind(rx_, reinterpret_cast<sockaddr *>(&ra), sizeof(ra)), 0);
        sockaddr_in bound{};
        socklen_t bl = sizeof(bound);
        ASSERT_EQ(::getsockname(rx_, reinterpret_cast<sockaddr *>(&bound), &bl), 0);
        dest_.ipv4_be = htonl(INADDR_LOOPBACK);
        dest_.port = ntohs(bound.sin_port);
        timeval tv{1, 0};
        ::setsockopt(rx_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    void TearDown() override {
        if (rx_ >= 0) {
            ::close(rx_);
        }
        SdSessionTest::TearDown();
    }

    // The Session and SD flags of the next datagram received, or {0, 0} on timeout.
    std::pair<std::uint16_t, std::uint8_t> receive() {
        std::uint8_t buf[256] = {};
        const ssize_t n = ::recv(rx_, buf, sizeof(buf), 0);
        if (n < 17) {
            return {0, 0};
        }
        return {static_cast<std::uint16_t>((buf[10] << 8) | buf[11]), buf[16]};
    }

    int rx_ = -1;
    SubscribeDestination dest_{};
};

TEST_F(SdSessionEmitTest, SubscribesDrawFromTheStreamAndFollowAChosenSession) {
    SubscribeEventgroupParams p{};
    ASSERT_EQ(emitSubscribeEventgroupRaw("lo", p, dest_), 0);
    ASSERT_EQ(emitSubscribeEventgroupRaw("lo", p, dest_), 0);
    SubscribeEventgroupParams chosen{};
    chosen.session_id = 0x0040;
    ASSERT_EQ(emitSubscribeEventgroupRaw("lo", chosen, dest_), 0);
    ASSERT_EQ(emitSubscribeEventgroupRaw("lo", p, dest_), 0);

    const auto s1 = receive();
    const auto s2 = receive();
    const auto s3 = receive();
    const auto s4 = receive();
    EXPECT_EQ(s1.first, 0x0001);
    EXPECT_EQ(s2.first, 0x0002);
    EXPECT_EQ(s3.first, 0x0040);
    EXPECT_EQ(s4.first, 0x0041);
    EXPECT_NE(s1.second & ::tc8::sd_flags::kReboot, 0);
    EXPECT_NE(s4.second & ::tc8::sd_flags::kReboot, 0);
}

}  // namespace
}  // namespace tc8::stimulus
