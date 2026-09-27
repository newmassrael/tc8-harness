// Unit tests for ut::applyArpStaticEntry — OpConditionArpCache's TC8 §4.2.3
// static-entry pair (install and take out a permanent ARP entry on the DUT),
// parsed once in the platform-agnostic UT core and performed
// through the DUT's net::SocketBackend. Pins that the entry the DUT installs is
// exactly the one the request carried, on the interface the DUT was told, and
// that a stack that could not do it says so instead of answering OK.
//
// The request bytes come from the TESTER's own builders, so the two ends of the
// wire are checked against each other rather than each against a hand copy.

#include "upper_tester/arp_static_entry.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "stimulus/upper_tester_client.h"
#include "stub_socket_backend.h"

namespace tc8::ut {
namespace {

class RecordingNeighbors : public ::tc8::test::StubSocketBackend {
public:
    struct Call {
        bool add = false;
        std::string ifname;
        std::uint32_t addr_be = 0;
        std::array<std::uint8_t, 6> mac{};
    };
    std::vector<Call> calls;
    net::OpStatus answer = net::OpStatus::Ok;

    net::OpStatus addStaticNeighbor(const std::string &ifname, std::uint32_t addr_be,
                                    const std::uint8_t *mac) override {
        Call c{true, ifname, addr_be, {}};
        for (std::size_t i = 0; i < 6; ++i) {
            c.mac[i] = mac[i];
        }
        calls.push_back(c);
        return answer;
    }
    net::OpStatus removeNeighbor(const std::string &ifname, std::uint32_t addr_be) override {
        calls.push_back({false, ifname, addr_be, {}});
        return answer;
    }
};

// The request params the server hands a handler: everything past <opcode><req_id>.
std::vector<std::uint8_t> paramsOf(const std::vector<std::uint8_t> &request) {
    return {request.begin() + 2, request.end()};
}

constexpr std::uint32_t kHost1IpBe = 0x0100A8C0U;  // 192.168.0.1, network order in memory
constexpr std::array<std::uint8_t, 6> kMacAddr1{0x02, 0x00, 0x00, 0x00, 0x00, 0xA1};

TEST(ArpStaticEntry, AddInstallsExactlyTheCarriedPairOnTheNamedInterface) {
    RecordingNeighbors be;
    const auto p = paramsOf(stimulus::buildArpAddStaticRequest(0x07, kHost1IpBe, kMacAddr1));
    std::uint8_t status = 0xFF;
    std::vector<std::uint8_t> body;
    ASSERT_TRUE(applyArpStaticEntry(be, "et0", p.data(), p.size(), status, body));
    EXPECT_EQ(status, kStatusOk);
    EXPECT_TRUE(body.empty());
    ASSERT_EQ(be.calls.size(), 1U);
    EXPECT_TRUE(be.calls[0].add);
    EXPECT_EQ(be.calls[0].ifname, "et0");
    EXPECT_EQ(be.calls[0].addr_be, kHost1IpBe);
    EXPECT_EQ(be.calls[0].mac, kMacAddr1);
}

TEST(ArpStaticEntry, RemoveTakesTheAddressAlone) {
    RecordingNeighbors be;
    const auto p = paramsOf(stimulus::buildArpRemoveStaticRequest(0x07, kHost1IpBe));
    std::uint8_t status = 0xFF;
    std::vector<std::uint8_t> body;
    ASSERT_TRUE(applyArpStaticEntry(be, "et0", p.data(), p.size(), status, body));
    EXPECT_EQ(status, kStatusOk);
    ASSERT_EQ(be.calls.size(), 1U);
    EXPECT_FALSE(be.calls[0].add);
    EXPECT_EQ(be.calls[0].addr_be, kHost1IpBe);
}

// A stack that cannot hold the entry must not answer OK: the case that follows
// asserts the DUT sends no ARP Request, and an entry that was never installed
// would make that assertion about nothing. The OpStatus rides back so a permanent
// "cannot" is told apart from a refusal.
TEST(ArpStaticEntry, AStackThatCouldNotDoItSaysWhy) {
    RecordingNeighbors be;
    be.answer = net::OpStatus::Unsupported;
    const auto p = paramsOf(stimulus::buildArpAddStaticRequest(0x07, kHost1IpBe, kMacAddr1));
    std::uint8_t status = 0xFF;
    std::vector<std::uint8_t> body;
    ASSERT_TRUE(applyArpStaticEntry(be, "et0", p.data(), p.size(), status, body));
    EXPECT_EQ(status, kStatusNotPerformed);
    ASSERT_EQ(body.size(), 1U);
    EXPECT_EQ(body[0], static_cast<std::uint8_t>(net::OpStatus::Unsupported));
}

// Short of the pair it names, the request is malformed and the backend is never
// asked — a truncated MAC must not become some other entry.
TEST(ArpStaticEntry, ATruncatedEntryIsMalformedAndTouchesNothing) {
    RecordingNeighbors be;
    auto p = paramsOf(stimulus::buildArpAddStaticRequest(0x07, kHost1IpBe, kMacAddr1));
    p.pop_back();
    std::uint8_t status = 0xFF;
    std::vector<std::uint8_t> body;
    ASSERT_TRUE(applyArpStaticEntry(be, "et0", p.data(), p.size(), status, body));
    EXPECT_EQ(status, kStatusMalformed);
    EXPECT_TRUE(be.calls.empty());
}

// The other 0x17 actions are not this function's: it declines them untouched so
// the DUT's own handler can take them.
TEST(ArpStaticEntry, OtherActionsAreDeclined) {
    RecordingNeighbors be;
    for (const std::uint8_t action : {kArpConditionFlushAll, kArpConditionAgeBySeconds}) {
        const auto p = paramsOf(stimulus::buildConditionArpCacheRequest(0x07, action, 5));
        std::uint8_t status = 0xFF;
        std::vector<std::uint8_t> body;
        EXPECT_FALSE(applyArpStaticEntry(be, "et0", p.data(), p.size(), status, body));
        EXPECT_EQ(status, 0xFF);
    }
    EXPECT_TRUE(be.calls.empty());
}

}  // namespace
}  // namespace tc8::ut
