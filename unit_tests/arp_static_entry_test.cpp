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
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "netns_test_util.h"
#include "stimulus/upper_tester_client.h"
#include "stub_socket_backend.h"
#include "tc8/linux_socket_backend.h"

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

// The kernel's own record of one neighbour entry, from /proc/net/arp:
// "<ip> <hw type> <flags> <mac> <mask> <device>". Empty when absent.
struct ProcArpRow {
    std::string flags;
    std::string mac;
};

ProcArpRow procArpRow(const std::string &ip, const std::string &dev) {
    std::ifstream in("/proc/net/arp");
    std::string line;
    std::getline(in, line);  // header
    while (std::getline(in, line)) {
        std::istringstream row(line);
        std::string r_ip, hw, flags, mac, mask, r_dev;
        if (row >> r_ip >> hw >> flags >> mac >> mask >> r_dev && r_ip == ip && r_dev == dev) {
            return {flags, mac};
        }
    }
    return {};
}

// End to end below the wire: the tester's own request bytes, the DUT-side parser,
// the reference DUT's real backend, and the kernel's neighbour table as the oracle
// — not the backend's return value, which says only that it believes it succeeded.
// Runs under scripts/run-netns-test.sh (arp_static_entry_privileged), so it holds
// CAP_NET_ADMIN over a private stack; skipped anywhere else.
TEST(ArpStaticEntryPrivileged, TheKernelHoldsExactlyTheCarriedEntryAndThenNone) {
    if (!::tc8::testutil::hasNetAdmin()) {
        GTEST_SKIP() << "neighbour writes need CAP_NET_ADMIN "
                        "(ctest runs this as arp_static_entry_privileged)";
    }
    constexpr const char *kIf = "tc8dummy3";
    if (!::tc8::testutil::createDummyIface(kIf)) {
        GTEST_SKIP() << "could not create a dummy interface (no dummy driver?)";
    }
    ::tc8::testutil::ScopeExit cleanup([&] { ::tc8::testutil::deleteIface(kIf); });

    ::tc8::dut::LinuxSocketBackend be;
    std::uint8_t status = 0xFF;
    std::vector<std::uint8_t> body;

    const auto add = paramsOf(stimulus::buildArpAddStaticRequest(0x01, kHost1IpBe, kMacAddr1));
    ASSERT_TRUE(applyArpStaticEntry(be, kIf, add.data(), add.size(), status, body));
    ASSERT_EQ(status, kStatusOk) << "OpStatus byte: " << (body.empty() ? -1 : int(body[0]));
    const ProcArpRow row = procArpRow("192.168.0.1", kIf);
    EXPECT_EQ(row.mac, "02:00:00:00:00:a1") << "the kernel holds a different entry, or none";
    // ATF_COM | ATF_PERM: complete and permanent — a static entry, not a learned one.
    EXPECT_EQ(row.flags, "0x6");

    body.clear();
    const auto rm = paramsOf(stimulus::buildArpRemoveStaticRequest(0x02, kHost1IpBe));
    ASSERT_TRUE(applyArpStaticEntry(be, kIf, rm.data(), rm.size(), status, body));
    EXPECT_EQ(status, kStatusOk);
    EXPECT_TRUE(procArpRow("192.168.0.1", kIf).mac.empty()) << "the entry survived its removal";
}

}  // namespace
}  // namespace tc8::ut
