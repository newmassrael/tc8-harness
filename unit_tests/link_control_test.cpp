#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <thread>

#include <gtest/gtest.h>

#include "tc8/net/link_control.h"
#include "netns_test_util.h"

namespace tc8::net {
namespace {

// Read the live interface flags for `ifname` via SIOCGIFFLAGS (unprivileged).
// Returns the flags, or -1 on error.
int ifaceFlags(const char *ifname) {
    const int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        return -1;
    }
    ifreq ifr{};
    std::strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    const int rc = ::ioctl(s, SIOCGIFFLAGS, &ifr);
    ::close(s);
    return rc < 0 ? -1 : ifr.ifr_flags;
}

// The interface is resolved unprivileged first, so an unknown name is rejected
// before any netlink write — false on any host, no CAP_NET_ADMIN needed.
TEST(SetLinkState, UnknownInterfaceRejected) {
    EXPECT_FALSE(setLinkState("tc8_no_such_iface", true));
    EXPECT_FALSE(setLinkState("tc8_no_such_iface", false));
}

// Toggle a throwaway dummy interface down then up and read the admin IFF_UP flag
// back each way. Runs wherever the process holds CAP_NET_ADMIN — including the
// no-sudo `unshare` netns the link_state_privileged CTest uses — else it skips.
// A dummy device (not `lo`) is used so a direct real-root run never disturbs the
// host's loopback.
TEST(SetLinkState, PrivilegedTogglesDummyIface) {
    using namespace ::tc8::testutil;
    if (!hasNetAdmin()) {
        GTEST_SKIP() << "link-state writes need CAP_NET_ADMIN "
                        "(try: unshare --user --map-root-user --net)";
    }
    constexpr const char *kIf = "tc8link0";
    if (!createDummyIface(kIf)) {
        GTEST_SKIP() << "could not create a dummy interface (no dummy driver?)";
    }
    // Remove the dummy at scope exit even if an assertion below early-returns.
    ScopeExit cleanup([&] { deleteIface(kIf); });

    // createDummyIface brings it up; take it administratively down, then back up.
    ASSERT_TRUE(setLinkState(kIf, false));
    EXPECT_EQ(ifaceFlags(kIf) & IFF_UP, 0) << "admin-down must clear IFF_UP";
    ASSERT_TRUE(setLinkState(kIf, true));
    EXPECT_NE(ifaceFlags(kIf) & IFF_UP, 0) << "admin-up must set IFF_UP";
}

// An interface that cannot be read is not a link in any state: the wait says it did not
// observe, which a case must not grade as the carrier staying up or going down.
TEST(LinkState, UnknownInterfaceIsNotObserved) {
    EXPECT_FALSE(readLinkState("tc8_no_such_iface").has_value());
    EXPECT_EQ(awaitCarrier("tc8_no_such_iface", false, std::chrono::milliseconds{20}),
              CarrierWait::kNotObserved);
}

// The wait reports the change, and reports a bound that elapsed with no change: the second
// is what a DUT that kept its link looks like. The change comes from another thread while
// the wait sits on its notification socket, so a wait that polled only once would miss it.
TEST(LinkState, PrivilegedWaitSeesTheCarrierChange) {
    using namespace ::tc8::testutil;
    if (!hasNetAdmin()) {
        GTEST_SKIP() << "link-state writes need CAP_NET_ADMIN "
                        "(try: unshare --user --map-root-user --net)";
    }
    constexpr const char *kIf = "tc8link1";
    if (!createDummyIface(kIf)) {
        GTEST_SKIP() << "could not create a dummy interface (no dummy driver?)";
    }
    ScopeExit cleanup([&] { deleteIface(kIf); });

    const auto up = readLinkState(kIf);
    ASSERT_TRUE(up.has_value());
    EXPECT_TRUE(up->admin_up);

    EXPECT_EQ(awaitCarrier(kIf, false, std::chrono::milliseconds{50}), CarrierWait::kBoundElapsed);

    std::thread down([] {
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
        setLinkState(kIf, false);
    });
    const auto reached = awaitCarrier(kIf, false, std::chrono::seconds{5});
    down.join();
    EXPECT_EQ(reached, CarrierWait::kReached);
    const auto after = readLinkState(kIf);
    ASSERT_TRUE(after.has_value());
    EXPECT_FALSE(after->admin_up);
    EXPECT_FALSE(after->carrier);
}

}  // namespace
}  // namespace tc8::net
