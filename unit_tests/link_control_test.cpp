#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>

#include <gtest/gtest.h>

#include "net/link_control.h"
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
    ScopeExit cleanup([&] { deleteDummyIface(kIf); });

    // createDummyIface brings it up; take it administratively down, then back up.
    ASSERT_TRUE(setLinkState(kIf, false));
    EXPECT_EQ(ifaceFlags(kIf) & IFF_UP, 0) << "admin-down must clear IFF_UP";
    ASSERT_TRUE(setLinkState(kIf, true));
    EXPECT_NE(ifaceFlags(kIf) & IFF_UP, 0) << "admin-up must set IFF_UP";
}

}  // namespace
}  // namespace tc8::net
