#pragma once

#include <arpa/inet.h>
#include <linux/veth.h>
#include <net/if.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>

#include "net/rtnetlink.h"
#include "posix_socket_backend.h"

// Scaffolding shared by the privileged netns tests (neighbor ops, interface
// link-state). Builds a throwaway "dummy" netdevice via rtnetlink so a privileged
// test runs in-process; under `unshare --user --map-root-user --net` it needs no
// sudo. The production code never creates interfaces — this is test-only. All
// netlink I/O goes through the production tc8::net::rtnl primitive, so there is
// one send+ACK path for product and test alike.
namespace tc8::testutil {

// Create an up dummy interface `name`. false where the kernel lacks the dummy
// driver or the privilege (the caller then skips).
inline bool createDummyIface(const char *name) {
    char buf[256] = {};
    auto *nlh = reinterpret_cast<::nlmsghdr *>(buf);
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(::ifinfomsg));
    nlh->nlmsg_type = RTM_NEWLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    auto *ifi = static_cast<::ifinfomsg *>(NLMSG_DATA(nlh));
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_flags = IFF_UP;
    ifi->ifi_change = IFF_UP;

    std::size_t off = NLMSG_ALIGN(nlh->nlmsg_len);
    ::tc8::net::rtnl::appendAttr(buf, &off, IFLA_IFNAME, name, std::strlen(name) + 1);
    const std::size_t li_start = off;
    auto *linkinfo = ::tc8::net::rtnl::appendAttr(buf, &off, IFLA_LINKINFO, nullptr, 0);  // nested
    ::tc8::net::rtnl::appendAttr(buf, &off, IFLA_INFO_KIND, "dummy", 5);  // strlen("dummy"), no NUL
    linkinfo->rta_len = static_cast<unsigned short>(off - li_start);
    nlh->nlmsg_len = static_cast<std::uint32_t>(off);
    return ::tc8::net::rtnl::sendRequestCheckAck(buf, nlh->nlmsg_len, /*enoent_ok=*/false);
}

// Delete interface `name` so the test cleans up even when run as real root rather
// than inside a throwaway netns. For a veth pair, deleting either end removes
// both, so `createVethPair` teardown needs only one call.
inline void deleteIface(const char *name) {
    const unsigned idx = ::if_nametoindex(name);
    if (idx == 0) {
        return;
    }
    struct {
        ::nlmsghdr nlh;
        ::ifinfomsg ifi;
    } req{};
    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = RTM_DELLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.ifi.ifi_family = AF_UNSPEC;
    req.ifi.ifi_index = static_cast<int>(idx);
    ::tc8::net::rtnl::sendRequestCheckAck(&req, sizeof(req), /*enoent_ok=*/true);
}

// Back-compat name for the dummy-iface call sites — `deleteIface` is the
// generic primitive (delete a link by name), shared with the veth fixture.
inline void deleteDummyIface(const char *name) { deleteIface(name); }

// Bring interface `name` administratively up (RTM_NEWLINK with IFF_UP). false on
// missing interface or a privilege/ACK failure.
inline bool setIfaceUp(const char *name) {
    const unsigned idx = ::if_nametoindex(name);
    if (idx == 0) {
        return false;
    }
    struct {
        ::nlmsghdr nlh;
        ::ifinfomsg ifi;
    } req{};
    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = RTM_NEWLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.ifi.ifi_family = AF_UNSPEC;
    req.ifi.ifi_index = static_cast<int>(idx);
    req.ifi.ifi_flags = IFF_UP;
    req.ifi.ifi_change = IFF_UP;
    return ::tc8::net::rtnl::sendRequestCheckAck(&req, sizeof(req), /*enoent_ok=*/false);
}

// Create an up veth pair `name_a` <-> `name_b` and bring both ends up. A frame
// transmitted on one end is received on the other, so an L2 test (e.g. the ARP
// responder) can run the device-under-test on `name_a` and inject/capture on
// `name_b` within a single throwaway netns. Returns false where the kernel lacks
// the veth driver or the privilege (the caller then skips). Teardown is a single
// `deleteIface(name_a)` (removes the peer too).
inline bool createVethPair(const char *name_a, const char *name_b) {
    char buf[512] = {};
    auto *nlh = reinterpret_cast<::nlmsghdr *>(buf);
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(::ifinfomsg));
    nlh->nlmsg_type = RTM_NEWLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    auto *ifi = static_cast<::ifinfomsg *>(NLMSG_DATA(nlh));
    ifi->ifi_family = AF_UNSPEC;

    std::size_t off = NLMSG_ALIGN(nlh->nlmsg_len);
    ::tc8::net::rtnl::appendAttr(buf, &off, IFLA_IFNAME, name_a, std::strlen(name_a) + 1);

    // IFLA_LINKINFO { IFLA_INFO_KIND="veth", IFLA_INFO_DATA { VETH_INFO_PEER { ... } } }
    const std::size_t li_start = off;
    auto *linkinfo = ::tc8::net::rtnl::appendAttr(buf, &off, IFLA_LINKINFO, nullptr, 0);
    ::tc8::net::rtnl::appendAttr(buf, &off, IFLA_INFO_KIND, "veth", 4);  // no NUL, like createDummyIface
    const std::size_t data_start = off;
    auto *infodata = ::tc8::net::rtnl::appendAttr(buf, &off, IFLA_INFO_DATA, nullptr, 0);  // nested
    // VETH_INFO_PEER's payload begins with a raw ifinfomsg (zeroed defaults),
    // then the peer's attributes — the iproute2 layout for `ip link add ... type
    // veth peer name ...`.
    const std::size_t peer_start = off;
    auto *peer = ::tc8::net::rtnl::appendAttr(buf, &off, VETH_INFO_PEER, nullptr, 0);  // nested
    std::memset(buf + off, 0, sizeof(::ifinfomsg));
    off += NLMSG_ALIGN(sizeof(::ifinfomsg));
    ::tc8::net::rtnl::appendAttr(buf, &off, IFLA_IFNAME, name_b, std::strlen(name_b) + 1);
    peer->rta_len = static_cast<unsigned short>(off - peer_start);
    infodata->rta_len = static_cast<unsigned short>(off - data_start);
    linkinfo->rta_len = static_cast<unsigned short>(off - li_start);
    nlh->nlmsg_len = static_cast<std::uint32_t>(off);

    if (!::tc8::net::rtnl::sendRequestCheckAck(buf, nlh->nlmsg_len, /*enoent_ok=*/false)) {
        return false;
    }
    return setIfaceUp(name_a) && setIfaceUp(name_b);
}

// True iff this process holds CAP_NET_ADMIN — probes the ACTUAL capability, not
// uid 0, so a CAP_NET_ADMIN-via-file-caps process isn't wrongly skipped and a
// capability-less uid-0 container isn't run red. The probe is a delete of an
// absent neighbor on loopback: a harmless no-op the kernel still gates on
// CAP_NET_ADMIN (→ -ENOENT/true with it, -EPERM/false without).
inline bool hasNetAdmin() {
    ::tc8::dut::PosixSocketBackend be;
    return be.removeNeighbor("lo", ::htonl(0x0A0000FE));
}

// RAII: run a cleanup at scope exit even if an ASSERT_* early-returns or the test
// aborts, so a privileged test never leaks host state. The netns CTest path is
// already leak-proof via namespace teardown; this protects a direct real-root run.
template <typename F>
class ScopeExit {
public:
    explicit ScopeExit(F f) : fn_(std::move(f)) {}
    ~ScopeExit() { fn_(); }
    ScopeExit(const ScopeExit &) = delete;
    ScopeExit &operator=(const ScopeExit &) = delete;

private:
    F fn_;
};

}  // namespace tc8::testutil
