#pragma once

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>

#include "tc8/net/rtnetlink.h"

namespace tc8::net {

// The interface's MTU, or 0 when it cannot be read (unknown interface, no
// permission). Read via SIOCGIFMTU — an ioctl, not a fork of `ip link`, so it
// keeps this header's "never shell out" contract; rtnetlink would be ceremony
// for one scalar the kernel hands over directly.
//
// 0 is a real answer, not an error to swallow: a caller sizing a buffer from the
// MTU must fall back to a safe maximum rather than read "unknown" as "small".
inline unsigned linkMtu(const std::string &ifname) {
    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return 0;
    }
    ifreq ifr{};
    std::strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
    const int rc = ::ioctl(fd, SIOCGIFMTU, &ifr);
    ::close(fd);
    return rc < 0 ? 0U : static_cast<unsigned>(ifr.ifr_mtu);
}

// L2 bytes that ride in front of an MTU-sized payload: the 14-byte Ethernet-II
// header plus room for two VLAN tags (the harness decodes 802.1Q), rounded up
// for headroom. Added to the MTU when sizing a capture snaplen so a whole frame
// is never cut.
inline constexpr unsigned kL2Headroom = 32;

// Snaplen that captures any whole frame `ifname` can legitimately carry, or
// `fallback` when the MTU is unreadable.
//
// This sizes capture CAPACITY, not just correctness. Immediate mode makes
// libpcap fall back to TPACKET_V2, whose ring is carved into FIXED slots sized
// by the snaplen — at 65535 every slot costs 64 KB, so a 16 MB ring holds ~256
// frames (measured) no matter how small the frames are, and ~700 small SD frames
// overflow it. Sized from the MTU the same ring holds ~7,885. Raising the buffer
// instead does not work: 4x the ring still dropped 97% in the same measurement,
// because the slot count, not the byte count, is the limit.
//
// Safe only because a frame past the snaplen is now REFUSED and counted rather
// than decoded short (PacketPipeline::truncatedFrames). If a link this repo does
// not own carries super-frames (segmentation offload left on), the run says so
// loudly instead of fabricating a plausible short decode.
inline unsigned captureSnaplenFor(const std::string &ifname, unsigned fallback) {
    const unsigned mtu = linkMtu(ifname);
    return mtu == 0 ? fallback : mtu + kL2Headroom;
}

// Bring interface `ifname` administratively up or down via rtnetlink (RTM_NEWLINK
// toggling IFF_UP). This is a CONFORMANCE-TESTER fault injector — it drives a
// link-loss teardown for a subscription case by downing the tester's own leg —
// NOT a DUT-side server capability, so it is a free function here rather than a
// SocketBackend (the DUT server I/O seam) method. "Speak netlink, never shell out
// to `ip link`." Returns true on a zero-error kernel ACK; false on an unknown
// interface or without CAP_NET_ADMIN (surfaced, not silently accepted). The
// caller is responsible for restoring the prior state.
//
// Note: bringing a link down blinds capture on that same leg, so a teardown case
// observes "no resumed notification after the link returns" (post-recovery
// silence) rather than watching during the outage.
inline bool setLinkState(const std::string &ifname, bool up) {
    const unsigned ifindex = ::if_nametoindex(ifname.c_str());
    if (ifindex == 0) {
        return false;  // unknown interface (resolved unprivileged, before any write)
    }
    struct {
        ::nlmsghdr nlh;
        ::ifinfomsg ifi;
    } req{};
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(::ifinfomsg));
    req.nlh.nlmsg_type = RTM_NEWLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.ifi.ifi_family = AF_UNSPEC;
    req.ifi.ifi_index = static_cast<int>(ifindex);
    req.ifi.ifi_flags = up ? static_cast<unsigned>(IFF_UP) : 0U;
    req.ifi.ifi_change = IFF_UP;  // only the IFF_UP bit is being changed
    return rtnl::sendRequestCheckAck(&req, req.nlh.nlmsg_len, /*enoent_ok=*/false);
}

// An interface's link state as the kernel reports it. `carrier` is IFF_RUNNING: the
// interface is up and its lower layer has a link, so on a veth it follows the peer's
// administrative state and on a NIC the PHY. They differ when an interface is up with
// nothing on the other end.
struct LinkState {
    bool admin_up = false;
    bool carrier = false;
};

// The current link state of `ifname`, or nullopt when it cannot be read (unknown
// interface). Unprivileged.
inline std::optional<LinkState> readLinkState(const std::string &ifname) {
    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return std::nullopt;
    }
    ifreq ifr{};
    std::strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
    const int rc = ::ioctl(fd, SIOCGIFFLAGS, &ifr);
    ::close(fd);
    if (rc < 0) {
        return std::nullopt;
    }
    LinkState state;
    state.admin_up = (ifr.ifr_flags & IFF_UP) != 0;
    state.carrier = (ifr.ifr_flags & IFF_RUNNING) != 0;
    return state;
}

// How a bounded wait for a carrier state ended. The first two are observations of the
// link. kNotObserved is not: the state could not be read, so it says nothing about the
// link and a case must not grade it.
enum class CarrierWait : std::uint8_t { kReached, kBoundElapsed, kNotObserved };

// Wait up to `bound` for the carrier of `ifname` to become `want`. Driven by the kernel's
// link notifications, opened BEFORE the first read, so a change between the read and the
// wait is not missed and a brief drop is not slept through. Unprivileged.
//
// kBoundElapsed from a DUT asked to drop its link is the DUT keeping it up, which is a
// finding. A DUT that was never asked is the caller's to record as an unperformed
// stimulus; this function cannot tell the two apart.
inline CarrierWait awaitCarrier(const std::string &ifname, bool want,
                                std::chrono::milliseconds bound) {
    const int nl = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (nl < 0) {
        return CarrierWait::kNotObserved;
    }
    sockaddr_nl addr{};
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_LINK;
    if (::bind(nl, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) < 0) {
        ::close(nl);
        return CarrierWait::kNotObserved;
    }
    const auto deadline = std::chrono::steady_clock::now() + bound;
    CarrierWait result = CarrierWait::kBoundElapsed;
    for (;;) {
        const auto state = readLinkState(ifname);
        if (!state) {
            result = CarrierWait::kNotObserved;
            break;
        }
        if (state->carrier == want) {
            result = CarrierWait::kReached;
            break;
        }
        const auto left = std::chrono::ceil<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        if (left.count() <= 0) {
            break;
        }
        pollfd pfd{nl, POLLIN, 0};
        if (::poll(&pfd, 1, static_cast<int>(left.count())) > 0) {
            // Any notification means "read again"; which link it names is not needed,
            // and a backlog is emptied so the next poll waits for a new one.
            char drain[8192];
            while (::recv(nl, drain, sizeof(drain), MSG_DONTWAIT) > 0) {
            }
        }
    }
    ::close(nl);
    return result;
}

}  // namespace tc8::net
