#pragma once

#include <net/if.h>

#include <string>

#include "net/rtnetlink.h"

namespace tc8::net {

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

}  // namespace tc8::net
