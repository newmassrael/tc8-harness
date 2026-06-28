#pragma once

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// Linux rtnetlink (NETLINK_ROUTE) request primitives — the single source of the
// "speak netlink, never shell out to `ip`" plumbing (fork+exec is slow and unsafe
// in a multi-threaded server). Shared by the DUT-side POSIX SocketBackend
// (neighbor/ARP-cache ops) and the conformance tester (interface link-state fault
// injection), so neither owns a private copy of the socket+send+ACK dance. Linux
// only; lwIP and other backends never include this. Header-only (small inline
// helpers) to avoid a cross-program link artifact for two callers.
namespace tc8::net::rtnl {

// Append a netlink rtattr (type + payload) at byte offset *off within `buf`,
// advancing *off past the RTA-aligned attribute. The caller sizes `buf` for the
// fixed, small messages built on top.
inline void appendAttr(char *buf, std::size_t *off, std::uint16_t type, const void *payload,
                       std::size_t plen) {
    auto *rta = reinterpret_cast<::rtattr *>(buf + *off);
    rta->rta_type = type;
    rta->rta_len = static_cast<unsigned short>(RTA_LENGTH(plen));
    std::memcpy(RTA_DATA(rta), payload, plen);
    *off += RTA_ALIGN(rta->rta_len);
}

// Send one already-built request `msg` of `len` bytes (with NLM_F_REQUEST |
// NLM_F_ACK set by the caller) over a transient NETLINK_ROUTE socket and check
// the kernel ACK. Strict: returns true ONLY on a received NLMSG_ERROR carrying
// error == 0, or (when `enoent_ok`) error == -ENOENT ("entry already absent",
// making a delete idempotent). A failed send, a short/absent reply, or any other
// error is false. The write needs CAP_NET_ADMIN, so a privilege-less caller gets
// false (surfaced, not silently accepted).
inline bool sendRequestCheckAck(const void *msg, std::uint32_t len, bool enoent_ok) {
    const int nl = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (nl < 0) {
        return false;
    }
    bool ok = false;
    if (::send(nl, msg, len, 0) >= 0) {
        char rbuf[512];
        const ssize_t r = ::recv(nl, rbuf, sizeof(rbuf), 0);
        if (r >= static_cast<ssize_t>(NLMSG_LENGTH(sizeof(::nlmsgerr)))) {
            const auto *rh = reinterpret_cast<const ::nlmsghdr *>(rbuf);
            if (rh->nlmsg_type == NLMSG_ERROR) {
                const auto *e = static_cast<const ::nlmsgerr *>(NLMSG_DATA(rh));
                ok = e->error == 0 || (enoent_ok && e->error == -ENOENT);
            }
        }
    }
    ::close(nl);
    return ok;
}

}  // namespace tc8::net::rtnl
