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

// Typed pointers to the payload that follows a netlink message header / rtattr.
// These reimplement the glibc NLMSG_DATA / RTA_DATA accessors — the ones whose
// expansion contains a C-style cast (`(void*)((char*)x + ...)`) that trips
// -Wold-style-cast under the harness's strict first-party set — with
// reinterpret_cast, so the cast lives here ONCE and no strict-gated caller open-
// codes the macro. The boundary is "the glibc accessors that LEAK A CAST", not an
// arbitrary subset: the pure-arithmetic length/alignment macros (NLMSG_HDRLEN /
// NLMSG_LENGTH / NLMSG_ALIGN / RTA_LENGTH / RTA_ALIGN) carry no cast and are used
// directly. const and mutable overloads preserve the caller's qualification.
template <class T>
inline const T *nlmsgData(const ::nlmsghdr *nlh) {
    return reinterpret_cast<const T *>(reinterpret_cast<const char *>(nlh) + NLMSG_HDRLEN);
}
template <class T>
inline T *nlmsgData(::nlmsghdr *nlh) {
    return reinterpret_cast<T *>(reinterpret_cast<char *>(nlh) + NLMSG_HDRLEN);
}
template <class T>
inline const T *rtaData(const ::rtattr *rta) {
    return reinterpret_cast<const T *>(reinterpret_cast<const char *>(rta) + RTA_LENGTH(0));
}
template <class T>
inline T *rtaData(::rtattr *rta) {
    return reinterpret_cast<T *>(reinterpret_cast<char *>(rta) + RTA_LENGTH(0));
}

// Netlink message / attribute iteration, mirroring the glibc NLMSG_OK/NLMSG_NEXT
// and RTA_OK/RTA_NEXT macros but with their int/unsigned conversions made
// explicit, so a caller walking a dump under the strict first-party set
// (-Wsign-conversion) does not inherit the macros' implicit narrowing. `*len` is
// the remaining buffer length, decremented as each step advances past the
// aligned message/attribute. Same single-source rationale as nlmsgData/rtaData:
// the bound-check int/unsigned conversions live here once rather than at each walk
// site (the pure-arithmetic NLMSG_ALIGN/RTA_ALIGN inside carry no such hazard).
inline bool nlmsgOk(const ::nlmsghdr *nh, int len) {
    return len >= static_cast<int>(sizeof(::nlmsghdr)) &&
           nh->nlmsg_len >= sizeof(::nlmsghdr) &&
           nh->nlmsg_len <= static_cast<std::uint32_t>(len);
}
inline ::nlmsghdr *nlmsgNext(::nlmsghdr *nh, int *len) {
    const std::uint32_t aligned = NLMSG_ALIGN(nh->nlmsg_len);
    *len -= static_cast<int>(aligned);
    return reinterpret_cast<::nlmsghdr *>(reinterpret_cast<char *>(nh) + aligned);
}
inline bool rtaOk(const ::rtattr *rta, int len) {
    return len >= static_cast<int>(sizeof(::rtattr)) &&
           static_cast<std::size_t>(rta->rta_len) >= sizeof(::rtattr) &&
           static_cast<unsigned int>(rta->rta_len) <= static_cast<unsigned int>(len);
}
inline const ::rtattr *rtaNext(const ::rtattr *rta, int *len) {
    const int aligned = RTA_ALIGN(rta->rta_len);
    *len -= aligned;
    return reinterpret_cast<const ::rtattr *>(reinterpret_cast<const char *>(rta) + aligned);
}

// Append a netlink rtattr (type + payload) at byte offset *off within `buf`,
// advancing *off past the RTA-aligned attribute and returning the written
// attribute so a caller building a nested container can fix up its rta_len after
// appending the children. The caller sizes `buf` for the fixed, small messages
// built on top. A zero `plen` writes a header-only attribute (a nested-container
// open), copying nothing.
inline ::rtattr *appendAttr(char *buf, std::size_t *off, std::uint16_t type, const void *payload,
                            std::size_t plen) {
    auto *rta = reinterpret_cast<::rtattr *>(buf + *off);
    rta->rta_type = type;
    rta->rta_len = static_cast<unsigned short>(RTA_LENGTH(plen));
    if (plen != 0) {
        std::memcpy(rtaData<char>(rta), payload, plen);
    }
    *off += RTA_ALIGN(rta->rta_len);
    return rta;
}

// Send one already-built request `msg` of `len` bytes (with NLM_F_REQUEST |
// NLM_F_ACK set by the caller) over a transient NETLINK_ROUTE socket and read
// the kernel ACK, reporting WHICH answer came back: true when an NLMSG_ERROR was
// received, with `nl_errno` set to the kernel's verdict (0 = performed, else a
// negative errno such as -EPERM for a missing CAP_NET_ADMIN or -ENOENT for an
// entry that is already absent); false when no ACK could be obtained at all (the
// socket, the send, or a short/absent reply), leaving `nl_errno` untouched.
//
// Splitting "the kernel answered X" from "nothing answered" is what lets a
// caller name the cause instead of collapsing every path to one bool — the
// distinction the capability seam (net/op_status.h) is built on.
inline bool sendRequestAck(const void *msg, std::uint32_t len, int &nl_errno) {
    const int nl = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (nl < 0) {
        return false;
    }
    bool acked = false;
    if (::send(nl, msg, len, 0) >= 0) {
        char rbuf[512];
        const ssize_t r = ::recv(nl, rbuf, sizeof(rbuf), 0);
        if (r >= static_cast<ssize_t>(NLMSG_LENGTH(sizeof(::nlmsgerr)))) {
            const auto *rh = reinterpret_cast<const ::nlmsghdr *>(rbuf);
            if (rh->nlmsg_type == NLMSG_ERROR) {
                nl_errno = nlmsgData<::nlmsgerr>(rh)->error;
                acked = true;
            }
        }
    }
    ::close(nl);
    return acked;
}

// The boolean form of sendRequestAck, for callers whose result is a plain
// success/failure. Strict: true ONLY on an ACK carrying error == 0, or (when
// `enoent_ok`) error == -ENOENT ("entry already absent", making a delete
// idempotent). A failed send, a short/absent reply, or any other error is false.
// The write needs CAP_NET_ADMIN, so a privilege-less caller gets false
// (surfaced, not silently accepted). Derived from sendRequestAck rather than
// repeating the socket+send+ACK dance, so there is one copy of it.
inline bool sendRequestCheckAck(const void *msg, std::uint32_t len, bool enoent_ok) {
    int nl_errno = 0;
    if (!sendRequestAck(msg, len, nl_errno)) {
        return false;
    }
    return nl_errno == 0 || (enoent_ok && nl_errno == -ENOENT);
}

}  // namespace tc8::net::rtnl
