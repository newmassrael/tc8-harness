#include "posix_socket_backend.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/inet_diag.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <initializer_list>
#include <memory>
#include <optional>
#include <vector>

#include "net/rtnetlink.h"
#include "tc8/testability_protocol.h"
#include "wire/ip_checksum.h"

namespace tc8::dut {

namespace tp = ::tc8::testability;
using ::tc8::net::Endpoint;

namespace {

// setsockopt with an int-sized value, mapped to the testability result: E_OK on
// success, E_NOK on any kernel rejection (e.g. a TCP-only option on a UDP
// socket, which the kernel fails with ENOPROTOOPT).
std::uint8_t setIntSockOpt(int fd, int level, int optname, int value) {
    return ::setsockopt(fd, level, optname, &value, sizeof(value)) == 0 ? tp::kRidEOk
                                                                        : tp::kRidENok;
}

// errno from a privileged netif / route ioctl -> testability Result ID: an unknown
// interface (an errno in `iif`) is E_IIF; everything else (notably EPERM on a host
// without CAP_NET_ADMIN) is E_NOK, surfaced rather than dropped.
std::uint8_t ridFromIfaceErrno(int e, std::initializer_list<int> iif = {ENODEV}) {
    for (int x : iif) {
        if (e == x) {
            return tp::kRidEIif;
        }
    }
    return tp::kRidENok;
}

// Open an AF_INET DGRAM socket and resolve `ifname` unprivileged via SIOCGIFFLAGS,
// so an unknown interface is E_IIF BEFORE any privileged write — SIOCSIFADDR /
// SIOCADDRT can otherwise report EPERM first on a host without CAP_NET_ADMIN. On
// success returns the fd (>= 0) with `ifr` carrying the resolved name + flags (the
// flags are load-bearing for INTERFACE_UP/DOWN); on failure returns -1 and sets
// `rid`. The caller closes the fd.
int openAndResolveIface(const std::string &ifname, ifreq &ifr, std::uint8_t &rid) {
    int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        rid = tp::kRidENok;
        return -1;
    }
    std::strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
    if (::ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
        const int e = errno;
        ::close(s);
        rid = ridFromIfaceErrno(e);
        return -1;
    }
    return s;
}

// IPv6 sibling of openAndResolveIface: resolve `ifname` to its index unprivileged via
// if_nametoindex (an unknown interface is E_IIF before any privileged write, the same
// guarantee SIOCGIFFLAGS gives the V4 path), then open an AF_INET6 DGRAM socket for the
// SIOCSIFADDR / SIOCADDRT in6_* ioctls (the index, not the flags, is what those need).
// Returns the fd (>= 0) with `ifindex` set, or -1 with `rid` set. The caller closes it.
int openAndResolveIfaceV6(const std::string &ifname, unsigned &ifindex, std::uint8_t &rid) {
    ifindex = ::if_nametoindex(ifname.c_str());
    if (ifindex == 0) {
        rid = tp::kRidEIif;
        return -1;
    }
    const int s = ::socket(AF_INET6, SOCK_DGRAM, 0);
    if (s < 0) {
        rid = tp::kRidENok;  // host has no IPv6 stack
        return -1;
    }
    return s;
}

// The kernel ABI for SIOCSIFADDR / SIOCADDRT on an AF_INET6 socket. These live in
// <linux/ipv6.h>, which clashes with the glibc <netinet/in.h> already included above
// on some header versions; declare the exact layouts here (in6_addr itself comes from
// <netinet/in.h>). Anonymous-namespace types never collide with the kernel header's
// ::in6_ifreq / ::in6_rtmsg, and the ioctl only needs matching memory.
struct in6_ifreq {
    in6_addr addr;
    std::uint32_t prefixlen;
    int ifindex;
};
struct in6_rtmsg {
    in6_addr dst;
    in6_addr src;
    in6_addr gateway;
    std::uint32_t type;
    std::uint16_t dst_len;
    std::uint16_t src_len;
    std::uint32_t metric;
    unsigned long info;
    std::uint32_t flags;
    int ifindex;
};

// Build and send a single RTM_NEWNEIGH / RTM_DELNEIGH via the shared rtnetlink
// request primitive (tc8::net::rtnl) — the request+ACK sibling of
// flushDynamicArp's dump. A non-null `mac` adds an NDA_LLADDR (an add carries it,
// a delete does not). Returns true on a zero-error ACK; `enoent_ok` additionally
// treats -ENOENT ("entry already absent") as success, making a delete idempotent.
// The write needs CAP_NET_ADMIN, so a privilege-less host gets false.
bool sendNeighborOp(unsigned ifindex, std::uint16_t nlmsg_type, std::uint16_t extra_flags,
                    std::uint16_t ndm_state, std::uint32_t dst_be, const std::uint8_t *mac,
                    bool enoent_ok) {
    char buf[256] = {};
    auto *nlh = reinterpret_cast<::nlmsghdr *>(buf);
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(::ndmsg));
    nlh->nlmsg_type = nlmsg_type;
    nlh->nlmsg_flags = static_cast<std::uint16_t>(NLM_F_REQUEST | NLM_F_ACK | extra_flags);
    auto *nd = static_cast<::ndmsg *>(NLMSG_DATA(nlh));
    nd->ndm_family = AF_INET;
    nd->ndm_ifindex = static_cast<int>(ifindex);
    nd->ndm_state = ndm_state;
    std::size_t off = NLMSG_ALIGN(nlh->nlmsg_len);
    ::tc8::net::rtnl::appendAttr(buf, &off, NDA_DST, &dst_be, sizeof(dst_be));
    if (mac != nullptr) {
        ::tc8::net::rtnl::appendAttr(buf, &off, NDA_LLADDR, mac, 6);
    }
    nlh->nlmsg_len = static_cast<std::uint32_t>(off);
    return ::tc8::net::rtnl::sendRequestCheckAck(buf, nlh->nlmsg_len, enoent_ok);
}

}  // namespace

int PosixSocketBackend::createUdp() {
    return ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
}

int PosixSocketBackend::createTcp() {
    return ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

void PosixSocketBackend::setReuseAddr(int fd) {
    int on = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
}

void PosixSocketBackend::setBroadcast(int fd) {
    int on = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
}

void PosixSocketBackend::setRecvTimeoutMs(int fd, int ms) {
    timeval tv{};
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

bool PosixSocketBackend::bindV4(int fd, std::uint32_t addr_be, std::uint16_t port) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = addr_be;  // 0 == INADDR_ANY
    addr.sin_port = htons(port);
    return ::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0;
}

int PosixSocketBackend::recvFromV4(int fd, void *buf, std::size_t len, Endpoint &src) {
    sockaddr_in sa{};
    socklen_t sl = sizeof(sa);
    // MSG_TRUNC: the return value is the true datagram length even when it
    // overflows `buf` (the core caps to the buffer for the valid bytes).
    const ssize_t n =
        ::recvfrom(fd, buf, len, MSG_TRUNC, reinterpret_cast<sockaddr *>(&sa), &sl);
    if (n >= 0) {
        src.addr_be = sa.sin_addr.s_addr;
        src.port = ntohs(sa.sin_port);
    }
    return static_cast<int>(n);
}

int PosixSocketBackend::sendToV4(int fd, const void *buf, std::size_t len, const Endpoint &dst) {
    sockaddr_in d{};
    d.sin_family = AF_INET;
    d.sin_addr.s_addr = dst.addr_be;
    d.sin_port = htons(dst.port);
    return static_cast<int>(
        ::sendto(fd, buf, len, 0, reinterpret_cast<sockaddr *>(&d), sizeof(d)));
}

bool PosixSocketBackend::joinMulticast(int fd, std::uint32_t group_be, std::uint32_t ifaddr_be) {
    ip_mreq mreq{};
    mreq.imr_multiaddr.s_addr = group_be;
    mreq.imr_interface.s_addr = ifaddr_be;  // 0 == INADDR_ANY -> default interface
    return ::setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == 0;
}

bool PosixSocketBackend::leaveMulticast(int fd, std::uint32_t group_be, std::uint32_t ifaddr_be) {
    ip_mreq mreq{};
    mreq.imr_multiaddr.s_addr = group_be;
    mreq.imr_interface.s_addr = ifaddr_be;  // 0 == INADDR_ANY -> default interface
    return ::setsockopt(fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq)) == 0;
}

bool PosixSocketBackend::flushDynamicArp(const std::string &ifname) {
    // Delete the learned (non-permanent) IPv4 neighbor entries on `ifname` via a
    // direct rtnetlink dump + per-entry RTM_DELNEIGH — the same "speak netlink, do
    // not shell out to `ip neigh`" stance as destroyTimeWaitResidual (fork+exec is
    // slow and unsafe in this multi-threaded server). The dump is unprivileged; the
    // deletes need CAP_NET_ADMIN, so a flush with entries present returns false
    // without it. Two-phase (collect during the dump, delete after it drains) so
    // the delete ACKs never interleave with dump messages on the shared socket.
    const unsigned ifindex = ::if_nametoindex(ifname.c_str());
    if (ifindex == 0) {
        return false;  // unknown interface
    }
    const int nl = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (nl < 0) {
        return false;
    }

    struct {
        ::nlmsghdr nlh;
        ::ndmsg nd;
    } dump{};
    dump.nlh.nlmsg_len = sizeof(dump);
    dump.nlh.nlmsg_type = RTM_GETNEIGH;
    dump.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    dump.nd.ndm_family = AF_INET;
    if (::send(nl, &dump, sizeof(dump), 0) < 0) {
        ::close(nl);
        return false;
    }

    std::vector<std::uint32_t> targets;  // NDA_DST (network order) of entries to flush
    bool ok = true;
    bool done = false;
    char buf[8192];
    while (!done) {
        const ssize_t r = ::recv(nl, buf, sizeof(buf), 0);
        if (r <= 0) {
            ok = false;
            break;
        }
        int len = static_cast<int>(r);
        for (::nlmsghdr *nh = reinterpret_cast<::nlmsghdr *>(buf); NLMSG_OK(nh, len);
             nh = NLMSG_NEXT(nh, len)) {
            if (nh->nlmsg_type == NLMSG_DONE) {
                done = true;
                break;
            }
            if (nh->nlmsg_type == NLMSG_ERROR) {
                ok = false;
                done = true;
                break;
            }
            if (nh->nlmsg_type != RTM_NEWNEIGH) {
                continue;
            }
            const auto *nd = static_cast<const ::ndmsg *>(NLMSG_DATA(nh));
            if (nd->ndm_ifindex != static_cast<int>(ifindex) ||
                (nd->ndm_state & (NUD_PERMANENT | NUD_NOARP)) != 0) {
                continue;  // other interface, or a static/no-ARP entry we must not flush
            }
            const ::rtattr *rta = reinterpret_cast<const ::rtattr *>(
                reinterpret_cast<const char *>(nd) + NLMSG_ALIGN(sizeof(*nd)));
            int rtlen = static_cast<int>(nh->nlmsg_len - NLMSG_LENGTH(sizeof(*nd)));
            for (; RTA_OK(rta, rtlen); rta = RTA_NEXT(rta, rtlen)) {
                if (rta->rta_type == NDA_DST && RTA_PAYLOAD(rta) == sizeof(std::uint32_t)) {
                    std::uint32_t dst_be = 0;
                    std::memcpy(&dst_be, RTA_DATA(rta), sizeof(dst_be));
                    targets.push_back(dst_be);
                }
            }
        }
    }

    for (const std::uint32_t dst_be : targets) {
        // Build the RTM_DELNEIGH via the shared rtnl::appendAttr — but send it on
        // the SAME socket as the dump (the shared-socket reason this loop keeps its
        // own lenient ACK check rather than the strict sendRequestCheckAck).
        char del[256] = {};
        auto *nlh = reinterpret_cast<::nlmsghdr *>(del);
        nlh->nlmsg_len = NLMSG_LENGTH(sizeof(::ndmsg));
        nlh->nlmsg_type = RTM_DELNEIGH;
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        auto *nd = static_cast<::ndmsg *>(NLMSG_DATA(nlh));
        nd->ndm_family = AF_INET;
        nd->ndm_ifindex = static_cast<int>(ifindex);
        std::size_t off = NLMSG_ALIGN(nlh->nlmsg_len);
        ::tc8::net::rtnl::appendAttr(del, &off, NDA_DST, &dst_be, sizeof(dst_be));
        nlh->nlmsg_len = static_cast<std::uint32_t>(off);
        if (::send(nl, del, nlh->nlmsg_len, 0) < 0) {
            ok = false;
            continue;
        }
        const ssize_t r = ::recv(nl, buf, sizeof(buf), 0);
        if (r >= static_cast<ssize_t>(NLMSG_LENGTH(sizeof(::nlmsgerr)))) {
            const auto *nh = reinterpret_cast<const ::nlmsghdr *>(buf);
            if (nh->nlmsg_type == NLMSG_ERROR) {
                const auto *e = static_cast<const ::nlmsgerr *>(NLMSG_DATA(nh));
                if (e->error != 0 && e->error != -ENOENT) {  // -ENOENT = already gone (benign)
                    ok = false;
                }
            }
        }
    }
    ::close(nl);
    return ok;
}

bool PosixSocketBackend::addStaticNeighbor(const std::string &ifname, std::uint32_t addr_be,
                                           const std::uint8_t *mac) {
    const unsigned ifindex = ::if_nametoindex(ifname.c_str());
    if (ifindex == 0) {
        return false;  // unknown interface
    }
    // NUD_PERMANENT = a static entry (never aged out); NLM_F_CREATE|NLM_F_REPLACE
    // so an existing entry for this address is overwritten rather than rejected.
    return sendNeighborOp(ifindex, RTM_NEWNEIGH, NLM_F_CREATE | NLM_F_REPLACE, NUD_PERMANENT,
                          addr_be, mac, /*enoent_ok=*/false);
}

bool PosixSocketBackend::removeNeighbor(const std::string &ifname, std::uint32_t addr_be) {
    const unsigned ifindex = ::if_nametoindex(ifname.c_str());
    if (ifindex == 0) {
        return false;  // unknown interface
    }
    // No NDA_LLADDR and no state filter: the named entry is deleted whatever its
    // kind (static or learned), and a missing entry is success (-ENOENT) so the
    // remove is idempotent per the seam contract.
    return sendNeighborOp(ifindex, RTM_DELNEIGH, /*extra_flags=*/0, /*ndm_state=*/0, addr_be,
                          /*mac=*/nullptr, /*enoent_ok=*/true);
}

bool PosixSocketBackend::setNeighborReachableMs(const std::string &ifname, int reachable_ms) {
    // Reject a '/' in the name BEFORE building the procfs path: if_nametoindex does
    // NOT screen out traversal — a colon-alias form like "lo:/../.." resolves to a
    // real index (it matches the base device and ignores the suffix). The path
    // happens not to escape (the literal "<alias>:" is not a real procfs directory,
    // so open() fails ENOENT), but the safety must be enforced by code, not left to
    // an accident of procfs layout — a '/' is the only character that could traverse.
    if (reachable_ms < 0 || ifname.find('/') != std::string::npos ||
        ::if_nametoindex(ifname.c_str()) == 0) {
        return false;  // nonsensical aging time, traversal attempt, or unknown interface
    }
    // Per-interface neighbor aging is the procfs sysctl
    // /proc/sys/net/ipv4/neigh/<dev>/base_reachable_time_ms, written via the file
    // API (sysctl(2) is deprecated on Linux). The write needs CAP_NET_ADMIN, so a
    // privilege-less host gets false.
    const std::string path = "/proc/sys/net/ipv4/neigh/" + ifname + "/base_reachable_time_ms";
    const int fd = ::open(path.c_str(), O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    const std::string val = std::to_string(reachable_ms);
    const ssize_t w = ::write(fd, val.c_str(), val.size());
    ::close(fd);
    return w == static_cast<ssize_t>(val.size());
}

int PosixSocketBackend::recv(int fd, void *buf, std::size_t len) {
    return static_cast<int>(::recv(fd, buf, len, 0));
}

int PosixSocketBackend::send(int fd, const void *buf, std::size_t len) {
    // MSG_NOSIGNAL: a send to a peer that already RST/closed returns EPIPE
    // instead of raising SIGPIPE (which would kill the multi-threaded server).
    return static_cast<int>(::send(fd, buf, len, MSG_NOSIGNAL));
}

bool PosixSocketBackend::connectBoundedV4(int fd, const Endpoint &dst, int timeout_ms) {
    sockaddr_in d{};
    d.sin_family = AF_INET;
    d.sin_addr.s_addr = dst.addr_be;
    d.sin_port = htons(dst.port);

    const int flags = ::fcntl(fd, F_GETFL, 0);
    ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    bool ok = false;
    const int rc = ::connect(fd, reinterpret_cast<sockaddr *>(&d), sizeof(d));
    if (rc == 0) {
        ok = true;  // immediate (loopback) connect
    } else if (errno == EINPROGRESS) {
        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(fd, &wset);
        timeval tv{};
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        if (::select(fd + 1, nullptr, &wset, nullptr, &tv) > 0) {
            int err = 0;
            socklen_t l = sizeof(err);
            if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &l) == 0 && err == 0) {
                ok = true;
            }
        }
    }
    ::fcntl(fd, F_SETFL, flags);  // restore blocking mode
    if (ok) {
        // Record the connected 4-tuple so a later abort can SOCK_DESTROY a
        // TIME-WAIT residual (by then the tw_sock no longer maps to the fd).
        sockaddr_in local{};
        socklen_t ll = sizeof(local);
        if (::getsockname(fd, reinterpret_cast<sockaddr *>(&local), &ll) == 0) {
            std::lock_guard<std::mutex> lk(tuples_mu_);
            tuples_[fd] = TcpConnTuple{local, d};
        }
    }
    return ok;
}

bool PosixSocketBackend::listen(int fd, int backlog) {
    return ::listen(fd, backlog) == 0;
}

int PosixSocketBackend::accept(int fd, Endpoint &client) {
    sockaddr_in cli{};
    socklen_t cl = sizeof(cli);
    const int c = ::accept(fd, reinterpret_cast<sockaddr *>(&cli), &cl);
    if (c >= 0) {
        client.addr_be = cli.sin_addr.s_addr;
        client.port = ntohs(cli.sin_port);
    }
    return c;
}

bool PosixSocketBackend::shutdown(int fd, int how) {
    const int h = (how == 0) ? SHUT_RD : (how == 1) ? SHUT_WR : SHUT_RDWR;
    return ::shutdown(fd, h) == 0;
}

void PosixSocketBackend::setNonBlocking(int fd, bool on) {
    const int flags = ::fcntl(fd, F_GETFL, 0);
    ::fcntl(fd, F_SETFL, on ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK));
}

int PosixSocketBackend::waitReadable(int fd, int timeout_us) {
    fd_set rset;
    FD_ZERO(&rset);
    FD_SET(fd, &rset);
    timeval tv{};
    tv.tv_usec = timeout_us;
    const int sr = ::select(fd + 1, &rset, nullptr, nullptr, &tv);
    if (sr == 0) {
        return 0;
    }
    if (sr < 0) {
        return (errno == EINTR) ? 0 : -1;
    }
    return 1;
}

int PosixSocketBackend::poll(const int *fds, std::size_t n, int timeout_ms,
                             std::vector<int> &readable) {
    readable.clear();
    // ::poll (not select) so a long-lived UTM with many sockets is not bounded by
    // FD_SETSIZE. POLLHUP/POLLERR are treated as readable so a closed/errored
    // watched fd surfaces to its handler (whose recv() then sees 0 / -1) instead
    // of spinning silently.
    std::vector<pollfd> pfds;
    pfds.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        if (fds[i] >= 0) {
            pfds.push_back(pollfd{fds[i], POLLIN, 0});
        }
    }
    const int sr = ::poll(pfds.data(), static_cast<nfds_t>(pfds.size()), timeout_ms);
    if (sr <= 0) {
        return (sr < 0 && errno != EINTR) ? -1 : 0;  // EINTR -> treat as a timeout
    }
    for (const pollfd &p : pfds) {
        if ((p.revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
            readable.push_back(p.fd);
        }
    }
    return static_cast<int>(readable.size());
}

namespace {
// POSIX waker: a single eventfd. Its counter saturates rather than dropping a
// signal (lossless), and the one fd is both the readable end (pollFd) and the
// write end (signal). EFD_NONBLOCK so drain() never blocks. RAII-closes the fd.
class EventfdWaker final : public tc8::testability::Waker {
public:
    explicit EventfdWaker(int fd) : fd_(fd) {}
    ~EventfdWaker() override {
        if (fd_ >= 0) {
            ::close(fd_);
        }
    }
    EventfdWaker(const EventfdWaker &) = delete;
    EventfdWaker &operator=(const EventfdWaker &) = delete;

    int pollFd() const override { return fd_; }
    void signal() override {
        const std::uint64_t one = 1;
        const ssize_t w = ::write(fd_, &one, sizeof(one));
        (void)w;  // best-effort: a saturated counter is already "signaled"
    }
    void drain() override {
        std::uint64_t sink = 0;
        while (::read(fd_, &sink, sizeof(sink)) == static_cast<ssize_t>(sizeof(sink))) {
        }
    }

private:
    int fd_;
};
}  // namespace

std::unique_ptr<tc8::testability::Waker> PosixSocketBackend::createWaker() {
    const int fd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (fd < 0) {
        return nullptr;
    }
    return std::make_unique<EventfdWaker>(fd);
}

void PosixSocketBackend::closeFd(int fd) {
    {
        std::lock_guard<std::mutex> lk(tuples_mu_);
        tuples_.erase(fd);
    }
    ::close(fd);
}

void PosixSocketBackend::closeWithAbort(int fd) {
    // SO_LINGER {on, 0} makes ::close emit a RST and skip the graceful FIN
    // (PRS_TPSP §6.10 CLOSE_SOCKET abort). Reaches CLOSED from EST / FIN-WAIT /
    // CLOSING / LAST-ACK on its own; a TIME-WAIT residual needs the SOCK_DESTROY.
    const linger lg{/*l_onoff=*/1, /*l_linger=*/0};
    ::setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
    std::optional<TcpConnTuple> tuple;
    {
        std::lock_guard<std::mutex> lk(tuples_mu_);
        const auto it = tuples_.find(fd);
        if (it != tuples_.end()) {
            tuple = it->second;
            tuples_.erase(it);
        }
    }
    ::close(fd);
    if (tuple.has_value()) {
        destroyTimeWaitResidual(*tuple);
    }
}

std::uint8_t PosixSocketBackend::configureOption(int fd, std::uint16_t param_id,
                                                 const std::uint8_t *val, std::uint16_t len) {
    // PRS_TPSP §6.10.10: each fixed-width parameter must carry exactly its
    // paramVal length; a mismatch is a malformed request.
    const auto fixed = [&](std::uint16_t want) { return len == want; };
    switch (param_id) {
        case tp::kCfgTtl:  // IP TTL / hop limit
            if (!fixed(1)) return tp::kRidEInv;
            return setIntSockOpt(fd, IPPROTO_IP, IP_TTL, val[0]);
        case tp::kCfgPriority:  // traffic class / DSCP & ECN -> the IPv4 TOS byte
        case tp::kCfgTos:       // IP Type of Service (RFC 791) -> the IPv4 TOS byte
            if (!fixed(1)) return tp::kRidEInv;
            return setIntSockOpt(fd, IPPROTO_IP, IP_TOS, val[0]);
        case tp::kCfgDontFragment:  // IP DF bit via the path-MTU-discovery mode
            if (!fixed(1)) return tp::kRidEInv;
            return setIntSockOpt(fd, IPPROTO_IP, IP_MTU_DISCOVER,
                                 val[0] ? IP_PMTUDISC_DO : IP_PMTUDISC_DONT);
        case tp::kCfgIpTimestampOption:
            // paramVal is the raw option-4 bytes "as stored in the IP header"
            // (PRS_TPSP §6.10.10, RFC 791); hand them to IP_OPTIONS verbatim.
            return ::setsockopt(fd, IPPROTO_IP, IP_OPTIONS, val, len) == 0 ? tp::kRidEOk
                                                                          : tp::kRidENok;
        case tp::kCfgMss:  // TCP maximum segment size (TCP only)
            if (!fixed(2)) return tp::kRidEInv;
            return setIntSockOpt(fd, IPPROTO_TCP, TCP_MAXSEG, tp::readU16(val));
        case tp::kCfgNagle:  // Nagle enable=1 -> TCP_NODELAY is its inverse (TCP only)
            if (!fixed(1)) return tp::kRidEInv;
            return setIntSockOpt(fd, IPPROTO_TCP, TCP_NODELAY, val[0] ? 0 : 1);
        case tp::kCfgUdpChecksum:  // UDP cksum tx enable=1 -> SO_NO_CHECK is its inverse
            if (!fixed(1)) return tp::kRidEInv;
            return setIntSockOpt(fd, SOL_SOCKET, SO_NO_CHECK, val[0] ? 0 : 1);
        default:
            return tp::kRidENtf;  // unknown / non-standard parameter not served here
    }
}

std::uint8_t PosixSocketBackend::sendIcmpEcho(const std::string &ifname, std::uint32_t dst_be,
                                              const std::uint8_t *body, std::size_t len) {
    // Prefer the unprivileged ICMP datagram (ping) socket where ping_group_range
    // permits; fall back to a raw socket for root deployments where ping sockets
    // are restricted.
    int s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (s < 0) {
        s = ::socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    }
    if (s < 0) {
        return tp::kRidENok;  // no ICMP socket available (e.g. no CAP_NET_RAW)
    }
    // Optional ifName (PRS_TPSP §6.10): pin egress to the named interface. "0" /
    // empty means "any"; an unknown interface is E_IIF.
    if (!ifname.empty() && ifname != "0") {
        if (::setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, ifname.c_str(),
                         static_cast<socklen_t>(ifname.size())) < 0) {
            const int e = errno;
            ::close(s);
            return (e == ENODEV) ? tp::kRidEIif : tp::kRidENok;
        }
    }
    sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port = 0;  // ICMP is portless
    dest.sin_addr.s_addr = dst_be;
    const ssize_t sent =
        ::sendto(s, body, len, 0, reinterpret_cast<sockaddr *>(&dest), sizeof(dest));
    ::close(s);
    return (sent == static_cast<ssize_t>(len)) ? tp::kRidEOk : tp::kRidENok;
}

std::uint8_t PosixSocketBackend::sendIcmpv6Echo(const std::string &ifname,
                                                const std::uint8_t *dst16,
                                                const std::uint8_t *body, std::size_t len) {
    // The IPv6 mirror of sendIcmpEcho: an unprivileged ICMPv6 datagram (ping6)
    // socket where ping_group_range permits, falling back to a raw socket.
    int s = ::socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
    if (s < 0) {
        s = ::socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    }
    if (s < 0) {
        return tp::kRidENok;  // no ICMPv6 socket (IPv6 absent, or no CAP_NET_RAW)
    }
    unsigned scope = 0;
    if (!ifname.empty() && ifname != "0") {
        if (::setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, ifname.c_str(),
                         static_cast<socklen_t>(ifname.size())) < 0) {
            const int e = errno;
            ::close(s);
            return (e == ENODEV) ? tp::kRidEIif : tp::kRidENok;
        }
        scope = ::if_nametoindex(ifname.c_str());  // a link-local dst needs the scope id
    }
    sockaddr_in6 dest{};
    dest.sin6_family = AF_INET6;
    dest.sin6_port = 0;  // ICMPv6 is portless
    dest.sin6_scope_id = scope;
    std::memcpy(&dest.sin6_addr, dst16, 16);
    // The kernel computes the ICMPv6 checksum (IPv6 pseudo-header) for an
    // IPPROTO_ICMPV6 socket, so `body` carries a zero checksum field.
    const ssize_t sent =
        ::sendto(s, body, len, 0, reinterpret_cast<sockaddr *>(&dest), sizeof(dest));
    ::close(s);
    return (sent == static_cast<ssize_t>(len)) ? tp::kRidEOk : tp::kRidENok;
}

std::uint8_t PosixSocketBackend::setInterfaceUp(const std::string &ifname, bool up) {
    // PRS_TPSP §6.10 INTERFACE_UP / INTERFACE_DOWN: toggle IFF_UP via the classic
    // SIOCGIFFLAGS/SIOCSIFFLAGS ioctl pair. openAndResolveIface does the GET (ENODEV
    // => unknown interface => E_IIF) and hands back the current flags; flipping
    // IFF_UP is administrative and needs CAP_NET_ADMIN (EPERM => E_NOK, surfaced).
    ifreq ifr{};
    std::uint8_t rid = tp::kRidENok;
    const int s = openAndResolveIface(ifname, ifr, rid);
    if (s < 0) {
        return rid;
    }
    if (up) {
        ifr.ifr_flags |= IFF_UP;
    } else {
        ifr.ifr_flags &= ~IFF_UP;
    }
    const bool ok = ::ioctl(s, SIOCSIFFLAGS, &ifr) == 0;
    const int e = errno;
    ::close(s);
    return ok ? tp::kRidEOk : ridFromIfaceErrno(e);
}

std::uint8_t PosixSocketBackend::setStaticAddressV4(const std::string &ifname,
                                                    std::uint32_t addr_be, std::uint8_t cidr) {
    // PRS_TPSP §6.10 STATIC_ADDRESS: SIOCSIFADDR assigns the IPv4 address,
    // SIOCSIFNETMASK the mask (CIDR -> dotted via tc8::wire::cidrToMaskHost).
    // openAndResolveIface resolves the interface unprivileged first (unknown =>
    // E_IIF); the assignment then needs CAP_NET_ADMIN (EPERM => E_NOK, surfaced).
    if (cidr > 32) {
        return tp::kRidEInv;
    }
    ifreq ifr{};
    std::uint8_t rid = tp::kRidENok;
    const int s = openAndResolveIface(ifname, ifr, rid);
    if (s < 0) {
        return rid;
    }
    auto *sin = reinterpret_cast<sockaddr_in *>(&ifr.ifr_addr);
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = addr_be;
    if (::ioctl(s, SIOCSIFADDR, &ifr) < 0) {
        const int e = errno;
        ::close(s);
        return ridFromIfaceErrno(e);
    }
    sin->sin_addr.s_addr = ::htonl(tc8::wire::cidrToMaskHost(cidr));
    const bool ok = ::ioctl(s, SIOCSIFNETMASK, &ifr) == 0;
    const int e = errno;
    ::close(s);
    return ok ? tp::kRidEOk : ridFromIfaceErrno(e);
}

std::uint8_t PosixSocketBackend::setStaticRouteV4(const std::string &ifname,
                                                  std::uint32_t subnet_be, std::uint8_t cidr,
                                                  std::uint32_t gateway_be) {
    // PRS_TPSP §6.10 STATIC_ROUTE: SIOCADDRT installs a non-persistent route to
    // subnet/cidr via gateway, scoped to ifname (mirrors dhcpv4_client's default-
    // route install). The destination is masked to its network address.
    // openAndResolveIface resolves the interface first (unknown => E_IIF, before the
    // privileged SIOCADDRT reports EPERM); ENXIO also maps to E_IIF and EEXIST is
    // success (the route is already present), matching the post-condition.
    if (cidr > 32) {
        return tp::kRidEInv;
    }
    ifreq ifr{};
    std::uint8_t rid = tp::kRidENok;
    const int s = openAndResolveIface(ifname, ifr, rid);
    if (s < 0) {
        return rid;
    }
    const std::uint32_t mask_be = ::htonl(tc8::wire::cidrToMaskHost(cidr));
    rtentry rt{};
    char dev_buf[IFNAMSIZ] = {};
    std::strncpy(dev_buf, ifname.c_str(), IFNAMSIZ - 1);
    auto *dst = reinterpret_cast<sockaddr_in *>(&rt.rt_dst);
    dst->sin_family = AF_INET;
    dst->sin_addr.s_addr = subnet_be & mask_be;  // network address
    auto *mask = reinterpret_cast<sockaddr_in *>(&rt.rt_genmask);
    mask->sin_family = AF_INET;
    mask->sin_addr.s_addr = mask_be;
    auto *gw = reinterpret_cast<sockaddr_in *>(&rt.rt_gateway);
    gw->sin_family = AF_INET;
    gw->sin_addr.s_addr = gateway_be;
    rt.rt_flags = (gateway_be != 0) ? (RTF_UP | RTF_GATEWAY) : RTF_UP;
    rt.rt_dev = dev_buf;
    const int rc = ::ioctl(s, SIOCADDRT, &rt);
    const int e = errno;
    ::close(s);
    if (rc == 0 || (rc < 0 && e == EEXIST)) {
        return tp::kRidEOk;
    }
    return ridFromIfaceErrno(e, {ENODEV, ENXIO});
}

std::uint8_t PosixSocketBackend::setStaticAddressV6(const std::string &ifname,
                                                    const std::uint8_t *addr16,
                                                    std::uint8_t prefix) {
    // PRS_TPSP §6.10 STATIC_ADDRESS (IPv6): SIOCSIFADDR with a struct in6_ifreq on an
    // AF_INET6 socket assigns the address + prefix length (the IPv6 analog of the
    // SIOCSIFADDR/SIOCSIFNETMASK pair the V4 path uses). openAndResolveIfaceV6 resolves
    // the interface unprivileged first, so an unknown one is E_IIF before the
    // privileged write reports EPERM; the assignment then needs CAP_NET_ADMIN
    // (EPERM => E_NOK, surfaced).
    if (prefix > 128) {
        return tp::kRidEInv;
    }
    unsigned ifindex = 0;
    std::uint8_t rid = tp::kRidENok;
    const int s = openAndResolveIfaceV6(ifname, ifindex, rid);
    if (s < 0) {
        return rid;
    }
    in6_ifreq ifr6{};
    std::memcpy(&ifr6.addr, addr16, 16);
    ifr6.prefixlen = prefix;
    ifr6.ifindex = static_cast<int>(ifindex);
    const bool ok = ::ioctl(s, SIOCSIFADDR, &ifr6) == 0;
    const int e = errno;
    ::close(s);
    return ok ? tp::kRidEOk : ridFromIfaceErrno(e);
}

std::uint8_t PosixSocketBackend::setStaticRouteV6(const std::string &ifname,
                                                  const std::uint8_t *subnet16, std::uint8_t prefix,
                                                  const std::uint8_t *gateway16) {
    // PRS_TPSP §6.10 STATIC_ROUTE (IPv6): SIOCADDRT with a struct in6_rtmsg on an
    // AF_INET6 socket installs a non-persistent route to subnet/prefix via gateway,
    // scoped to ifname (the IPv6 analog of the rtentry SIOCADDRT the V4 path uses).
    // openAndResolveIfaceV6 resolves the interface first (unknown => E_IIF before the
    // privileged SIOCADDRT reports EPERM); ENXIO also maps to E_IIF and EEXIST is
    // success (the route is already present), matching the post-condition.
    if (prefix > 128) {
        return tp::kRidEInv;
    }
    unsigned ifindex = 0;
    std::uint8_t rid = tp::kRidENok;
    const int s = openAndResolveIfaceV6(ifname, ifindex, rid);
    if (s < 0) {
        return rid;
    }
    bool gw_zero = true;
    for (int i = 0; i < 16; ++i) {
        if (gateway16[i] != 0) {
            gw_zero = false;
            break;
        }
    }
    in6_rtmsg rt{};
    // The kernel masks rtmsg_dst by rtmsg_dst_len on insert, so (unlike the V4 rtentry
    // path, which masks rt_dst itself) the destination is copied verbatim.
    std::memcpy(&rt.dst, subnet16, 16);
    std::memcpy(&rt.gateway, gateway16, 16);
    rt.dst_len = prefix;
    rt.metric = 0;  // 0 => the kernel applies its IP6_RT_PRIO_USER default (as V4 does)
    rt.ifindex = static_cast<int>(ifindex);
    rt.flags = gw_zero ? RTF_UP : (RTF_UP | RTF_GATEWAY);
    const int rc = ::ioctl(s, SIOCADDRT, &rt);
    const int e = errno;
    ::close(s);
    if (rc == 0 || (rc < 0 && e == EEXIST)) {
        return tp::kRidEOk;
    }
    return ridFromIfaceErrno(e, {ENODEV, ENXIO});
}

void PosixSocketBackend::destroyTimeWaitResidual(const TcpConnTuple &t) {
    // sock_diag SOCK_DESTROY over a direct netlink request — terminate the
    // TIME-WAIT residual that SO_LINGER + close left behind. A direct netlink
    // send, not a shell-out to `ss -K`: fork+exec from this multi-threaded
    // server is both slow and unsafe. Best-effort and fire-and-forget.
    const int nl = ::socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);
    if (nl < 0) {
        return;
    }
    struct {
        ::nlmsghdr nlh;
        ::inet_diag_req_v2 req;
    } msg{};
    msg.nlh.nlmsg_len = sizeof(msg);
    msg.nlh.nlmsg_type = SOCK_DESTROY;
    msg.nlh.nlmsg_flags = NLM_F_REQUEST;
    msg.req.sdiag_family = AF_INET;
    msg.req.sdiag_protocol = IPPROTO_TCP;
    msg.req.idiag_states = ~0U;
    msg.req.id.idiag_sport = t.local.sin_port;  // already network byte order
    msg.req.id.idiag_dport = t.peer.sin_port;
    msg.req.id.idiag_src[0] = t.local.sin_addr.s_addr;
    msg.req.id.idiag_dst[0] = t.peer.sin_addr.s_addr;
    msg.req.id.idiag_cookie[0] = INET_DIAG_NOCOOKIE;
    msg.req.id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;
    const ssize_t sent = ::send(nl, &msg, sizeof(msg), 0);
    (void)sent;
    ::close(nl);
}

}  // namespace tc8::dut
