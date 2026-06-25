#include "lwip_socket_backend.h"

#include <cerrno>
#include <memory>

#include "wire/ip_checksum.h"

#include "lwip/api.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/prot/ip.h"
#include "lwip/raw.h"
#include "lwip/sockets.h"
#include "lwip/tcp.h"
#include "lwip/tcpip.h"
// fd -> pcb bridge for the abortive close: lwIP's socket layer exposes no
// unconditional-RST path. Wrapped in extern "C" because upstream declares
// lwip_socket_dbg_get_socket after closing its own extern "C" block.
extern "C" {
#include "lwip/priv/sockets_priv.h"
}

// lwIP's LWIP_COMPAT_SOCKETS layer (sockets.h) defines recv/send/accept/listen/
// shutdown/poll as function-like macros aliasing the lwip_* forms. They collide
// with this backend's SocketBackend override names (which are the natural
// socket-API verbs the interface declares); the bodies call the lwip_* forms
// explicitly (poll() multiplexes via lwip_select), so drop just these six macros
// for this TU. Compat sockets stay enabled elsewhere, and the interface keeps
// its clean names.
#undef recv
#undef send
#undef accept
#undef listen
#undef shutdown
#undef poll

namespace tc8::lwip_dut {

namespace tp = ::tc8::testability;
using ::tc8::net::Endpoint;

int LwipSocketBackend::createUdp() {
    return lwip_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
}

int LwipSocketBackend::createTcp() {
    return lwip_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

void LwipSocketBackend::setReuseAddr(int fd) {
    int on = 1;
    lwip_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
}

void LwipSocketBackend::setBroadcast(int fd) {
    int on = 1;
    lwip_setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
}

void LwipSocketBackend::setRecvTimeoutMs(int fd, int ms) {
    timeval tv{};
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    lwip_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

bool LwipSocketBackend::bindV4(int fd, std::uint32_t addr_be, std::uint16_t port) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = addr_be;  // 0 == INADDR_ANY
    addr.sin_port = lwip_htons(port);
    return lwip_bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0;
}

int LwipSocketBackend::recvFromV4(int fd, void *buf, std::size_t len, Endpoint &src) {
    sockaddr_in sa{};
    socklen_t sl = sizeof(sa);
    const int n =
        lwip_recvfrom(fd, buf, len, MSG_TRUNC, reinterpret_cast<sockaddr *>(&sa), &sl);
    if (n >= 0) {
        src.addr_be = sa.sin_addr.s_addr;
        src.port = lwip_ntohs(sa.sin_port);
    }
    return n;
}

int LwipSocketBackend::sendToV4(int fd, const void *buf, std::size_t len, const Endpoint &dst) {
    sockaddr_in d{};
    d.sin_family = AF_INET;
    d.sin_addr.s_addr = dst.addr_be;
    d.sin_port = lwip_htons(dst.port);
    return lwip_sendto(fd, buf, len, 0, reinterpret_cast<sockaddr *>(&d), sizeof(d));
}

bool LwipSocketBackend::joinMulticast(int /*fd*/, std::uint32_t /*group_be*/,
                                      std::uint32_t /*ifaddr_be*/) {
    // IPv4 multicast reception needs LWIP_IGMP, which this fixture deliberately
    // builds OFF. A single shared lwipopts.h compiles the lwIP core ONCE for BOTH
    // tc8-lwip-dut (conformance) and tc8-lwip-utm; enabling IGMP would add
    // all-systems (224.0.0.1) membership and IGMP report emission to the
    // conformance DUT's wire behaviour, perturbing the broadcast/multicast
    // silent-discard cases (UDP_INTRODUCTION_02 et al.). So multicast rx is
    // deferred for the lwIP backend: report false (surfaced, not silently
    // dropped) — a module that needs the group degrades exactly as on a failed
    // bind. A UTM-only deployment that opts into LWIP_IGMP would implement this as
    // lwip_setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &ip_mreq{group, iface}).
    return false;
}

int LwipSocketBackend::recv(int fd, void *buf, std::size_t len) {
    return lwip_recv(fd, buf, len, 0);
}

int LwipSocketBackend::send(int fd, const void *buf, std::size_t len) {
    return lwip_send(fd, buf, len, 0);
}

bool LwipSocketBackend::connectBoundedV4(int fd, const Endpoint &dst, int timeout_ms) {
    sockaddr_in d{};
    d.sin_family = AF_INET;
    d.sin_addr.s_addr = dst.addr_be;
    d.sin_port = lwip_htons(dst.port);

    const int flags = lwip_fcntl(fd, F_GETFL, 0);
    lwip_fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    bool ok = false;
    const int rc = lwip_connect(fd, reinterpret_cast<sockaddr *>(&d), sizeof(d));
    if (rc == 0) {
        ok = true;
    } else if (errno == EINPROGRESS) {
        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(fd, &wset);
        timeval tv{};
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        if (lwip_select(fd + 1, nullptr, &wset, nullptr, &tv) > 0) {
            int err = 0;
            socklen_t l = sizeof(err);
            if (lwip_getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &l) == 0 && err == 0) {
                ok = true;
            }
        }
    }
    lwip_fcntl(fd, F_SETFL, flags);  // restore blocking mode
    return ok;
}

bool LwipSocketBackend::listen(int fd, int backlog) {
    return lwip_listen(fd, backlog) == 0;
}

int LwipSocketBackend::accept(int fd, Endpoint &client) {
    sockaddr_in cli{};
    socklen_t cl = sizeof(cli);
    const int c = lwip_accept(fd, reinterpret_cast<sockaddr *>(&cli), &cl);
    if (c >= 0) {
        client.addr_be = cli.sin_addr.s_addr;
        client.port = lwip_ntohs(cli.sin_port);
    }
    return c;
}

bool LwipSocketBackend::shutdown(int fd, int how) {
    const int h = (how == 0) ? SHUT_RD : (how == 1) ? SHUT_WR : SHUT_RDWR;
    return lwip_shutdown(fd, h) == 0;
}

void LwipSocketBackend::setNonBlocking(int fd, bool on) {
    const int flags = lwip_fcntl(fd, F_GETFL, 0);
    lwip_fcntl(fd, F_SETFL, on ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK));
}

int LwipSocketBackend::waitReadable(int fd, int timeout_us) {
    fd_set rset;
    FD_ZERO(&rset);
    FD_SET(fd, &rset);
    timeval tv{};
    tv.tv_usec = timeout_us;
    const int sr = lwip_select(fd + 1, &rset, nullptr, nullptr, &tv);
    if (sr == 0) {
        return 0;
    }
    if (sr < 0) {
        return (errno == EINTR) ? 0 : -1;
    }
    return 1;
}

int LwipSocketBackend::poll(const int *fds, std::size_t n, int timeout_ms,
                            std::vector<int> &readable) {
    readable.clear();
    // lwIP socket fds are small contiguous indices, so FD_SETSIZE bounds them
    // comfortably and lwip_select is the natural multiplexer (mirrors waitReadable
    // and connectBoundedV4). A negative timeout_ms is an indefinite wait (NULL
    // timeval); otherwise convert to a timeval. Divergence from the POSIX ::poll
    // backend: lwip_select is an fd_set API with no per-fd revents, so a
    // hung-up/errored watched socket is NOT surfaced as readable here (the reactor
    // contract requires unwatch-before-close, so a watched fd is never left closed
    // in the set).
    fd_set rset;
    FD_ZERO(&rset);
    int maxfd = -1;
    for (std::size_t i = 0; i < n; ++i) {
        if (fds[i] >= 0) {
            FD_SET(fds[i], &rset);
            if (fds[i] > maxfd) {
                maxfd = fds[i];
            }
        }
    }
    timeval tv{};
    timeval *ptv = nullptr;
    if (timeout_ms >= 0) {
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        ptv = &tv;
    }
    const int sr = lwip_select(maxfd + 1, &rset, nullptr, nullptr, ptv);
    if (sr <= 0) {
        return (sr < 0 && errno != EINTR) ? -1 : 0;  // EINTR -> treat as a timeout
    }
    for (std::size_t i = 0; i < n; ++i) {
        if (fds[i] >= 0 && FD_ISSET(fds[i], &rset)) {
            readable.push_back(fds[i]);
        }
    }
    return static_cast<int>(readable.size());
}

namespace {
// lwIP waker: a 127.0.0.1 UDP socket PAIR (the loopback netif exists because
// LWIP_NETIF_LOOPBACK is set). The executor reads/polls the RECEIVER; any thread
// signals by sending 1 byte on the connected SENDER — two distinct sockets, so no
// lwIP socket is ever touched by two threads at once (lwIP permits same-socket
// multi-thread use only with LWIP_NETCONN_FULLDUPLEX, off here). The object owns
// both fds and closes them on destruction (the sender first). signal() is
// best-effort: a loopback datagram can drop under pbuf exhaustion, so the reactor
// backstops liveness — a lost wake only delays, never loses, an enqueued task.
class LoopbackWaker final : public tc8::testability::Waker {
public:
    LoopbackWaker(int rx, int tx) : rx_(rx), tx_(tx) {}
    ~LoopbackWaker() override {
        lwip_close(tx_);
        lwip_close(rx_);
    }
    LoopbackWaker(const LoopbackWaker &) = delete;
    LoopbackWaker &operator=(const LoopbackWaker &) = delete;

    int pollFd() const override { return rx_; }
    void signal() override {
        const std::uint8_t b = 1;
        lwip_send(tx_, &b, 1, 0);  // connected sender -> loops to the receiver
    }
    void drain() override {
        std::uint8_t sink[64];
        while (lwip_recv(rx_, sink, sizeof(sink), 0) > 0) {
        }
    }

private:
    int rx_;
    int tx_;
};
}  // namespace

std::unique_ptr<tc8::testability::Waker> LwipSocketBackend::createWaker() {
    // Runs on the server thread before the executor starts, so the getsockname()
    // here touches a not-yet-shared socket. Both sockets bind 127.0.0.1 (loopback
    // netif); the sender is connected to the receiver's ephemeral port so signal()
    // is a 1-byte send that loops back inside the stack (no wire emission).
    const int rx = lwip_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (rx < 0) {
        return nullptr;
    }
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = PP_HTONL(IPADDR_LOOPBACK);  // 127.0.0.1 via the loopback netif
    a.sin_port = 0;                                 // ephemeral
    socklen_t al = sizeof(a);
    if (lwip_bind(rx, reinterpret_cast<sockaddr *>(&a), sizeof(a)) != 0 ||
        lwip_getsockname(rx, reinterpret_cast<sockaddr *>(&a), &al) != 0) {  // learn the port
        lwip_close(rx);
        return nullptr;
    }
    lwip_fcntl(rx, F_SETFL, lwip_fcntl(rx, F_GETFL, 0) | O_NONBLOCK);
    const int tx = lwip_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (tx < 0) {
        lwip_close(rx);
        return nullptr;
    }
    if (lwip_connect(tx, reinterpret_cast<sockaddr *>(&a), sizeof(a)) != 0) {  // (127.0.0.1, rx port)
        lwip_close(tx);
        lwip_close(rx);
        return nullptr;
    }
    return std::make_unique<LoopbackWaker>(rx, tx);
}

void LwipSocketBackend::closeFd(int fd) {
    lwip_close(fd);
}

void LwipSocketBackend::closeWithAbort(int fd) {
    // tcp_abort() on the raw pcb is lwIP's actual abort primitive — its
    // SO_LINGER{on,0} close only aborts while unsent/unacked data remains
    // (api_msg.c), an empty queue always FINs. Then lwip_close reaps the slot.
    LOCK_TCPIP_CORE();
    struct lwip_sock *s = lwip_socket_dbg_get_socket(fd);
    if (s != nullptr && s->conn != nullptr &&
        NETCONNTYPE_GROUP(s->conn->type) == NETCONN_TCP && s->conn->pcb.tcp != nullptr) {
        tcp_abort(s->conn->pcb.tcp);
    }
    UNLOCK_TCPIP_CORE();
    lwip_close(fd);
}

std::uint8_t LwipSocketBackend::configureOption(int fd, std::uint16_t param_id,
                                                const std::uint8_t *val, std::uint16_t len) {
    const auto fixed = [&](std::uint16_t want) { return len == want; };
    const auto setIntOpt = [&](int level, int optname, int value) -> std::uint8_t {
        return lwip_setsockopt(fd, level, optname, &value, sizeof(value)) == 0 ? tp::kRidEOk
                                                                               : tp::kRidENok;
    };
    switch (param_id) {
        case tp::kCfgTtl:  // IP TTL / hop limit
            if (!fixed(1)) return tp::kRidEInv;
            return setIntOpt(IPPROTO_IP, IP_TTL, val[0]);
        case tp::kCfgPriority:  // traffic class / DSCP & ECN -> the IPv4 TOS byte
        case tp::kCfgTos:       // IP Type of Service (RFC 791) -> the IPv4 TOS byte
            if (!fixed(1)) return tp::kRidEInv;
            return setIntOpt(IPPROTO_IP, IP_TOS, val[0]);
        case tp::kCfgNagle:  // Nagle enable=1 -> TCP_NODELAY is its inverse (TCP only)
            if (!fixed(1)) return tp::kRidEInv;
            return setIntOpt(IPPROTO_TCP, TCP_NODELAY, val[0] ? 0 : 1);
        case tp::kCfgUdpChecksum:  // UDP cksum tx enable=1 -> SO_NO_CHECK is its inverse
            if (!fixed(1)) return tp::kRidEInv;
            return setIntOpt(SOL_SOCKET, SO_NO_CHECK, val[0] ? 0 : 1);
        case tp::kCfgDontFragment:       // IP DF bit (Linux IP_MTU_DISCOVER)
        case tp::kCfgIpTimestampOption:  // IP option-4 bytes (Linux IP_OPTIONS)
        case tp::kCfgMss:                // TCP MSS clamp (Linux TCP_MAXSEG)
            // lwIP's socket layer exposes no DF-bit, IP-options or MSS-clamp
            // setsockopt — answer E_NOK so a tester sees the rejection rather
            // than a false success (a case depending on one would be ledgered
            // platform_known_fail, like the OOB / reassembly gaps).
            return tp::kRidENok;
        default:
            return tp::kRidENtf;  // unknown / non-standard parameter not served here
    }
}

std::uint8_t LwipSocketBackend::sendIcmpEcho(const std::string &ifname, std::uint32_t dst_be,
                                             const std::uint8_t *body, std::size_t len) {
    // lwIP's socket layer offers no unprivileged ICMP datagram (ping) socket, so
    // emit through a raw pcb on IP_PROTO_ICMP under the core lock — the stack
    // builds the IP header and the named-interface egress. The body (framed by
    // the core via tc8::wire) is already checksummed and the raw pcb leaves it
    // untouched (chksum_reqd defaults to 0), so there is no double-checksum.
    std::uint8_t rid = tp::kRidENok;
    LOCK_TCPIP_CORE();
    struct raw_pcb *pcb = raw_new(IP_PROTO_ICMP);
    if (pcb != nullptr) {
        bool iface_ok = true;
        // Optional ifName (PRS_TPSP §6.10): pin egress to the named netif. "0" /
        // empty means "any"; an unknown interface is E_IIF.
        if (!ifname.empty() && ifname != "0") {
            struct netif *nif = netif_find(ifname.c_str());
            if (nif == nullptr) {
                iface_ok = false;
                rid = tp::kRidEIif;
            } else {
                raw_bind_netif(pcb, nif);
            }
        }
        if (iface_ok) {
            struct pbuf *p = pbuf_alloc(PBUF_IP, static_cast<u16_t>(len), PBUF_RAM);
            if (p != nullptr) {
                pbuf_take(p, body, static_cast<u16_t>(len));
                ip_addr_t dst;
                ip_addr_set_ip4_u32_val(dst, dst_be);
                rid = (raw_sendto(pcb, p, &dst) == ERR_OK) ? tp::kRidEOk : tp::kRidENok;
                pbuf_free(p);
            }
        }
        raw_remove(pcb);
    }
    UNLOCK_TCPIP_CORE();
    return rid;
}

std::uint8_t LwipSocketBackend::sendIcmpv6Echo(const std::string & /*ifname*/,
                                               const std::uint8_t * /*dst16*/,
                                               const std::uint8_t * /*body*/,
                                               std::size_t /*len*/) {
    // This fixture's lwipopts.h builds the stack with LWIP_IPV6 == 0, so there is
    // no ICMPv6 emit path. Report E_NOK — surfaced, not silently accepted, the
    // same way the unsupported CONFIGURE_SOCKET options answer. A deployment that
    // enables IPv6 would add a raw ip6 pcb emit here, mirroring sendIcmpEcho.
    return tp::kRidENok;
}

std::uint8_t LwipSocketBackend::setInterfaceUp(const std::string &ifname, bool up) {
    // PRS_TPSP §6.10 INTERFACE_UP / INTERFACE_DOWN: toggle the netif's
    // administrative state under the core lock. netif_find resolves the name
    // (an unknown / unnamed interface is null => E_IIF); there is no privilege
    // gate in a single-process stack, so a resolved netif always succeeds.
    std::uint8_t rid;
    LOCK_TCPIP_CORE();
    struct netif *nif = netif_find(ifname.c_str());
    if (nif == nullptr) {
        rid = tp::kRidEIif;
    } else {
        if (up) {
            netif_set_up(nif);
        } else {
            netif_set_down(nif);
        }
        rid = tp::kRidEOk;
    }
    UNLOCK_TCPIP_CORE();
    return rid;
}

std::uint8_t LwipSocketBackend::setStaticAddressV4(const std::string &ifname, std::uint32_t addr_be,
                                                   std::uint8_t cidr) {
    // PRS_TPSP §6.10 STATIC_ADDRESS: assign the address + CIDR netmask via
    // netif_set_addr under the core lock, keeping the existing gateway (the SP
    // carries no gateway). netif_find resolves the name (unknown => E_IIF); a
    // single-process stack has no privilege gate, so a resolved netif succeeds.
    if (cidr > 32) {
        return tp::kRidEInv;
    }
    std::uint8_t rid;
    LOCK_TCPIP_CORE();
    struct netif *nif = netif_find(ifname.c_str());
    if (nif == nullptr) {
        rid = tp::kRidEIif;
    } else {
        ip4_addr_t ip{};
        ip4_addr_t nm{};
        ip4_addr_set_u32(&ip, addr_be);
        ip4_addr_set_u32(&nm, lwip_htonl(tc8::wire::cidrToMaskHost(cidr)));
        netif_set_addr(nif, &ip, &nm, netif_ip4_gw(nif));
        rid = tp::kRidEOk;
    }
    UNLOCK_TCPIP_CORE();
    return rid;
}

std::uint8_t LwipSocketBackend::setStaticRouteV4(const std::string &ifname, std::uint32_t /*subnet*/,
                                                 std::uint8_t /*cidr*/, std::uint32_t /*gateway*/) {
    // PRS_TPSP §6.10 STATIC_ROUTE: base lwIP routes by netif (one default gateway
    // per interface), with no general per-subnet routing table — a faithful "add a
    // route for this subnet via this gateway" is not expressible. Report E_NOK
    // (surfaced, not silently dropped), the same unsupported-capability convention
    // as the IPv6/DF/MSS stubs. The interface is still resolved so an unknown one
    // is E_IIF rather than a blanket E_NOK.
    std::uint8_t rid;
    LOCK_TCPIP_CORE();
    struct netif *nif = netif_find(ifname.c_str());
    rid = (nif == nullptr) ? tp::kRidEIif : tp::kRidENok;
    UNLOCK_TCPIP_CORE();
    return rid;
}

std::uint8_t LwipSocketBackend::setStaticAddressV6(const std::string &ifname,
                                                   const std::uint8_t * /*addr16*/,
                                                   std::uint8_t /*prefix*/) {
    // PRS_TPSP §6.10 STATIC_ADDRESS (IPv6): this fixture builds lwIP with LWIP_IPV6 0
    // (see lwipopts.h), so there is no ip6 address to assign. Report E_NOK for the
    // missing capability (surfaced, not silently dropped), but — unlike sendIcmpv6Echo,
    // which returns a blanket E_NOK — still resolve the interface (as setStaticRouteV4 /
    // setInterfaceUp do) so an unknown one is E_IIF.
    std::uint8_t rid;
    LOCK_TCPIP_CORE();
    struct netif *nif = netif_find(ifname.c_str());
    rid = (nif == nullptr) ? tp::kRidEIif : tp::kRidENok;
    UNLOCK_TCPIP_CORE();
    return rid;
}

std::uint8_t LwipSocketBackend::setStaticRouteV6(const std::string &ifname,
                                                 const std::uint8_t * /*subnet16*/,
                                                 std::uint8_t /*prefix*/,
                                                 const std::uint8_t * /*gateway16*/) {
    // PRS_TPSP §6.10 STATIC_ROUTE (IPv6): with LWIP_IPV6 0 there is no ip6 routing
    // path; like setStaticRouteV4 (no per-subnet table) and setStaticAddressV6, this
    // answers E_NOK for the missing capability (surfaced), resolving the interface (as
    // setStaticRouteV4 does) so an unknown one is E_IIF.
    std::uint8_t rid;
    LOCK_TCPIP_CORE();
    struct netif *nif = netif_find(ifname.c_str());
    rid = (nif == nullptr) ? tp::kRidEIif : tp::kRidENok;
    UNLOCK_TCPIP_CORE();
    return rid;
}

}  // namespace tc8::lwip_dut
