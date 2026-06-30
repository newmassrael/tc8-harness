#include "lwip_stack_probe.h"

#include <cerrno>
#include <cstring>

#include "lwip/api.h"  // struct netconn (NETCONNTYPE_GROUP / pcb union) for the fd->pcb bridge
#include "lwip/sockets.h"
#include "lwip/tcp.h"
#include "lwip/tcpip.h"
// fd -> pcb bridge for queryTcpInfo: the lwIP socket layer exposes no
// getsockopt(TCP_INFO), so the probe walks down to the tcp_pcb under the core
// lock. Wrapped in extern "C" because upstream declares
// lwip_socket_dbg_get_socket AFTER closing its own extern "C" block — without the
// wrapper a C++ TU sees a mangled name the C object never defines.
extern "C" {
#include "lwip/priv/sockets_priv.h"
}
// TCP_SLOW_INTERVAL (the unit of tcp_pcb.rto) and the full tcp_seg definition
// (walking the unacked queue) live in this private header. Unlike sockets_priv.h
// its extern "C" block covers every declaration, so no wrapper.
#include "lwip/priv/tcp_priv.h"

#include "tc8/upper_tester_protocol.h"

namespace tc8::lwip_dut {
namespace {

namespace ut = ::tc8::ut;

// The TcpInfo.state byte speaks the wire protocol's encoding
// (upper_tester_protocol.h kTcpState* = the SSOT, which equals the Linux kernel
// TCP FSM numbering — the POSIX probe passes tcpi_state through verbatim); lwIP's
// enum tcp_state numbers the same FSM differently (tcpbase.h: CLOSED=0 ..
// TIME_WAIT=10), so translate at the edge. No default branch so an upstream state
// addition surfaces as a -Wswitch warning instead of a silent zero.
std::uint8_t wireTcpState(enum tcp_state s) {
    switch (s) {
    case CLOSED:      return ut::kTcpStateClose;
    case LISTEN:      return ut::kTcpStateListen;
    case SYN_SENT:    return ut::kTcpStateSynSent;
    case SYN_RCVD:    return ut::kTcpStateSynRecv;
    case ESTABLISHED: return ut::kTcpStateEstablished;
    case FIN_WAIT_1:  return ut::kTcpStateFinWait1;
    case FIN_WAIT_2:  return ut::kTcpStateFinWait2;
    case CLOSE_WAIT:  return ut::kTcpStateCloseWait;
    case CLOSING:     return ut::kTcpStateClosing;
    case LAST_ACK:    return ut::kTcpStateLastAck;
    case TIME_WAIT:   return ut::kTcpStateTimeWait;
    }
    return 0;
}

// §4.6.5.4 UDP_FIELDS_12: the data listener must accept a 65 507 B max-length UDP
// datagram. SO_RCVBUF keeps the headroom deterministic; best-effort (the bind is
// what gates success). Matches the POSIX probe's headroom.
constexpr int kDataRcvBuf = 131072;

}  // namespace

bool LwipStackProbe::queryTcpInfo(int fd, ut::TcpInfo &out) {
    // The connection pcb's own fields, read under the core lock through the same
    // fd -> pcb bridge the abortive close uses. The wire speaks Linux TCP_INFO
    // conventions, so the pcb values are translated at the edge (state numbering,
    // rto ticks -> microseconds).
    bool have_pcb = false;
    LOCK_TCPIP_CORE();
    struct lwip_sock *s = lwip_socket_dbg_get_socket(fd);
    if (s != nullptr && s->conn != nullptr &&
        NETCONNTYPE_GROUP(s->conn->type) == NETCONN_TCP && s->conn->pcb.tcp != nullptr) {
        const struct tcp_pcb *pcb = s->conn->pcb.tcp;
        out.state = wireTcpState(pcb->state);
        // pcb->rto counts TCP_SLOW_INTERVAL (500 ms) ticks; the wire wants µs.
        out.rto_us = static_cast<std::uint32_t>(pcb->rto) * (TCP_SLOW_INTERVAL * 1000U);
        // nrtx is reset on forward progress, like the icsk_retransmits the POSIX
        // probe reads from tcpi_retransmits.
        out.retransmits = pcb->nrtx;
        // Segments on the unacked queue — the lwIP analog of tcpi_unacked.
        std::uint32_t unacked = 0;
        for (const struct tcp_seg *seg = pcb->unacked; seg != nullptr; seg = seg->next) {
            ++unacked;
        }
        out.unacked = unacked;
        have_pcb = true;
    }
    UNLOCK_TCPIP_CORE();
    return have_pcb;
}

int LwipStackProbe::recvOob(int /*fd*/, void * /*buf*/, std::size_t /*len*/, int /*timeout_ms*/) {
    // lwIP TCP implements no urgent-data path (RFC 793 §3.7 URG), so there is
    // nothing a MSG_OOB read could return. Zero is "no urgent byte" (the core
    // surfaces it as an empty receive, not an error); the affected case fails
    // visibly and is ledgered platform_known_fail.
    return 0;
}

int LwipStackProbe::openOriginalDstListenerV4(std::uint16_t port) {
    int fd = lwip_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        return -1;
    }
    int on = 1;
    // IP_PKTINFO (LWIP_NETBUF_RECVINFO) surfaces the wire destination in the
    // recvmsg ancillary data, which is how recvWithOriginalDstV4 tells
    // limited-broadcast, directed-broadcast and unicast apart for
    // ADDRESSING_01/02 — the socket-layer equivalent of the Linux probe's
    // IP_PKTINFO. SO_BROADCAST lets the socket receive the limited-broadcast
    // path. A 200 ms recv timeout lets the core loop wake to check its stop flag.
    const bool ok =
        lwip_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == 0 &&
        lwip_setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) == 0 &&
        lwip_setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) == 0;
    if (!ok) {
        lwip_close(fd);
        return -1;
    }
    timeval tv{};
    tv.tv_usec = 200 * 1000;
    lwip_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    lwip_setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &kDataRcvBuf, sizeof(kDataRcvBuf));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = lwip_htons(port);
    if (lwip_bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        lwip_close(fd);
        return -1;
    }
    return fd;
}

int LwipStackProbe::recvWithOriginalDstV4(int fd, void *buf, std::size_t len,
                                          tc8::net::Endpoint &src, std::uint32_t &orig_dst_be) {
    sockaddr_in peer{};
    iovec iov{};
    iov.iov_base = buf;
    iov.iov_len = len;
    // Headroom for the single IP_PKTINFO cmsg lwIP appends (CMSG_SPACE of one
    // in_pktinfo); a fixed buffer mirrors the POSIX probe.
    std::uint8_t cbuf[64];
    msghdr msg{};
    msg.msg_name = &peer;
    msg.msg_namelen = sizeof(peer);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    const ssize_t n = lwip_recvmsg(fd, &msg, 0);
    if (n < 0) {
        return -1;  // timeout (EWOULDBLOCK) / error — caller re-checks its stop flag
    }
    src.addr_be = peer.sin_addr.s_addr;
    src.port = lwip_ntohs(peer.sin_port);
    orig_dst_be = 0;
    for (cmsghdr *c = CMSG_FIRSTHDR(&msg); c != nullptr; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO) {
            in_pktinfo info{};
            std::memcpy(&info, CMSG_DATA(c), sizeof(info));
            orig_dst_be = info.ipi_addr.s_addr;
            break;
        }
    }
    return static_cast<int>(n);
}

}  // namespace tc8::lwip_dut
