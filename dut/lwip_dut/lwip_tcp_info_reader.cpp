#include "lwip_tcp_info_reader.h"

#include "lwip/api.h"  // struct netconn (NETCONNTYPE_GROUP / pcb union) for the fd->pcb bridge
#include "lwip/sockets.h"
#include "lwip/tcp.h"
#include "lwip/tcpip.h"
// The fd -> pcb bridge: the lwIP socket layer exposes no getsockopt(TCP_INFO), so the
// read walks down to the tcp_pcb under the core lock. Wrapped in extern "C" because
// upstream declares lwip_socket_dbg_get_socket AFTER closing its own extern "C" block —
// without the wrapper a C++ TU sees a mangled name the C object never defines.
extern "C" {
#include "lwip/priv/sockets_priv.h"
}
// TCP_SLOW_INTERVAL (the unit of tcp_pcb.rto) and the full tcp_seg definition (walking
// the unacked queue) live in this private header. Unlike sockets_priv.h its extern "C"
// block covers every declaration, so no wrapper.
#include "lwip/priv/tcp_priv.h"

namespace tc8::lwip_dut {
namespace {

namespace net = ::tc8::net;

// lwIP's enum tcp_state numbers the FSM differently from net::kTcpState* (tcpbase.h:
// CLOSED=0 .. TIME_WAIT=10), so translate at the edge. No default branch so an upstream
// state addition surfaces as a -Wswitch warning instead of a silent zero.
std::uint8_t commonTcpState(enum tcp_state s) {
    switch (s) {
    case CLOSED:      return net::kTcpStateClose;
    case LISTEN:      return net::kTcpStateListen;
    case SYN_SENT:    return net::kTcpStateSynSent;
    case SYN_RCVD:    return net::kTcpStateSynRecv;
    case ESTABLISHED: return net::kTcpStateEstablished;
    case FIN_WAIT_1:  return net::kTcpStateFinWait1;
    case FIN_WAIT_2:  return net::kTcpStateFinWait2;
    case CLOSE_WAIT:  return net::kTcpStateCloseWait;
    case CLOSING:     return net::kTcpStateClosing;
    case LAST_ACK:    return net::kTcpStateLastAck;
    case TIME_WAIT:   return net::kTcpStateTimeWait;
    }
    return 0;
}

}  // namespace

bool LwipTcpInfoReader::queryTcpInfo(int fd, net::TcpInfo &out) {
    // The connection pcb's own fields, read under the core lock through the same
    // fd -> pcb bridge the abortive close uses. TcpInfo speaks Linux TCP_INFO
    // conventions, so the pcb values are translated at the edge (state numbering,
    // rto ticks -> microseconds).
    bool have_pcb = false;
    LOCK_TCPIP_CORE();
    struct lwip_sock *s = lwip_socket_dbg_get_socket(fd);
    if (s != nullptr && s->conn != nullptr &&
        NETCONNTYPE_GROUP(s->conn->type) == NETCONN_TCP && s->conn->pcb.tcp != nullptr) {
        const struct tcp_pcb *pcb = s->conn->pcb.tcp;
        out.state = commonTcpState(pcb->state);
        // pcb->rto counts TCP_SLOW_INTERVAL (500 ms) ticks; TcpInfo wants µs.
        out.rto_us = static_cast<std::uint32_t>(pcb->rto) * (TCP_SLOW_INTERVAL * 1000U);
        // nrtx is reset on forward progress, like the icsk_retransmits the POSIX
        // reader gets from tcpi_retransmits.
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

}  // namespace tc8::lwip_dut
