#include "tc8/linux_tcp_info_reader.h"

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

namespace tc8 {

bool LinuxTcpInfoReader::queryTcpInfo(int fd, net::TcpInfo &out) {
    struct tcp_info info{};
    socklen_t info_len = sizeof(info);
    if (::getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &info_len) < 0) {
        return false;
    }
    // tcpi_state passes through verbatim because the encoding (kTcpState*) is defined
    // as the kernel's TCP FSM numbering; pin the equivalence so a divergence breaks the
    // build here instead of silently re-encoding the value.
    static_assert(net::kTcpStateEstablished == TCP_ESTABLISHED &&
                      net::kTcpStateSynSent == TCP_SYN_SENT &&
                      net::kTcpStateSynRecv == TCP_SYN_RECV &&
                      net::kTcpStateFinWait1 == TCP_FIN_WAIT1 &&
                      net::kTcpStateFinWait2 == TCP_FIN_WAIT2 &&
                      net::kTcpStateTimeWait == TCP_TIME_WAIT &&
                      net::kTcpStateClose == TCP_CLOSE &&
                      net::kTcpStateCloseWait == TCP_CLOSE_WAIT &&
                      net::kTcpStateLastAck == TCP_LAST_ACK &&
                      net::kTcpStateListen == TCP_LISTEN &&
                      net::kTcpStateClosing == TCP_CLOSING,
                  "TCP state encoding must equal the kernel's TCP FSM numbering "
                  "(tcpi_state pass-through)");
    out.state = info.tcpi_state;
    out.rto_us = info.tcpi_rto;
    out.retransmits = info.tcpi_retransmits;
    out.unacked = info.tcpi_unacked;
    return true;
}

}  // namespace tc8
