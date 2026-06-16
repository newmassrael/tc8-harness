#include "posix_stack_probe.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "tc8/upper_tester_protocol.h"

namespace tc8::dut {

namespace {
namespace ut = ::tc8::ut;

// §4.6.5.4 UDP_FIELDS_12: the data listener must accept a 65 507 B max-length
// UDP datagram. SO_RCVBUF keeps the headroom deterministic across distro /
// netns sysctl defaults; best-effort (the bind is what gates success).
constexpr int kDataRcvBuf = 131072;
}  // namespace

bool PosixStackProbe::queryTcpInfo(int fd, ut::TcpInfo &out) {
    struct tcp_info info{};
    socklen_t info_len = sizeof(info);
    if (::getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &info_len) < 0) {
        return false;
    }
    // tcpi_state passes through verbatim because the wire encoding
    // (upper_tester_protocol.h kTcpState*) is defined as the kernel's TCP FSM
    // numbering; pin the equivalence so a divergence breaks the build here
    // instead of silently re-encoding the wire.
    static_assert(ut::kTcpStateEstablished == TCP_ESTABLISHED &&
                      ut::kTcpStateSynSent == TCP_SYN_SENT &&
                      ut::kTcpStateSynRecv == TCP_SYN_RECV &&
                      ut::kTcpStateFinWait1 == TCP_FIN_WAIT1 &&
                      ut::kTcpStateFinWait2 == TCP_FIN_WAIT2 &&
                      ut::kTcpStateTimeWait == TCP_TIME_WAIT &&
                      ut::kTcpStateClose == TCP_CLOSE &&
                      ut::kTcpStateCloseWait == TCP_CLOSE_WAIT &&
                      ut::kTcpStateLastAck == TCP_LAST_ACK &&
                      ut::kTcpStateListen == TCP_LISTEN &&
                      ut::kTcpStateClosing == TCP_CLOSING,
                  "wire TCP state encoding must equal the kernel's TCP FSM "
                  "numbering (tcpi_state pass-through)");
    out.state = info.tcpi_state;
    out.rto_us = info.tcpi_rto;
    out.retransmits = info.tcpi_retransmits;
    out.unacked = info.tcpi_unacked;
    return true;
}

int PosixStackProbe::recvOob(int fd, void *buf, std::size_t len, int timeout_ms) {
    // Linux's OOB queue holds at most one byte per URG segment under default
    // sysctl_tcp_stdurg=0 / SO_OOBINLINE off, so a single recv(MSG_OOB) is
    // enough — a retry would EINVAL ("no oob data"). Bound it with SO_RCVTIMEO
    // so a stuck stimulus returns within the caller's budget. A non-positive
    // result (timeout / EINVAL / peer close) is "no urgent byte" = 0.
    timeval tv{};
    tv.tv_sec = static_cast<time_t>(timeout_ms / 1000);
    tv.tv_usec = static_cast<suseconds_t>((timeout_ms % 1000) * 1000);
    if (::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        return 0;
    }
    const ssize_t rc = ::recv(fd, buf, len, MSG_OOB);
    return rc > 0 ? static_cast<int>(rc) : 0;
}

int PosixStackProbe::openOriginalDstListenerV4(std::uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        return -1;
    }
    int on = 1;
    // IP_PKTINFO surfaces the wire-level destination in ancillary data, which is
    // how recvWithOriginalDstV4 tells limited-broadcast (255.255.255.255),
    // directed-broadcast (172.16.0.255), and unicast apart for ADDRESSING_01/02.
    // SO_BROADCAST lets the socket receive the limited-broadcast path. A
    // 200 ms recv timeout lets the core loop wake to check its stop flag.
    const bool ok =
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == 0 &&
        ::setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) == 0 &&
        ::setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) == 0;
    if (!ok) {
        ::close(fd);
        return -1;
    }
    timeval tv{};
    tv.tv_usec = 200 * 1000;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &kDataRcvBuf, sizeof(kDataRcvBuf));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

int PosixStackProbe::recvWithOriginalDstV4(int fd, void *buf, std::size_t len,
                                           tc8::net::Endpoint &src,
                                           std::uint32_t &orig_dst_be) {
    sockaddr_in peer{};
    iovec iov{};
    iov.iov_base = buf;
    iov.iov_len = len;
    std::uint8_t cbuf[512];
    msghdr msg{};
    msg.msg_name = &peer;
    msg.msg_namelen = sizeof(peer);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    const ssize_t n = ::recvmsg(fd, &msg, 0);
    if (n < 0) {
        return -1;  // timeout (EAGAIN) / error — caller re-checks its stop flag
    }
    src.addr_be = peer.sin_addr.s_addr;
    src.port = ntohs(peer.sin_port);
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

}  // namespace tc8::dut
