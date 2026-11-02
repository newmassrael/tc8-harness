#include "lwip_stack_probe.h"

#include <cerrno>
#include <cstring>

#include "lwip/sockets.h"

#include "lwip_tcp_info_reader.h"

namespace tc8::lwip_dut {
namespace {

// §4.6.5.4 UDP_FIELDS_12: the data listener must accept a 65 507 B max-length UDP
// datagram. SO_RCVBUF keeps the headroom deterministic; best-effort (the bind is
// what gates success). Matches the POSIX probe's headroom.
constexpr int kDataRcvBuf = 131072;

}  // namespace

bool LwipStackProbe::queryTcpInfo(int fd, tc8::net::TcpInfo &out) {
    return LwipTcpInfoReader{}.queryTcpInfo(fd, out);
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
