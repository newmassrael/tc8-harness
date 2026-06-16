#pragma once

#include <cstddef>
#include <cstdint>

#include "net/socket_backend.h"
#include "upper_tester/stack_probe.h"

namespace tc8::lwip_dut {

// lwIP adapter for the Upper Tester's StackProbe seam: the stack operations the
// UT server needs beyond the plain socket primitives (those are
// LwipSocketBackend). queryTcpInfo walks fd -> lwip_sock -> tcp_pcb under the
// core lock, because lwIP's socket layer exposes no getsockopt(TCP_INFO);
// recvOob returns zero, because lwIP TCP implements no RFC 793 urgent path; the
// original-destination listener uses a UDP socket with IP_PKTINFO
// (LWIP_NETBUF_RECVINFO) so the §4.4.4.5 ADDRESSING data listener can recover each
// datagram's wire destination — the socket-layer equivalent of the Linux
// IP_PKTINFO path, replacing the former core-API udp_recv callback that read
// ip_current_dest_addr() directly. Stateless — every method acts on the fd it is
// given (the core owns the receipt store and the broadcast/multicast discard).
class LwipStackProbe : public tc8::ut::StackProbe {
public:
    bool queryTcpInfo(int fd, tc8::ut::TcpInfo &out) override;
    int recvOob(int fd, void *buf, std::size_t len, int timeout_ms) override;
    int openOriginalDstListenerV4(std::uint16_t port) override;
    int recvWithOriginalDstV4(int fd, void *buf, std::size_t len, tc8::net::Endpoint &src,
                              std::uint32_t &orig_dst_be) override;
};

}  // namespace tc8::lwip_dut
