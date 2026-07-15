#pragma once

#include <cstddef>
#include <cstdint>

#include "tc8/net/socket_backend.h"
#include "upper_tester/stack_probe.h"

namespace tc8::dut {

// POSIX (Linux) adapter for the Upper Tester's StackProbe seam: the stack
// operations the UT server needs beyond plain socket primitives (those are
// PosixSocketBackend). queryTcpInfo reads getsockopt(TCP_INFO); recvOob reads
// recv(MSG_OOB); the original-destination listener uses IP_PKTINFO ancillary
// data so the §4.4 ADDRESSING data listener can recover each datagram's wire
// destination. Stateless — every method acts on the fd or option it is given.
class PosixStackProbe : public tc8::ut::StackProbe {
public:
    bool queryTcpInfo(int fd, tc8::ut::TcpInfo &out) override;
    int recvOob(int fd, void *buf, std::size_t len, int timeout_ms) override;
    int openOriginalDstListenerV4(std::uint16_t port) override;
    int recvWithOriginalDstV4(int fd, void *buf, std::size_t len, tc8::net::Endpoint &src,
                              std::uint32_t &orig_dst_be) override;
};

}  // namespace tc8::dut
