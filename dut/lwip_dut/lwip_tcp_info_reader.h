#pragma once

#include "tc8/net/tcp_info_reader.h"

namespace tc8::lwip_dut {

// lwIP adapter for net::TcpInfoReader. It walks fd -> lwip_sock -> tcp_pcb under the
// core lock, because lwIP's socket layer exposes no getsockopt(TCP_INFO). A TCP socket
// whose pcb lwIP has freed reads as CLOSED, as Linux reports it; only an fd that is no
// TCP socket cannot be reported. Stateless.
class LwipTcpInfoReader final : public tc8::net::TcpInfoReader {
public:
    bool queryTcpInfo(int fd, tc8::net::TcpInfo &out) override;
};

}  // namespace tc8::lwip_dut
