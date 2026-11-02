#pragma once

#include "tc8/net/tcp_info_reader.h"

namespace tc8 {

// POSIX adapter for net::TcpInfoReader: getsockopt(TCP_INFO). Stateless.
class LinuxTcpInfoReader final : public net::TcpInfoReader {
public:
    bool queryTcpInfo(int fd, net::TcpInfo &out) override;
};

}  // namespace tc8
