#include "stimulus/tcp_client.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>

#include "stimulus/iface_addr.h"  // ipv4OfInterface — tester IPv4 (NBO) SSOT.

namespace tc8::stimulus {

int connectTcpFromIface(std::string_view iface, const Endpoint &dst,
                        std::uint32_t source_ip_be, std::uint16_t *out_local_port,
                        bool nonblocking) {
    if (out_local_port != nullptr) {
        *out_local_port = 0;
    }

    const int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::fprintf(stderr, "stimulus: tcp socket() failed: %s\n", std::strerror(errno));
        return -1;
    }

    const std::uint32_t bind_ip = source_ip_be != 0 ? source_ip_be : ipv4OfInterface(iface);
    if (bind_ip == 0) {
        std::fprintf(stderr,
                     "stimulus: interface '%.*s' has no IPv4 address — cannot bind "
                     "tester source for tcp connect\n",
                     static_cast<int>(iface.size()), iface.data());
        ::close(sock);
        return -2;
    }

    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = 0;
    bind_addr.sin_addr.s_addr = bind_ip;
    if (::bind(sock, reinterpret_cast<sockaddr *>(&bind_addr), sizeof(bind_addr)) < 0) {
        std::fprintf(stderr, "stimulus: tcp bind(ephemeral) failed: %s\n", std::strerror(errno));
        ::close(sock);
        return -3;
    }

    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(dst.port);
    peer.sin_addr.s_addr = dst.ipv4_be;
    if (::connect(sock, reinterpret_cast<sockaddr *>(&peer), sizeof(peer)) < 0) {
        std::fprintf(stderr, "stimulus: tcp connect(dut:%u) failed: %s\n",
                     dst.port, std::strerror(errno));
        ::close(sock);
        return -4;
    }

    if (out_local_port != nullptr) {
        sockaddr_in local{};
        socklen_t local_len = sizeof(local);
        if (::getsockname(sock, reinterpret_cast<sockaddr *>(&local), &local_len) == 0) {
            *out_local_port = ntohs(local.sin_port);
        }
    }

    if (nonblocking) {
        const int flags = ::fcntl(sock, F_GETFL, 0);
        if (flags < 0 || ::fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
            std::fprintf(stderr, "stimulus: tcp O_NONBLOCK failed: %s\n", std::strerror(errno));
            ::close(sock);
            return -3;
        }
    }

    return sock;
}

}  // namespace tc8::stimulus
