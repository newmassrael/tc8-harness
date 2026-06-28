#include "stimulus/udp_emit.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "stimulus/iface_addr.h"
#include "stimulus/ipv4_frame_builder.h"
#include "stimulus/udp_datagram_builder.h"

namespace tc8::stimulus {

namespace {

// A UDP socket bound to a chosen source port on a chosen interface, paired with
// that interface's resolved IPv4 address (the multicast path needs it for
// IP_MULTICAST_IF). `fd < 0` is a failure sentinel — one of the negative codes
// the public emitters document; `if_addr` is meaningful only when `fd >= 0`.
struct BoundSocket {
    int fd;
    std::uint32_t if_addr;
};

// The shared prologue of every UDP emit: open a datagram socket, resolve the
// interface IPv4, and bind the source port to it. SO_REUSEADDR lets successive
// one-shot emits reuse the same source port without TIME_WAIT recycling.
BoundSocket openBoundUdpSocket(std::string_view iface_name, std::uint16_t src_port) {
    const int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::fprintf(stderr, "stimulus: socket() failed: %s\n", std::strerror(errno));
        return {-1, 0};
    }

    const std::uint32_t if_addr = ipv4OfInterface(iface_name);
    if (if_addr == 0) {
        std::fprintf(stderr, "stimulus: interface '%.*s' has no IPv4 address — cannot bind UDP source\n",
                     static_cast<int>(iface_name.size()), iface_name.data());
        ::close(sock);
        return {-2, 0};
    }

    const int reuse = 1;
    if (::setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        std::fprintf(stderr, "stimulus: setsockopt(SO_REUSEADDR) failed: %s\n", std::strerror(errno));
        ::close(sock);
        return {-7, 0};
    }

    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(src_port);
    bind_addr.sin_addr.s_addr = if_addr;
    if (::bind(sock, reinterpret_cast<sockaddr *>(&bind_addr), sizeof(bind_addr)) < 0) {
        std::fprintf(stderr, "stimulus: bind(source port %u) failed: %s\n", src_port, std::strerror(errno));
        ::close(sock);
        return {-7, 0};
    }

    return {sock, if_addr};
}

}  // namespace

int sendUdpUnicast(const std::vector<std::uint8_t> &datagram, std::string_view iface_name,
                   std::uint16_t src_port, std::uint32_t dst_ip_be, std::uint16_t dst_port) {
    const BoundSocket bs = openBoundUdpSocket(iface_name, src_port);
    if (bs.fd < 0) {
        return bs.fd;
    }

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dst_port);
    dst.sin_addr.s_addr = dst_ip_be;

    const ssize_t n =
        ::sendto(bs.fd, datagram.data(), datagram.size(), 0, reinterpret_cast<sockaddr *>(&dst), sizeof(dst));
    const int saved_errno = errno;
    ::close(bs.fd);

    if (n < 0 || static_cast<std::size_t>(n) != datagram.size()) {
        std::fprintf(stderr, "stimulus: sendto(unicast %u.%u.%u.%u:%u) failed: %s (sent=%zd of %zu)\n",
                     (dst_ip_be >> 0) & 0xFFU, (dst_ip_be >> 8) & 0xFFU, (dst_ip_be >> 16) & 0xFFU,
                     (dst_ip_be >> 24) & 0xFFU, dst_port, std::strerror(saved_errno), n, datagram.size());
        return -6;
    }
    return 0;
}

int sendUdpMulticast(const std::vector<std::uint8_t> &datagram, std::string_view iface_name,
                     std::uint16_t src_port, std::string_view mcast_group, std::uint16_t mcast_port,
                     std::uint8_t ttl) {
    const BoundSocket bs = openBoundUdpSocket(iface_name, src_port);
    if (bs.fd < 0) {
        return bs.fd;
    }

    // Pin egress to the bound interface — on veth setups the default-route choice
    // is fragile.
    in_addr mcast_if{};
    mcast_if.s_addr = bs.if_addr;
    if (::setsockopt(bs.fd, IPPROTO_IP, IP_MULTICAST_IF, &mcast_if, sizeof(mcast_if)) < 0) {
        std::fprintf(stderr, "stimulus: setsockopt(IP_MULTICAST_IF) failed: %s\n", std::strerror(errno));
        ::close(bs.fd);
        return -3;
    }

    if (::setsockopt(bs.fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0) {
        std::fprintf(stderr, "stimulus: setsockopt(IP_MULTICAST_TTL) failed: %s\n", std::strerror(errno));
        ::close(bs.fd);
        return -4;
    }

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(mcast_port);
    if (::inet_pton(AF_INET, std::string(mcast_group).c_str(), &dst.sin_addr) != 1) {
        std::fprintf(stderr, "stimulus: inet_pton('%.*s') failed\n", static_cast<int>(mcast_group.size()),
                     mcast_group.data());
        ::close(bs.fd);
        return -5;
    }

    const ssize_t n =
        ::sendto(bs.fd, datagram.data(), datagram.size(), 0, reinterpret_cast<sockaddr *>(&dst), sizeof(dst));
    const int saved_errno = errno;
    ::close(bs.fd);

    if (n < 0 || static_cast<std::size_t>(n) != datagram.size()) {
        std::fprintf(stderr, "stimulus: sendto(%.*s:%u) failed: %s (sent=%zd of %zu)\n",
                     static_cast<int>(mcast_group.size()), mcast_group.data(), mcast_port,
                     std::strerror(saved_errno), n, datagram.size());
        return -6;
    }
    return 0;
}

std::vector<std::uint8_t> buildUdpFromSourceIpFrame(
    const std::vector<std::uint8_t> &payload, std::uint32_t src_ip_be, std::uint16_t src_port,
    std::uint32_t dst_ip_be, std::uint16_t dst_port, const std::array<std::uint8_t, 6> &dst_mac,
    const std::array<std::uint8_t, 6> &src_mac) {
    const std::vector<std::uint8_t> udp =
        buildUdpDatagram(src_ip_be, dst_ip_be, src_port, dst_port, payload.data(), payload.size());
    Ipv4FrameSpec spec{};
    spec.src_mac = src_mac;
    spec.dst_mac = dst_mac;
    spec.src_ip = src_ip_be;
    spec.dst_ip = dst_ip_be;
    spec.ip_protocol = kIpProtoUdp;
    return buildIpv4Frame(spec, udp);
}

int sendUdpFromSourceIp(const std::vector<std::uint8_t> &payload, std::string_view iface,
                        std::uint32_t src_ip_be, std::uint16_t src_port, std::uint32_t dst_ip_be,
                        std::uint16_t dst_port, const std::array<std::uint8_t, 6> &dst_mac,
                        const std::array<std::uint8_t, 6> &src_mac) {
    const std::vector<std::uint8_t> frame = buildUdpFromSourceIpFrame(
        payload, src_ip_be, src_port, dst_ip_be, dst_port, dst_mac, src_mac);
    return sendRawEthernet(frame, iface);
}

}  // namespace tc8::stimulus
