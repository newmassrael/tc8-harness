#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "net/socket_backend.h"
#include "testability/protocol_server.h"

namespace tc8::lwip_dut {

// lwIP adapter for the testability ProtocolServer's SocketBackend seam. Every
// operation is an lwIP socket call, except the two the socket layer cannot
// express: the abortive close routes through tcp_abort() on the raw pcb (lwIP
// FINs an empty-queue lingering close, so SO_LINGER does not RST), and
// ECHO_REQUEST emits through a raw pcb under the core lock (lwIP has no
// unprivileged ICMP datagram socket). No netlink SOCK_DESTROY analog exists —
// tcp_abort reaches CLOSED directly, leaving no TIME-WAIT residual to track.
class LwipSocketBackend : public tc8::testability::SocketBackend {
public:
    int createUdp() override;
    int createTcp() override;
    void setReuseAddr(int fd) override;
    void setBroadcast(int fd) override;
    void setRecvTimeoutMs(int fd, int ms) override;
    bool bindV4(int fd, std::uint32_t addr_be, std::uint16_t port) override;
    int recvFromV4(int fd, void *buf, std::size_t len, tc8::net::Endpoint &src) override;
    int sendToV4(int fd, const void *buf, std::size_t len,
                 const tc8::net::Endpoint &dst) override;
    int recv(int fd, void *buf, std::size_t len) override;
    int send(int fd, const void *buf, std::size_t len) override;
    bool connectBoundedV4(int fd, const tc8::net::Endpoint &dst, int timeout_ms) override;
    bool listen(int fd, int backlog) override;
    int accept(int fd, tc8::net::Endpoint &client) override;
    bool shutdown(int fd, int how) override;
    void setNonBlocking(int fd, bool on) override;
    int waitReadable(int fd, int timeout_us) override;
    void closeFd(int fd) override;
    void closeWithAbort(int fd) override;
    std::uint8_t configureOption(int fd, std::uint16_t param_id, const std::uint8_t *val,
                                 std::uint16_t len) override;
    std::uint8_t sendIcmpEcho(const std::string &ifname, std::uint32_t dst_be,
                              const std::uint8_t *body, std::size_t len) override;
    std::uint8_t sendIcmpv6Echo(const std::string &ifname, const std::uint8_t *dst16,
                                const std::uint8_t *body, std::size_t len) override;
    std::uint8_t setInterfaceUp(const std::string &ifname, bool up) override;
    std::uint8_t setStaticAddressV4(const std::string &ifname, std::uint32_t addr_be,
                                    std::uint8_t cidr) override;
    std::uint8_t setStaticRouteV4(const std::string &ifname, std::uint32_t subnet_be,
                                  std::uint8_t cidr, std::uint32_t gateway_be) override;
};

}  // namespace tc8::lwip_dut
