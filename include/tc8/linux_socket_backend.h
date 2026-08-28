#pragma once

#include <netinet/in.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "tc8/net/socket_backend.h"
#include "tc8/testability/socket_backend.h"

namespace tc8::dut {

// The Linux adapter for the testability ProtocolServer's SocketBackend seam.
//
// The name is the contract: this is Linux, not POSIX. It does not compile on
// QNX, the BSDs, or any other POSIX system, because it reaches past the
// portable socket API in four places:
//
//   * rtnetlink (<linux/netlink.h>, <linux/rtnetlink.h>) for the neighbor
//     operations — flush / add-static / remove
//   * sock_diag SOCK_DESTROY for the abortive close that also clears a
//     TIME-WAIT residual
//   * eventfd for the waker, and /proc/sys/net/ipv4/neigh/... for the
//     reachable-time knob
//   * SO_BINDTODEVICE for interface pinning
//
// None of that is a defect: the operations a TC8 Upper Tester must perform
// (shape the neighbor cache, destroy a socket abortively) simply have no
// portable spelling, which is exactly why they sit behind a seam.
//
// So a DUT on another stack does NOT port this file — it writes a sibling
// adapter against `tc8::net::SocketBackend` (24 pure virtuals) and hands it to
// the same ProtocolServer. That is a travelled path, not a theory:
// `dut/lwip_dut/lwip_socket_backend.cpp` already implements the same seam for
// lwIP, a stack with no netlink, no procfs and no eventfd. A QNX adapter is the
// third of its kind, not the first.
//
// This was `PosixSocketBackend` in `tc8/posix_socket_backend.h` until the name
// was corrected. No compatibility alias was left behind: an alias would keep
// the misleading name reachable and readable forever, which is the whole defect
// it was meant to retire — and a second spelling of one type is a duplicate
// source waiting to drift. Out-of-tree UTM consumers update the include and the
// type name once, and the compiler tells them exactly where. Note the sibling
// `posix_stack_probe` keeps its name deliberately: it really is POSIX (nothing
// but <arpa/inet.h>, <netinet/*>, <sys/socket.h>), so the distinction the two
// names now draw is a real one.
class LinuxSocketBackend : public tc8::testability::SocketBackend {
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
    tc8::net::OpStatus joinMulticast(int fd, std::uint32_t group_be,
                                     std::uint32_t ifaddr_be) override;
    tc8::net::OpStatus leaveMulticast(int fd, std::uint32_t group_be,
                                      std::uint32_t ifaddr_be) override;
    tc8::net::OpStatus flushDynamicArp(const std::string &ifname) override;
    tc8::net::OpStatus addStaticNeighbor(const std::string &ifname, std::uint32_t addr_be,
                                         const std::uint8_t *mac) override;
    tc8::net::OpStatus removeNeighbor(const std::string &ifname, std::uint32_t addr_be) override;
    tc8::net::OpStatus setNeighborReachableMs(const std::string &ifname,
                                              int reachable_ms) override;
    int recv(int fd, void *buf, std::size_t len) override;
    int send(int fd, const void *buf, std::size_t len) override;
    bool connectBoundedV4(int fd, const tc8::net::Endpoint &dst, int timeout_ms) override;
    bool listen(int fd, int backlog) override;
    int accept(int fd, tc8::net::Endpoint &client) override;
    bool shutdown(int fd, int how) override;
    void setNonBlocking(int fd, bool on) override;
    int waitReadable(int fd, int timeout_us) override;
    int poll(const int *fds, std::size_t n, int timeout_ms,
             std::vector<int> &readable) override;
    std::unique_ptr<tc8::testability::Waker> createWaker() override;
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
    std::uint8_t setStaticAddressV6(const std::string &ifname, const std::uint8_t *addr16,
                                    std::uint8_t prefix) override;
    std::uint8_t setStaticRouteV6(const std::string &ifname, const std::uint8_t *subnet16,
                                  std::uint8_t prefix, const std::uint8_t *gateway16) override;

private:
    // A connected TCP 4-tuple captured at CONNECT for the abort SOCK_DESTROY.
    struct TcpConnTuple {
        sockaddr_in local{};
        sockaddr_in peer{};
    };
    static void destroyTimeWaitResidual(const TcpConnTuple &t);

    std::mutex tuples_mu_;
    std::map<int, TcpConnTuple> tuples_;  // fd -> connected 4-tuple (active opens)
};

// Standalone eventfd Waker factory (the single source of the eventfd-creation code —
// LinuxSocketBackend::createWaker() delegates here). A caller that needs ONLY a
// cross-thread wake (e.g. the DUT lifecycle channel) mints one without constructing a
// whole socket backend just to reach a stateless factory. Returns nullptr iff eventfd()
// fails (fd exhaustion); the caller degrades gracefully.
std::unique_ptr<tc8::testability::Waker> makeEventfdWaker();

}  // namespace tc8::dut
