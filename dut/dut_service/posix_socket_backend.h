#pragma once

#include <netinet/in.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>

#include "testability/protocol_server.h"

namespace tc8::dut {

// POSIX (Linux) adapter for the testability ProtocolServer's SocketBackend
// seam: every operation is a kernel socket syscall. The abortive close uses
// SO_LINGER{1,0} + a sock_diag SOCK_DESTROY to also clear a TIME-WAIT residual,
// so this backend privately tracks each active-open connection's 4-tuple (the
// detached tw_sock no longer maps to the fd by abort time).
class PosixSocketBackend : public tc8::testability::SocketBackend {
public:
    int createUdp() override;
    int createTcp() override;
    void setReuseAddr(int fd) override;
    void setRecvTimeoutMs(int fd, int ms) override;
    bool bindV4(int fd, std::uint32_t addr_be, std::uint16_t port) override;
    int recvFromV4(int fd, void *buf, std::size_t len, tc8::testability::Endpoint &src) override;
    int sendToV4(int fd, const void *buf, std::size_t len,
                 const tc8::testability::Endpoint &dst) override;
    int recv(int fd, void *buf, std::size_t len) override;
    int send(int fd, const void *buf, std::size_t len) override;
    bool connectBoundedV4(int fd, const tc8::testability::Endpoint &dst, int timeout_ms) override;
    bool listen(int fd, int backlog) override;
    int accept(int fd, tc8::testability::Endpoint &client) override;
    bool shutdown(int fd, int how) override;
    void setNonBlocking(int fd, bool on) override;
    int waitReadable(int fd, int timeout_us) override;
    void closeFd(int fd) override;
    void closeWithAbort(int fd) override;
    std::uint8_t configureOption(int fd, std::uint16_t param_id, const std::uint8_t *val,
                                 std::uint16_t len) override;
    std::uint8_t sendIcmpEcho(const std::string &ifname, std::uint32_t dst_be,
                              const std::uint8_t *body, std::size_t len) override;

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

}  // namespace tc8::dut
