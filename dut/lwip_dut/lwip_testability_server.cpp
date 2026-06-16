// AUTOSAR Testability Protocol endpoint for the lwIP DUT fixture.
//
// Functional mirror of dut/dut_service/testability_server.cpp, rebuilt on the
// lwIP socket API — the same relationship lwip_ut_server.cpp has to the opcode
// UpperTesterServer. The wire framing + codec are reused verbatim from the
// shared SSOT include/tc8/testability_protocol.h, and the ICMP Echo Request
// body from the shared tc8::wire builder; only the syscall layer is rewritten.
// Per-deviation rationale lives at each call site (and is summarised in the
// header); the structural differences from the Linux server are all forced by
// a stack property, never a shortcut.

#include "lwip_testability_server.h"

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "lwip/api.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/prot/ip.h"
#include "lwip/raw.h"
#include "lwip/sockets.h"
#include "lwip/tcp.h"
#include "lwip/tcpip.h"
// fd -> pcb bridge for the CLOSE_SOCKET abort (see abortTcpPcb): lwIP's socket
// layer exposes no unconditional-RST path, so the abort walks down to the raw
// pcb under the core lock. Wrapped in extern "C" because upstream declares
// lwip_socket_dbg_get_socket AFTER closing its own extern "C" block — without
// the wrapper a C++ TU sees a mangled name the C object never defines (same
// idiom as lwip_ut_server.cpp).
extern "C" {
#include "lwip/priv/sockets_priv.h"
}

#include "tc8/testability_protocol.h"
#include "wire/icmp_echo.h"

namespace tc8::lwip_dut {
namespace {

namespace tp = ::tc8::testability;

// Wake interval for the async-event SP worker threads' select() loop — bounds
// how fast acceptLoop / receiveLoop notice the stop / reset flags.
constexpr int kEventThreadWakeUs = 200 * 1000;  // 200 ms

// PRS_TPSP §6.10 SEND_DATA totalLen rule, shared by the UDP and TCP backends:
// repeat `data` up to `total_len` bytes; if total_len < data_len send the full
// data. data_len == 0 yields `total_len` zero bytes. (Identical to the Linux
// server — pure byte math, no stack dependency.)
std::vector<std::uint8_t> buildRepeatedPayload(const std::uint8_t *data_body,
                                               std::uint16_t data_len,
                                               std::uint16_t total_len) {
    std::vector<std::uint8_t> payload;
    const std::size_t want = (total_len > data_len) ? total_len : data_len;
    payload.reserve(want);
    if (data_len == 0) {
        payload.assign(want, 0);
    } else {
        while (payload.size() < want) {
            const std::size_t take =
                ((want - payload.size()) < data_len) ? (want - payload.size()) : data_len;
            payload.insert(payload.end(), data_body, data_body + take);
        }
    }
    return payload;
}

// setsockopt with an int-sized value, mapped to the testability result: E_OK on
// success, E_NOK on any lwIP rejection (e.g. a TCP-only option on a UDP socket).
std::uint8_t setIntSockOpt(int fd, int level, int optname, int value) {
    return lwip_setsockopt(fd, level, optname, &value, sizeof(value)) == 0 ? tp::kRidEOk
                                                                           : tp::kRidENok;
}

// Bounded active connect: O_NONBLOCK connect + select up to `timeout_ms`, so a
// missing peer cannot stall the single server thread. lwIP does not guarantee a
// cross-thread shutdown() unblocks an in-flight blocking connect, so the
// non-blocking form is also what makes CONNECT reliably reapable (the same
// reason lwip_ut_server's active opens use it). The fd is left blocking on
// return. 0 on an established connection, -1 on failure or timeout.
int connectWithTimeout(int fd, const sockaddr_in &dst, int timeout_ms) {
    const int flags = lwip_fcntl(fd, F_GETFL, 0);
    lwip_fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    int result = -1;
    const int rc = lwip_connect(fd, reinterpret_cast<const sockaddr *>(&dst), sizeof(dst));
    if (rc == 0) {
        result = 0;  // immediate connect
    } else if (errno == EINPROGRESS) {
        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(fd, &wset);
        timeval tv{};
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        if (lwip_select(fd + 1, nullptr, &wset, nullptr, &tv) > 0) {
            int err = 0;
            socklen_t len = sizeof(err);
            if (lwip_getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0) {
                result = 0;
            }
        }
    }
    lwip_fcntl(fd, F_SETFL, flags);  // restore blocking mode
    return result;
}

// Abort the TCP connection behind socket fd with a RST and detach its netconn,
// through the fd -> pcb bridge. lwIP's SO_LINGER{on,0} + close recipe (the Linux
// path) does not map — lwIP only aborts a lingering close while unsent/unacked
// data remains, so an empty queue always closes gracefully with FIN
// (api_msg.c lwip_netconn_do_close_internal). tcp_abort() on the raw pcb is the
// stack's actual abort primitive; the caller still lwip_close()s afterwards to
// reap the socket slot. Returns true if a live TCP pcb was found and aborted.
bool abortTcpPcb(int fd) {
    bool aborted = false;
    LOCK_TCPIP_CORE();
    struct lwip_sock *s = lwip_socket_dbg_get_socket(fd);
    if (s != nullptr && s->conn != nullptr &&
        NETCONNTYPE_GROUP(s->conn->type) == NETCONN_TCP && s->conn->pcb.tcp != nullptr) {
        tcp_abort(s->conn->pcb.tcp);
        aborted = true;
    }
    UNLOCK_TCPIP_CORE();
    return aborted;
}

// The testability endpoint, rebuilt on lwIP. Same method surface as the Linux
// TestabilityServer minus the OEM seam (no fixture caller) and minus the
// netlink SOCK_DESTROY path (no lwIP analog — tcp_abort leaves no TIME-WAIT
// residual to destroy).
class TestabilityServer {
public:
    bool start(std::uint16_t port);
    void stop();

private:
    void serverLoop();
    void dispatch(const tp::Header &req, const std::uint8_t *dat, std::size_t dat_len,
                  const sockaddr_in &peer, std::uint8_t &rid_out,
                  std::vector<std::uint8_t> &resp_dat);

    std::uint8_t createAndBind(const std::uint8_t *dat, std::size_t dat_len, int socktype,
                               std::uint16_t &socket_id_out);
    void respondCreateAndBind(int socktype, const std::uint8_t *dat, std::size_t dat_len,
                              std::uint8_t &rid_out, std::vector<std::uint8_t> &resp_dat);
    std::uint8_t sendDataUdp(const std::uint8_t *dat, std::size_t dat_len);
    std::uint8_t sendDataTcp(const std::uint8_t *dat, std::size_t dat_len);
    std::uint8_t connectTcp(const std::uint8_t *dat, std::size_t dat_len);
    std::uint8_t listenAndAcceptTcp(const std::uint8_t *dat, std::size_t dat_len,
                                    std::uint16_t service_id, const sockaddr_in &peer);
    std::uint8_t closeSocket(const std::uint8_t *dat, std::size_t dat_len);
    std::uint8_t shutdownSocket(const std::uint8_t *dat, std::size_t dat_len);
    std::uint8_t configureSocket(const std::uint8_t *dat, std::size_t dat_len);
    std::uint8_t receiveAndForward(const std::uint8_t *dat, std::size_t dat_len,
                                   std::uint16_t service_id, const sockaddr_in &peer,
                                   std::vector<std::uint8_t> &resp_dat, bool udp);
    std::uint8_t echoRequest(const std::uint8_t *dat, std::size_t dat_len);

    void runEventWorkerLoop(int fd, const std::shared_ptr<std::atomic<bool>> &stop,
                            const std::function<bool()> &again,
                            const std::function<bool()> &on_readable);
    void acceptLoop(int listen_fd, std::uint16_t service_id, std::uint16_t listen_socket_id,
                    std::uint16_t max_con, sockaddr_in peer,
                    std::shared_ptr<std::atomic<bool>> stop);
    void receiveLoopTcp(int conn_fd, std::uint16_t service_id, std::uint16_t max_fwd,
                        std::uint16_t max_len, sockaddr_in peer,
                        std::shared_ptr<std::atomic<bool>> stop);
    void receiveLoopUdp(int sock_fd, std::uint16_t service_id, std::uint16_t max_fwd,
                        std::uint16_t max_len, sockaddr_in peer,
                        std::shared_ptr<std::atomic<bool>> stop);
    void emitEvent(std::uint16_t service_id, std::uint8_t gid, std::uint8_t pid,
                   const std::vector<std::uint8_t> &dat, const sockaddr_in &peer);

    std::uint16_t registerSocket(int fd);
    std::optional<int> lookupSocket(std::uint16_t id) const;
    bool eraseSocket(std::uint16_t id, bool abort = false);
    void closeAllSockets();

    void joinEventThreads();
    void stopWorker(std::uint16_t socket_id);

    int fd_ = -1;
    std::thread thread_;
    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> reset_events_{false};

    // Response + async-Event egress on the shared listener socket are serialised
    // here: lwIP gives no cross-thread ordering guarantee on one netconn (the
    // Linux server relied on the kernel serialising sub-MTU sendto), so the
    // worker threads and serverLoop must not interleave their sends on fd_.
    std::mutex send_mu_;

    struct EventWorker {
        std::shared_ptr<std::atomic<bool>> stop;
        std::thread thread;
    };
    std::mutex workers_mu_;
    std::map<std::uint16_t, EventWorker> event_workers_;

    mutable std::mutex sockets_mu_;
    std::map<std::uint16_t, int> sockets_;
    std::uint16_t next_socket_id_ = 1;
};

bool TestabilityServer::start(std::uint16_t port) {
    fd_ = lwip_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd_ < 0) {
        return false;
    }
    int on = 1;
    lwip_setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    // 200 ms recv timeout so the loop wakes to check stop_requested_.
    timeval tv{};
    tv.tv_usec = 200 * 1000;
    lwip_setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = lwip_htons(port);
    if (lwip_bind(fd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        std::fprintf(stderr, "tc8-lwip-testability: bind UDP :%u failed: %s\n", port,
                     std::strerror(errno));
        lwip_close(fd_);
        fd_ = -1;
        return false;
    }
    thread_ = std::thread([this] { serverLoop(); });
    return true;
}

void TestabilityServer::stop() {
    stop_requested_ = true;
    if (thread_.joinable()) {
        thread_.join();
    }
    joinEventThreads();
    if (fd_ >= 0) {
        lwip_close(fd_);
        fd_ = -1;
    }
    closeAllSockets();
}

void TestabilityServer::serverLoop() {
    std::uint8_t buf[2048];
    while (!stop_requested_) {
        sockaddr_in peer{};
        socklen_t plen = sizeof(peer);
        const int n = lwip_recvfrom(fd_, buf, sizeof(buf), 0,
                                    reinterpret_cast<sockaddr *>(&peer), &plen);
        if (n < static_cast<int>(tp::kHeaderSize)) {
            continue;  // timeout or runt
        }
        const auto header = tp::parseHeader(buf, static_cast<std::size_t>(n));
        if (!header || header->tid != tp::kTidRequest) {
            continue;  // not a request addressed to us
        }

        const std::uint8_t *dat = buf + tp::kHeaderSize;
        const std::size_t dat_len = static_cast<std::size_t>(n) - tp::kHeaderSize;

        std::uint8_t rid = tp::kRidEOk;
        std::vector<std::uint8_t> resp_dat;
        dispatch(*header, dat, dat_len, peer, rid, resp_dat);

        tp::Header resp = *header;     // echo service_id + method_id
        resp.tid = tp::kTidResponse;   // PRS_TPSP §6.2 Response
        resp.rid = rid;
        const auto out = tp::buildMessage(resp, resp_dat.empty() ? nullptr : resp_dat.data(),
                                          resp_dat.size());
        std::lock_guard<std::mutex> lk(send_mu_);
        lwip_sendto(fd_, out.data(), out.size(), 0, reinterpret_cast<sockaddr *>(&peer), plen);
    }
}

void TestabilityServer::dispatch(const tp::Header &req, const std::uint8_t *dat,
                                 std::size_t dat_len, const sockaddr_in &peer,
                                 std::uint8_t &rid_out, std::vector<std::uint8_t> &resp_dat) {
    const std::uint8_t gid = tp::gidOf(req.method_id);
    const std::uint8_t pid = tp::pidOf(req.method_id);

    if (gid == tp::kGidGeneral) {
        switch (pid) {
            case tp::kPidGetVersion:
                tp::appendU16(resp_dat, tp::kVersionMajor);
                tp::appendU16(resp_dat, tp::kVersionMinor);
                tp::appendU16(resp_dat, tp::kVersionPatch);
                rid_out = tp::kRidEOk;
                return;
            case tp::kPidStartTest:
                rid_out = tp::kRidEOk;
                return;
            case tp::kPidEndTest:
                reset_events_ = true;
                joinEventThreads();
                reset_events_ = false;
                closeAllSockets();
                rid_out = tp::kRidEOk;
                return;
            default:
                rid_out = tp::kRidENtf;  // PRS_TPSP §6.8 service primitive not found
                return;
        }
    }

    if (gid == tp::kGidUdp) {
        switch (pid) {
            case tp::kPidCreateAndBind:
                respondCreateAndBind(SOCK_DGRAM, dat, dat_len, rid_out, resp_dat);
                return;
            case tp::kPidSendData:
                rid_out = sendDataUdp(dat, dat_len);
                return;
            case tp::kPidCloseSocket:
                rid_out = closeSocket(dat, dat_len);
                return;
            case tp::kPidShutdown:
                rid_out = shutdownSocket(dat, dat_len);
                return;
            case tp::kPidReceiveAndForward:
                rid_out = receiveAndForward(dat, dat_len, req.service_id, peer, resp_dat,
                                            /*udp=*/true);
                return;
            case tp::kPidConfigureSocket:
                rid_out = configureSocket(dat, dat_len);
                return;
            default:
                rid_out = tp::kRidENtf;
                return;
        }
    }

    if (gid == tp::kGidTcp) {
        switch (pid) {
            case tp::kPidCreateAndBind:
                respondCreateAndBind(SOCK_STREAM, dat, dat_len, rid_out, resp_dat);
                return;
            case tp::kPidConnect:
                rid_out = connectTcp(dat, dat_len);
                return;
            case tp::kPidListenAndAccept:
                rid_out = listenAndAcceptTcp(dat, dat_len, req.service_id, peer);
                return;
            case tp::kPidSendData:
                rid_out = sendDataTcp(dat, dat_len);
                return;
            case tp::kPidCloseSocket:
                rid_out = closeSocket(dat, dat_len);
                return;
            case tp::kPidShutdown:
                rid_out = shutdownSocket(dat, dat_len);
                return;
            case tp::kPidReceiveAndForward:
                rid_out = receiveAndForward(dat, dat_len, req.service_id, peer, resp_dat,
                                            /*udp=*/false);
                return;
            case tp::kPidConfigureSocket:
                rid_out = configureSocket(dat, dat_len);
                return;
            default:
                rid_out = tp::kRidENtf;
                return;
        }
    }

    if (gid == tp::kGidIcmp) {
        switch (pid) {
            case tp::kPidEchoRequest:
                rid_out = echoRequest(dat, dat_len);
                return;
            default:
                rid_out = tp::kRidENtf;  // ICMP group defines only ECHO_REQUEST
                return;
        }
    }

    rid_out = tp::kRidENtf;  // group not implemented by this fixture
}

std::uint8_t TestabilityServer::createAndBind(const std::uint8_t *dat, std::size_t dat_len,
                                              int socktype, std::uint16_t &socket_id_out) {
    // PRS_TPSP §6.10 CREATE_AND_BIND: doBind(bool) + localPort(uint16) +
    // localAddr(ipxaddr). Shape identical for UDP/TCP; socktype selects the kind.
    if (dat_len < 1 + 2 + 2) {
        return tp::kRidEInv;
    }
    const bool do_bind = dat[0] != 0;
    const std::uint16_t local_port = tp::readU16(dat + 1);
    std::size_t off = 3;
    const std::uint8_t *addr_body = nullptr;
    std::uint16_t addr_len = 0;
    if (!tp::readVint8(dat, dat_len, off, addr_body, addr_len)) {
        return tp::kRidEInv;
    }
    if (addr_len != 0 && addr_len != 4) {
        return tp::kRidEInv;  // IPv6 (n=16) not implemented in this iteration
    }

    const int proto = (socktype == SOCK_STREAM) ? IPPROTO_TCP : IPPROTO_UDP;
    const int s = lwip_socket(AF_INET, socktype, proto);
    if (s < 0) {
        return tp::kRidEUcs;  // unable to create socket
    }
    if (do_bind) {
        int on = 1;
        lwip_setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        // localPort 0xFFFF == PORT_ANY (PRS_TPSP §6.10) => 0 (kernel-assigned).
        addr.sin_port = lwip_htons(local_port == 0xFFFF ? 0 : local_port);
        addr.sin_addr.s_addr = INADDR_ANY;
        if (addr_len == 4) {
            const bool all_zero = addr_body[0] == 0 && addr_body[1] == 0 &&
                                  addr_body[2] == 0 && addr_body[3] == 0;
            if (!all_zero) {
                std::memcpy(&addr.sin_addr.s_addr, addr_body, 4);  // wire bytes are NBO
            }
        }
        if (lwip_bind(s, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
            lwip_close(s);
            return tp::kRidEUbs;  // unable to bind, port taken
        }
    }

    socket_id_out = registerSocket(s);
    return tp::kRidEOk;
}

void TestabilityServer::respondCreateAndBind(int socktype, const std::uint8_t *dat,
                                             std::size_t dat_len, std::uint8_t &rid_out,
                                             std::vector<std::uint8_t> &resp_dat) {
    std::uint16_t id = 0;
    rid_out = createAndBind(dat, dat_len, socktype, id);
    if (rid_out == tp::kRidEOk) {
        tp::appendU16(resp_dat, id);  // PRS_TPSP §6.10 response: socketId(uint16)
    }
}

std::uint8_t TestabilityServer::sendDataUdp(const std::uint8_t *dat, std::size_t dat_len) {
    // PRS_TPSP §6.10 SEND_DATA (UDP): socketId + totalLen + destPort +
    // destAddr(ipxaddr) + data(vint8).
    if (dat_len < 2 + 2 + 2) {
        return tp::kRidEInv;
    }
    const std::uint16_t socket_id = tp::readU16(dat);
    const std::uint16_t total_len = tp::readU16(dat + 2);
    const std::uint16_t dest_port = tp::readU16(dat + 4);
    std::size_t off = 6;
    const std::uint8_t *addr_body = nullptr;
    std::uint16_t addr_len = 0;
    if (!tp::readVint8(dat, dat_len, off, addr_body, addr_len) || addr_len != 4) {
        return tp::kRidEInv;
    }
    const std::uint8_t *data_body = nullptr;
    std::uint16_t data_len = 0;
    if (!tp::readVint8(dat, dat_len, off, data_body, data_len)) {
        return tp::kRidEInv;
    }

    const auto fd = lookupSocket(socket_id);
    if (!fd) {
        return tp::kRidEIsd;  // invalid socket id
    }

    const std::vector<std::uint8_t> payload =
        buildRepeatedPayload(data_body, data_len, total_len);

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = lwip_htons(dest_port);
    std::memcpy(&dst.sin_addr.s_addr, addr_body, 4);  // wire bytes are NBO
    const int sent = lwip_sendto(*fd, payload.data(), payload.size(), 0,
                                 reinterpret_cast<sockaddr *>(&dst), sizeof(dst));
    // Non-blocking semantics (PRS_TPSP §6.10): E_OK signals the transmission was
    // issued, not delivered; a hard send failure surfaces as E_NOK.
    return sent < 0 ? tp::kRidENok : tp::kRidEOk;
}

std::uint8_t TestabilityServer::configureSocket(const std::uint8_t *dat, std::size_t dat_len) {
    // PRS_TPSP §6.10.10 CONFIGURE_SOCKET: socketId + paramId + paramVal(vint8).
    if (dat_len < 2 + 2) {
        return tp::kRidEInv;
    }
    const std::uint16_t socket_id = tp::readU16(dat);
    const std::uint16_t param_id = tp::readU16(dat + 2);
    std::size_t off = 4;
    const std::uint8_t *val = nullptr;
    std::uint16_t val_len = 0;
    if (!tp::readVint8(dat, dat_len, off, val, val_len)) {
        return tp::kRidEInv;
    }

    const auto fd = lookupSocket(socket_id);
    if (!fd) {
        return tp::kRidEIsd;  // PRS_TPSP §6.8 invalid socket descriptor
    }

    const auto fixed = [&](std::uint16_t want) { return val_len == want; };

    switch (param_id) {
        case tp::kCfgTtl:  // IP TTL / hop limit
            if (!fixed(1)) return tp::kRidEInv;
            return setIntSockOpt(*fd, IPPROTO_IP, IP_TTL, val[0]);
        case tp::kCfgPriority:  // traffic class / DSCP & ECN -> the IPv4 TOS byte
        case tp::kCfgTos:       // IP Type of Service (RFC 791) -> the IPv4 TOS byte
            if (!fixed(1)) return tp::kRidEInv;
            return setIntSockOpt(*fd, IPPROTO_IP, IP_TOS, val[0]);
        case tp::kCfgNagle:  // Nagle enable=1 -> TCP_NODELAY is its inverse (TCP only)
            if (!fixed(1)) return tp::kRidEInv;
            return setIntSockOpt(*fd, IPPROTO_TCP, TCP_NODELAY, val[0] ? 0 : 1);
        case tp::kCfgUdpChecksum:  // UDP cksum tx enable=1 -> SO_NO_CHECK is its inverse
            if (!fixed(1)) return tp::kRidEInv;
            return setIntSockOpt(*fd, SOL_SOCKET, SO_NO_CHECK, val[0] ? 0 : 1);
        case tp::kCfgDontFragment:       // IP DF bit (Linux IP_MTU_DISCOVER)
        case tp::kCfgIpTimestampOption:  // IP option-4 bytes (Linux IP_OPTIONS)
        case tp::kCfgMss:                // TCP MSS clamp (Linux TCP_MAXSEG)
            // lwIP's socket layer exposes no DF-bit, IP-options or MSS-clamp
            // setsockopt — the Linux options these map to are absent. Answer
            // E_NOK so a tester sees the rejection rather than a false success;
            // a case that came to depend on one of these would be ledgered as
            // platform_known_fail, the same way the OOB / reassembly gaps are.
            return tp::kRidENok;
        default:
            // Unknown / non-standard (0xFFFF-down) parameter not served here.
            return tp::kRidENtf;
    }
}

std::uint8_t TestabilityServer::echoRequest(const std::uint8_t *dat, std::size_t dat_len) {
    // PRS_TPSP §6.10 ECHO_REQUEST (ICMP): ifName(text) + destAddr(ipxaddr) + data(vint8).
    std::size_t off = 0;
    std::string ifname;
    if (!tp::readText(dat, dat_len, off, ifname)) {
        return tp::kRidEInv;
    }
    const std::uint8_t *addr_body = nullptr;
    std::uint16_t addr_len = 0;
    if (!tp::readVint8(dat, dat_len, off, addr_body, addr_len) || addr_len != 4) {
        return tp::kRidEInv;  // IPv4 ipxaddr only — ICMPv6 is a separate GID
    }
    std::uint32_t dest_be = 0;
    std::memcpy(&dest_be, addr_body, 4);
    const std::uint8_t *data_body = nullptr;
    std::uint16_t data_len = 0;
    if (!tp::readVint8(dat, dat_len, off, data_body, data_len)) {
        return tp::kRidEInv;
    }

    // Build the Echo Request via the shared wire builder — the same source the
    // tester stimulus frames echoes from, so DUT-emitted and tester-observed
    // bytes agree by construction. The builder checksums the body itself; the
    // raw pcb leaves it untouched (chksum_reqd defaults to 0), so there is no
    // double-checksum. No syscalls in the builder — reused verbatim from Linux.
    const std::vector<std::uint8_t> msg =
        tc8::wire::buildIcmpEchoRequestBody(/*id=*/0, /*seq=*/1, data_body, data_len);

    // lwIP's socket layer offers no unprivileged ICMP datagram (ping) socket, so
    // emit through a raw pcb on IP_PROTO_ICMP under the core lock — the stack
    // builds the IP header and the named-interface egress.
    std::uint8_t rid = tp::kRidENok;
    LOCK_TCPIP_CORE();
    struct raw_pcb *pcb = raw_new(IP_PROTO_ICMP);
    if (pcb != nullptr) {
        bool iface_ok = true;
        // Optional ifName (PRS_TPSP §6.10): pin egress to the named netif. "0" /
        // empty means "any" per the spec; an unknown interface is E_IIF.
        if (!ifname.empty() && ifname != "0") {
            struct netif *nif = netif_find(ifname.c_str());
            if (nif == nullptr) {
                iface_ok = false;
                rid = tp::kRidEIif;
            } else {
                raw_bind_netif(pcb, nif);
            }
        }
        if (iface_ok) {
            struct pbuf *p = pbuf_alloc(PBUF_IP, static_cast<u16_t>(msg.size()), PBUF_RAM);
            if (p != nullptr) {
                pbuf_take(p, msg.data(), static_cast<u16_t>(msg.size()));
                ip_addr_t dst;
                ip_addr_set_ip4_u32_val(dst, dest_be);
                rid = (raw_sendto(pcb, p, &dst) == ERR_OK) ? tp::kRidEOk : tp::kRidENok;
                pbuf_free(p);
            }
        }
        raw_remove(pcb);
    }
    UNLOCK_TCPIP_CORE();
    return rid;
}

std::uint8_t TestabilityServer::connectTcp(const std::uint8_t *dat, std::size_t dat_len) {
    // PRS_TPSP §6.10 CONNECT (TCP): socketId + destPort + destAddr(ipxaddr).
    if (dat_len < 2 + 2) {
        return tp::kRidEInv;
    }
    const std::uint16_t socket_id = tp::readU16(dat);
    const std::uint16_t dest_port = tp::readU16(dat + 2);
    std::size_t off = 4;
    const std::uint8_t *addr_body = nullptr;
    std::uint16_t addr_len = 0;
    if (!tp::readVint8(dat, dat_len, off, addr_body, addr_len) || addr_len != 4) {
        return tp::kRidEInv;
    }

    const auto fd = lookupSocket(socket_id);
    if (!fd) {
        return tp::kRidEIsd;  // invalid socket id
    }

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = lwip_htons(dest_port);
    std::memcpy(&dst.sin_addr.s_addr, addr_body, 4);  // wire bytes are NBO
    // Bounded so an absent peer times out instead of freezing the dispatch loop.
    // No 4-tuple is recorded (the Linux server kept it only for the netlink
    // SOCK_DESTROY abort, which lwIP has no analog for — tcp_abort suffices).
    if (connectWithTimeout(*fd, dst, /*timeout_ms=*/1000) != 0) {
        return tp::kRidENok;  // connection refused / unreachable / timed out
    }
    return tp::kRidEOk;
}

std::uint8_t TestabilityServer::sendDataTcp(const std::uint8_t *dat, std::size_t dat_len) {
    // PRS_TPSP §6.10 SEND_DATA (TCP): socketId + totalLen + flags(u8) + data(vint8).
    if (dat_len < 2 + 2 + 1) {
        return tp::kRidEInv;
    }
    const std::uint16_t socket_id = tp::readU16(dat);
    const std::uint16_t total_len = tp::readU16(dat + 2);
    std::size_t off = 5;  // skip flags(u8) at dat[4]
    const std::uint8_t *data_body = nullptr;
    std::uint16_t data_len = 0;
    if (!tp::readVint8(dat, dat_len, off, data_body, data_len)) {
        return tp::kRidEInv;
    }

    const auto fd = lookupSocket(socket_id);
    if (!fd) {
        return tp::kRidEIsd;  // invalid socket id
    }

    const std::vector<std::uint8_t> payload =
        buildRepeatedPayload(data_body, data_len, total_len);
    const int sent = lwip_send(*fd, payload.data(), payload.size(), 0);
    return sent < 0 ? tp::kRidENok : tp::kRidEOk;
}

std::uint8_t TestabilityServer::listenAndAcceptTcp(const std::uint8_t *dat, std::size_t dat_len,
                                                   std::uint16_t service_id,
                                                   const sockaddr_in &peer) {
    // PRS_TPSP §6.10 LISTEN_AND_ACCEPT (TCP): listenSocketId + maxCon.
    if (dat_len < 2 + 2) {
        return tp::kRidEInv;
    }
    const std::uint16_t listen_socket_id = tp::readU16(dat);
    std::uint16_t max_con = tp::readU16(dat + 2);
    if (max_con == 0) {
        max_con = 1;  // a zero backlog cannot accept anything; treat as one
    }

    const auto fd = lookupSocket(listen_socket_id);
    if (!fd) {
        return tp::kRidEIsd;  // invalid socket id
    }
    if (lwip_listen(*fd, max_con) < 0) {
        return tp::kRidENok;  // not a bound stream socket / listen failed
    }

    // Accept asynchronously: E_OK now, each accepted connection reported later as
    // an Event to the requesting tester. The worker's lifetime is owned by the
    // listen socket (stopWorker on close), so re-arm the slot before installing.
    stopWorker(listen_socket_id);
    auto stop = std::make_shared<std::atomic<bool>>(false);
    std::thread t(&TestabilityServer::acceptLoop, this, *fd, service_id, listen_socket_id, max_con,
                  peer, stop);
    {
        std::lock_guard<std::mutex> lk(workers_mu_);
        auto &w = event_workers_[listen_socket_id];  // fresh: stopWorker erased any prior
        w.stop = std::move(stop);
        w.thread = std::move(t);
    }
    return tp::kRidEOk;
}

void TestabilityServer::runEventWorkerLoop(int fd, const std::shared_ptr<std::atomic<bool>> &stop,
                                           const std::function<bool()> &again,
                                           const std::function<bool()> &on_readable) {
    // PRS_TPSP §6.2 async-SP worker skeleton, shared by acceptLoop /
    // receiveLoopTcp / receiveLoopUdp. The fd is non-blocking only for the span
    // of the loop (restored on exit) so select() never blocks past the wake
    // window — that bounds how fast the stop / reset flags are noticed.
    const int flags = lwip_fcntl(fd, F_GETFL, 0);
    lwip_fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    while (!stop_requested_ && !reset_events_ && !stop->load() && again()) {
        fd_set rset;
        FD_ZERO(&rset);
        FD_SET(fd, &rset);
        timeval tv{};
        tv.tv_usec = kEventThreadWakeUs;
        const int sr = lwip_select(fd + 1, &rset, nullptr, nullptr, &tv);
        if (sr == 0 || (sr < 0 && errno == EINTR)) {
            continue;  // timeout or signal — re-check the stop / reset flags
        }
        if (sr < 0) {
            break;  // fd closed under us / fatal select error — stop
        }
        if (!on_readable()) {
            break;  // the body signalled end-of-stream (e.g. a TCP peer close)
        }
    }
    lwip_fcntl(fd, F_SETFL, flags);  // restore (the fd lives on in the socket table)
}

void TestabilityServer::acceptLoop(int listen_fd, std::uint16_t service_id,
                                   std::uint16_t listen_socket_id, std::uint16_t max_con,
                                   sockaddr_in peer, std::shared_ptr<std::atomic<bool>> stop) {
    std::uint16_t accepted = 0;
    runEventWorkerLoop(
        listen_fd, stop, [&] { return accepted < max_con; },
        [&] {
            sockaddr_in client{};
            socklen_t clen = sizeof(client);
            const int conn = lwip_accept(listen_fd, reinterpret_cast<sockaddr *>(&client), &clen);
            if (conn < 0) {
                return true;  // spurious wakeup — keep waiting (not end-of-stream)
            }
            const std::uint16_t new_socket_id = registerSocket(conn);
            ++accepted;

            // PRS_TPSP §6.10 LISTEN_AND_ACCEPT Event: listenSocketId + newSocketId
            // + clientPort + clientAddr(ipxaddr).
            std::vector<std::uint8_t> ev_dat;
            tp::appendU16(ev_dat, listen_socket_id);
            tp::appendU16(ev_dat, new_socket_id);
            tp::appendU16(ev_dat, lwip_ntohs(client.sin_port));
            tp::appendIpv4Addr(ev_dat, client.sin_addr.s_addr);
            emitEvent(service_id, tp::kGidTcp, tp::kPidListenAndAccept, ev_dat, peer);
            return true;
        });
}

std::uint8_t TestabilityServer::closeSocket(const std::uint8_t *dat, std::size_t dat_len) {
    // PRS_TPSP §6.10 CLOSE_SOCKET: socketId + optional abort(bool, TCP). abort=true
    // RSTs immediately (tcp_abort via the pcb bridge), not waiting for outstanding
    // transmissions; the byte is absent (or 0) for a graceful close and for UDP.
    if (dat_len < 2) {
        return tp::kRidEInv;
    }
    const std::uint16_t socket_id = tp::readU16(dat);
    const bool abort = (dat_len >= 3) && (dat[2] != 0);
    return eraseSocket(socket_id, abort) ? tp::kRidEOk : tp::kRidEIsd;
}

std::uint8_t TestabilityServer::shutdownSocket(const std::uint8_t *dat, std::size_t dat_len) {
    // PRS_TPSP §6.10 SHUTDOWN: socketId + typeId(uint8). 0x00 reception, 0x01
    // transmission, 0x02 both. The fd lives on (a half-close), so the socket
    // stays in the table for a later RECEIVE / SEND on the open direction.
    if (dat_len < 2 + 1) {
        return tp::kRidEInv;
    }
    const std::uint16_t socket_id = tp::readU16(dat);
    int how = 0;
    switch (dat[2]) {
        case tp::kShutdownRd:
            how = SHUT_RD;
            break;
        case tp::kShutdownWr:
            how = SHUT_WR;
            break;
        case tp::kShutdownRdWr:
            how = SHUT_RDWR;
            break;
        default:
            return tp::kRidEInv;  // unknown typeId
    }
    const auto fd = lookupSocket(socket_id);
    if (!fd) {
        return tp::kRidEIsd;  // invalid socket id
    }
    return lwip_shutdown(*fd, how) == 0 ? tp::kRidEOk : tp::kRidENok;
}

std::uint8_t TestabilityServer::receiveAndForward(const std::uint8_t *dat, std::size_t dat_len,
                                                  std::uint16_t service_id,
                                                  const sockaddr_in &peer,
                                                  std::vector<std::uint8_t> &resp_dat, bool udp) {
    // PRS_TPSP §6.10 RECEIVE_AND_FORWARD (UDP/TCP): socketId + maxFwd + maxLen.
    // Response: dropCnt(u16). `udp` selects the forward loop.
    if (dat_len < 2 + 2 + 2) {
        return tp::kRidEInv;
    }
    const std::uint16_t socket_id = tp::readU16(dat);
    const std::uint16_t max_fwd = tp::readU16(dat + 2);
    const std::uint16_t max_len = tp::readU16(dat + 4);

    const auto fd = lookupSocket(socket_id);
    if (!fd) {
        return tp::kRidEIsd;  // invalid socket id
    }

    // PRS_TPSP §6.10 inactive-phase drain: consume the bytes queued before this
    // call and report the count as dropCnt. Non-blocking so an empty queue does
    // not stall the dispatch loop.
    const int flags = lwip_fcntl(*fd, F_GETFL, 0);
    lwip_fcntl(*fd, F_SETFL, flags | O_NONBLOCK);
    std::uint32_t dropped = 0;
    std::uint8_t drain[2048];
    for (;;) {
        const int n = lwip_recv(*fd, drain, sizeof(drain), 0);
        if (n <= 0) {
            break;
        }
        dropped += static_cast<std::uint32_t>(n);
    }
    lwip_fcntl(*fd, F_SETFL, flags);
    // dropCnt is a u16 field; saturate rather than wrap.
    tp::appendU16(resp_dat, static_cast<std::uint16_t>(dropped > 0xFFFF ? 0xFFFF : dropped));

    // Active phase: forward subsequently-received data as Events on a worker
    // thread — same async lifecycle (and socket-owned lifetime) as the accept
    // worker. Re-arm the slot before installing the new worker.
    stopWorker(socket_id);
    auto stop = std::make_shared<std::atomic<bool>>(false);
    std::thread t = udp ? std::thread(&TestabilityServer::receiveLoopUdp, this, *fd, service_id,
                                      max_fwd, max_len, peer, stop)
                        : std::thread(&TestabilityServer::receiveLoopTcp, this, *fd, service_id,
                                      max_fwd, max_len, peer, stop);
    {
        std::lock_guard<std::mutex> lk(workers_mu_);
        auto &w = event_workers_[socket_id];  // fresh: stopWorker erased any prior
        w.stop = std::move(stop);
        w.thread = std::move(t);
    }
    return tp::kRidEOk;
}

void TestabilityServer::receiveLoopTcp(int conn_fd, std::uint16_t service_id,
                                       std::uint16_t max_fwd, std::uint16_t max_len,
                                       sockaddr_in peer, std::shared_ptr<std::atomic<bool>> stop) {
    const bool limitless = (max_len == 0xFFFF);  // PRS_TPSP §6.10 maxLen 0xFFFF
    std::uint32_t consumed = 0;
    runEventWorkerLoop(
        conn_fd, stop, [&] { return limitless || consumed < max_len; },
        [&]() -> bool {
            std::uint8_t buf[2048];
            std::size_t want = sizeof(buf);
            if (!limitless) {
                const std::uint32_t remaining = max_len - consumed;
                if (remaining < want) {
                    want = remaining;
                }
            }
            const int n = lwip_recv(conn_fd, buf, want, 0);
            if (n <= 0) {
                return n != 0;  // n==0 peer close -> stop; n<0 spurious -> keep waiting
            }
            consumed += static_cast<std::uint32_t>(n);
            const std::uint16_t full_len = static_cast<std::uint16_t>(n);
            const std::uint16_t fwd_len =
                static_cast<std::uint16_t>(n < static_cast<int>(max_fwd) ? n : max_fwd);

            // PRS_TPSP §6.10 RECEIVE_AND_FORWARD Event (TCP): fullLen + payload(vint8).
            // fullLen is THIS recv()'s length, not a whole logical message.
            std::vector<std::uint8_t> ev_dat;
            tp::appendU16(ev_dat, full_len);
            tp::appendVint8(ev_dat, buf, fwd_len);
            emitEvent(service_id, tp::kGidTcp, tp::kPidReceiveAndForward, ev_dat, peer);
            return true;
        });
}

void TestabilityServer::receiveLoopUdp(int sock_fd, std::uint16_t service_id,
                                       std::uint16_t max_fwd, std::uint16_t max_len,
                                       sockaddr_in peer, std::shared_ptr<std::atomic<bool>> stop) {
    const bool limitless = (max_len == 0xFFFF);  // PRS_TPSP §6.10 maxLen 0xFFFF
    std::uint32_t consumed = 0;
    runEventWorkerLoop(
        sock_fd, stop, [&] { return limitless || consumed < max_len; },
        [&]() -> bool {
            std::uint8_t buf[2048];
            sockaddr_in src{};
            socklen_t srclen = sizeof(src);
            // MSG_TRUNC: the return value is the true datagram length even when
            // it overflows `buf`, so fullLen is exact while the buffer holds at
            // most sizeof(buf) bytes to forward from.
            const int n = lwip_recvfrom(sock_fd, buf, sizeof(buf), MSG_TRUNC,
                                        reinterpret_cast<sockaddr *>(&src), &srclen);
            if (n < 0) {
                return true;  // spurious wakeup — keep waiting (UDP has no close)
            }
            // A zero-length UDP datagram is a valid event (fullLen 0), NOT a peer
            // close — the key behavioural split from the TCP body.
            const std::size_t in_buf = (static_cast<std::size_t>(n) < sizeof(buf))
                                           ? static_cast<std::size_t>(n)
                                           : sizeof(buf);
            consumed += static_cast<std::uint32_t>(n);
            const std::uint16_t full_len = static_cast<std::uint16_t>(n > 0xFFFF ? 0xFFFF : n);
            const std::uint16_t fwd_len =
                static_cast<std::uint16_t>(in_buf < max_fwd ? in_buf : max_fwd);

            // PRS_TPSP §6.10 RECEIVE_AND_FORWARD Event (UDP): fullLen + srcPort +
            // srcAddr(ipxaddr) + payload(vint8). The connectionless variant
            // reports each datagram's source endpoint.
            std::vector<std::uint8_t> ev_dat;
            tp::appendU16(ev_dat, full_len);
            tp::appendU16(ev_dat, lwip_ntohs(src.sin_port));
            tp::appendIpv4Addr(ev_dat, src.sin_addr.s_addr);
            tp::appendVint8(ev_dat, buf, fwd_len);
            emitEvent(service_id, tp::kGidUdp, tp::kPidReceiveAndForward, ev_dat, peer);
            return true;
        });
}

void TestabilityServer::emitEvent(std::uint16_t service_id, std::uint8_t gid, std::uint8_t pid,
                                  const std::vector<std::uint8_t> &dat, const sockaddr_in &peer) {
    // PRS_TPSP §6.2 Event: EVB-set method id for group `gid` + TID 0x02. fd_ is
    // shared with serverLoop and the other worker threads; send_mu_ serialises
    // every egress on it (lwIP gives no cross-thread send ordering on one
    // netconn, unlike the Linux kernel the original relied on).
    tp::Header ev;
    ev.service_id = service_id;
    ev.method_id = tp::methodId(gid, pid, /*event=*/true);
    ev.tid = tp::kTidEvent;
    ev.rid = tp::kRidEOk;
    const auto out = tp::buildMessage(ev, dat.data(), dat.size());
    std::lock_guard<std::mutex> lk(send_mu_);
    lwip_sendto(fd_, out.data(), out.size(), 0, reinterpret_cast<const sockaddr *>(&peer),
                sizeof(peer));
}

std::uint16_t TestabilityServer::registerSocket(int fd) {
    std::lock_guard<std::mutex> lk(sockets_mu_);
    const std::uint16_t id = next_socket_id_++;
    sockets_[id] = fd;
    return id;
}

std::optional<int> TestabilityServer::lookupSocket(std::uint16_t id) const {
    std::lock_guard<std::mutex> lk(sockets_mu_);
    const auto it = sockets_.find(id);
    if (it == sockets_.end()) {
        return std::nullopt;
    }
    return it->second;
}

bool TestabilityServer::eraseSocket(std::uint16_t id, bool abort) {
    // Stop + join this socket's async-event worker (if any) BEFORE closing the
    // fd, so the worker can never select/accept on a closed (and possibly
    // reused) fd. Done outside sockets_mu_ (stopWorker takes only workers_mu_)
    // so a worker blocked in registerSocket cannot deadlock the join.
    stopWorker(id);

    int fd = -1;
    {
        std::lock_guard<std::mutex> lk(sockets_mu_);
        const auto it = sockets_.find(id);
        if (it == sockets_.end()) {
            return false;
        }
        fd = it->second;
        sockets_.erase(it);
    }
    // Abortive close: RST the TCP connection through the pcb bridge, then reap
    // the socket slot. A no-op for a UDP socket or an already-gone connection
    // (abortTcpPcb finds no live TCP pcb); the lwip_close still frees the fd.
    if (abort) {
        abortTcpPcb(fd);
    }
    lwip_close(fd);
    return true;
}

void TestabilityServer::closeAllSockets() {
    std::lock_guard<std::mutex> lk(sockets_mu_);
    for (const auto &kv : sockets_) {
        lwip_close(kv.second);
    }
    sockets_.clear();
}

void TestabilityServer::stopWorker(std::uint16_t socket_id) {
    EventWorker w;
    {
        std::lock_guard<std::mutex> lk(workers_mu_);
        const auto it = event_workers_.find(socket_id);
        if (it == event_workers_.end()) {
            return;  // no worker on this socket
        }
        w = std::move(it->second);
        event_workers_.erase(it);
    }
    // Signal + join with workers_mu_ released: the worker may still take
    // sockets_mu_ (registerSocket) as it winds down, and joining here never
    // holds workers_mu_, so neither lock order can deadlock.
    if (w.stop) {
        w.stop->store(true);
    }
    if (w.thread.joinable()) {
        w.thread.join();
    }
}

void TestabilityServer::joinEventThreads() {
    std::map<std::uint16_t, EventWorker> workers;
    {
        std::lock_guard<std::mutex> lk(workers_mu_);
        workers.swap(event_workers_);
    }
    for (auto &kv : workers) {
        if (kv.second.stop) {
            kv.second.stop->store(true);
        }
    }
    for (auto &kv : workers) {
        if (kv.second.thread.joinable()) {
            kv.second.thread.join();
        }
    }
}

// Leaked deliberately like the UT server: the endpoint lives for the process
// lifetime and the fixture tears the process down via the topology conf. The
// pointer is kept so the SIGTERM path (StopTestabilityServer) can join + close.
TestabilityServer *g_server = nullptr;

}  // namespace

void StartTestabilityServer(std::uint16_t port) {
    if (g_server != nullptr) {
        return;  // already started
    }
    auto *server = new TestabilityServer();
    if (!server->start(port)) {
        std::fprintf(stderr,
                     "tc8-lwip-testability: endpoint start failed on UDP port %u (continuing — "
                     "additive to the opcode UT)\n",
                     port);
        delete server;
        return;
    }
    g_server = server;
    std::fprintf(stderr, "tc8-lwip-testability: AUTOSAR testability endpoint on UDP port %u\n",
                 port);
}

void StopTestabilityServer() {
    if (g_server != nullptr) {
        g_server->stop();
    }
}

}  // namespace tc8::lwip_dut
