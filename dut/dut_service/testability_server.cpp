#include "testability_server.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>

namespace tc8::dut {

namespace tp = ::tc8::testability;

namespace {

// Wake interval for the async-event SP worker threads' select() loop — bounds
// how fast acceptLoop / receiveLoop notice stop_requested_ / reset_events_.
constexpr int kEventThreadWakeUs = 200 * 1000;  // 200 ms

// PRS_TPSP §6.10 SEND_DATA totalLen rule, shared by the UDP and TCP backends:
// repeat `data` up to `total_len` bytes; if total_len < data_len send the full
// data. data_len == 0 yields `total_len` zero bytes.
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
// success, E_NOK on any kernel rejection (e.g. a TCP-only option on a UDP
// socket, which the kernel fails with ENOPROTOOPT). Shared by the CONFIGURE_SOCKET
// parameter arms so the result mapping lives in one place.
std::uint8_t setIntSockOpt(int fd, int level, int optname, int value) {
    return ::setsockopt(fd, level, optname, &value, sizeof(value)) == 0 ? tp::kRidEOk
                                                                        : tp::kRidENok;
}

// Bounded active connect on `fd` to `dst`: O_NONBLOCK connect + select up to
// `timeout_ms`, so a missing peer cannot stall the single server thread. The
// fd is left in blocking mode on return. 0 on an established connection, -1 on
// failure or timeout.
int connectWithTimeout(int fd, const sockaddr_in &dst, int timeout_ms) {
    const int flags = ::fcntl(fd, F_GETFL, 0);
    ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    int result = -1;
    const int rc = ::connect(fd, reinterpret_cast<const sockaddr *>(&dst), sizeof(dst));
    if (rc == 0) {
        result = 0;  // immediate (loopback) connect
    } else if (errno == EINPROGRESS) {
        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(fd, &wset);
        timeval tv{};
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        if (::select(fd + 1, nullptr, &wset, nullptr, &tv) > 0) {
            int err = 0;
            socklen_t len = sizeof(err);
            if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0) {
                result = 0;
            }
        }
    }
    ::fcntl(fd, F_SETFL, flags);  // restore blocking mode
    return result;
}

}  // namespace

TestabilityServer::TestabilityServer() = default;

TestabilityServer::~TestabilityServer() {
    stop();
}

bool TestabilityServer::start(std::uint16_t port) {
    fd_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd_ < 0) {
        return false;
    }
    int on = 1;
    ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    // 200 ms recv timeout so the loop wakes to check stop_requested_.
    timeval tv{};
    tv.tv_usec = 200 * 1000;
    ::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (::bind(fd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        std::fprintf(stderr, "testability: bind UDP :%u failed: %s\n", port,
                     std::strerror(errno));
        ::close(fd_);
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
    // Join accept threads before tearing down the socket table — they touch the
    // listen fds and register accepted sockets.
    joinEventThreads();
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    closeAllSockets();
}

void TestabilityServer::serverLoop() {
    std::uint8_t buf[2048];
    while (!stop_requested_) {
        sockaddr_in peer{};
        socklen_t plen = sizeof(peer);
        const ssize_t n = ::recvfrom(fd_, buf, sizeof(buf), 0,
                                     reinterpret_cast<sockaddr *>(&peer), &plen);
        if (n < static_cast<ssize_t>(tp::kHeaderSize)) {
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
        ::sendto(fd_, out.data(), out.size(), 0, reinterpret_cast<sockaddr *>(&peer), plen);
    }
}

void TestabilityServer::dispatch(const testability::Header &req, const std::uint8_t *dat,
                                 std::size_t dat_len, const sockaddr_in &peer,
                                 std::uint8_t &rid_out, std::vector<std::uint8_t> &resp_dat) {
    const std::uint8_t gid = tp::gidOf(req.method_id);
    const std::uint8_t pid = tp::pidOf(req.method_id);

    if (gid == tp::kGidGeneral) {
        switch (pid) {
            case tp::kPidGetVersion: {
                // PRS_TPSP §6.10 GET_VERSION response: major/minor/patch (uint16 x3),
                // serialised through the protocol SSOT helper.
                tp::appendU16(resp_dat, tp::kVersionMajor);
                tp::appendU16(resp_dat, tp::kVersionMinor);
                tp::appendU16(resp_dat, tp::kVersionPatch);
                rid_out = tp::kRidEOk;
                return;
            }
            case tp::kPidStartTest:
                // PRS_TPSP §6.10 entry tag — no state change beyond marking the session.
                rid_out = tp::kRidEOk;
                return;
            case tp::kPidEndTest:
                // PRS_TPSP §6.10 reset: terminate active SPs (accept threads),
                // then close all test-channel sockets and clear state.
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
                rid_out = tp::kRidENtf;  // no remaining TCP SPs in this build
                return;
        }
    }

    rid_out = tp::kRidENtf;  // group not implemented by this DUT
}

std::uint8_t TestabilityServer::createAndBind(const std::uint8_t *dat, std::size_t dat_len,
                                              int socktype, std::uint16_t &socket_id_out) {
    // PRS_TPSP §6.10 CREATE_AND_BIND request: doBind(bool) + localPort(uint16) +
    // localAddr(ipxaddr). Shape is identical for UDP/TCP; socktype selects
    // SOCK_DGRAM / SOCK_STREAM.
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
    const int s = ::socket(AF_INET, socktype, proto);
    if (s < 0) {
        return tp::kRidEUcs;  // unable to create socket
    }
    if (do_bind) {
        int on = 1;
        ::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        // localPort 0xFFFF == PORT_ANY (PRS_TPSP §6.10) => 0 (kernel-assigned).
        addr.sin_port = htons(local_port == 0xFFFF ? 0 : local_port);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        if (addr_len == 4) {
            bool all_zero = addr_body[0] == 0 && addr_body[1] == 0 && addr_body[2] == 0 &&
                            addr_body[3] == 0;
            if (!all_zero) {
                std::memcpy(&addr.sin_addr.s_addr, addr_body, 4);  // wire bytes are NBO
            }
        }
        if (::bind(s, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
            ::close(s);
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
    // PRS_TPSP §6.10 SEND_DATA (UDP): socketId(u16) + totalLen(u16) + destPort(u16) +
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
    dst.sin_port = htons(dest_port);
    std::memcpy(&dst.sin_addr.s_addr, addr_body, 4);  // wire bytes are NBO
    const ssize_t sent = ::sendto(*fd, payload.data(), payload.size(), 0,
                                  reinterpret_cast<sockaddr *>(&dst), sizeof(dst));
    // Non-blocking semantics (PRS_TPSP §6.10): E_OK signals the transmission was issued,
    // not that it was delivered. A hard send failure surfaces as E_NOK.
    return sent < 0 ? tp::kRidENok : tp::kRidEOk;
}

std::uint8_t TestabilityServer::configureSocket(const std::uint8_t *dat, std::size_t dat_len) {
    // PRS_TPSP §6.10.10 CONFIGURE_SOCKET request: socketId(u16) + paramId(u16) +
    // paramVal(vint8). Group-agnostic — the IP-level options apply to both the UDP
    // and TCP arms; MSS/Nagle are TCP-only and the UDP-checksum toggle UDP-only,
    // where an inapplicable option surfaces as the kernel setsockopt failure ->
    // E_NOK.
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

    // Each fixed-width parameter must carry exactly its paramVal length
    // (PRS_TPSP §6.10.10); a mismatch is a malformed request.
    const auto fixed = [&](std::uint16_t want) { return val_len == want; };

    switch (param_id) {
        case tp::kCfgTtl:  // IP TTL / hop limit
            if (!fixed(1)) return tp::kRidEInv;
            return setIntSockOpt(*fd, IPPROTO_IP, IP_TTL, val[0]);
        case tp::kCfgPriority:  // traffic class / DSCP & ECN -> the IPv4 TOS byte
        case tp::kCfgTos:       // IP Type of Service (RFC 791) -> the IPv4 TOS byte
            if (!fixed(1)) return tp::kRidEInv;
            return setIntSockOpt(*fd, IPPROTO_IP, IP_TOS, val[0]);
        case tp::kCfgDontFragment:  // IP DF bit via the path-MTU-discovery mode
            if (!fixed(1)) return tp::kRidEInv;
            return setIntSockOpt(*fd, IPPROTO_IP, IP_MTU_DISCOVER,
                                 val[0] ? IP_PMTUDISC_DO : IP_PMTUDISC_DONT);
        case tp::kCfgIpTimestampOption:
            // paramVal is the raw option-4 bytes "as stored in the IP header"
            // (PRS_TPSP §6.10.10, RFC 791); hand them to IP_OPTIONS verbatim.
            return ::setsockopt(*fd, IPPROTO_IP, IP_OPTIONS, val, val_len) == 0 ? tp::kRidEOk
                                                                                : tp::kRidENok;
        case tp::kCfgMss:  // TCP maximum segment size (TCP only)
            if (!fixed(2)) return tp::kRidEInv;
            return setIntSockOpt(*fd, IPPROTO_TCP, TCP_MAXSEG, tp::readU16(val));
        case tp::kCfgNagle:  // Nagle enable=1 -> TCP_NODELAY is its inverse (TCP only)
            if (!fixed(1)) return tp::kRidEInv;
            return setIntSockOpt(*fd, IPPROTO_TCP, TCP_NODELAY, val[0] ? 0 : 1);
        case tp::kCfgUdpChecksum:  // UDP cksum tx enable=1 -> SO_NO_CHECK is its inverse (UDP only)
            if (!fixed(1)) return tp::kRidEInv;
            return setIntSockOpt(*fd, SOL_SOCKET, SO_NO_CHECK, val[0] ? 0 : 1);
        default:
            // Unknown / non-standard (0xFFFF-down) parameter not served here.
            return tp::kRidENtf;
    }
}

std::uint8_t TestabilityServer::connectTcp(const std::uint8_t *dat, std::size_t dat_len) {
    // PRS_TPSP §6.10 CONNECT (TCP): socketId(u16) + destPort(u16) + destAddr(ipxaddr).
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
    dst.sin_port = htons(dest_port);
    std::memcpy(&dst.sin_addr.s_addr, addr_body, 4);  // wire bytes are NBO
    // Bounded so an absent peer times out instead of freezing the dispatch loop.
    if (connectWithTimeout(*fd, dst, /*timeout_ms=*/1000) != 0) {
        return tp::kRidENok;  // connection refused / unreachable / timed out
    }
    // Record the connected 4-tuple so a later abort can SOCK_DESTROY a TIME-WAIT
    // residual (by then the tw_sock no longer maps back to the fd). `dst` is the
    // peer; getsockname yields the kernel-assigned local endpoint.
    sockaddr_in local{};
    socklen_t llen = sizeof(local);
    if (::getsockname(*fd, reinterpret_cast<sockaddr *>(&local), &llen) == 0) {
        std::lock_guard<std::mutex> lk(sockets_mu_);
        tcp_conn_[socket_id] = TcpConnTuple{local, dst};
    }
    return tp::kRidEOk;
}

std::uint8_t TestabilityServer::sendDataTcp(const std::uint8_t *dat, std::size_t dat_len) {
    // PRS_TPSP §6.10 SEND_DATA (TCP): socketId(u16) + totalLen(u16) + flags(u8) +
    // data(vint8). The socket is connection-oriented, so there is no per-call
    // destination; flags bit 7 is reserved and ignored here.
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
    const ssize_t sent = ::send(*fd, payload.data(), payload.size(), 0);
    // Non-blocking semantics (PRS_TPSP §6.10): E_OK signals the transmission was issued.
    return sent < 0 ? tp::kRidENok : tp::kRidEOk;
}

std::uint8_t TestabilityServer::listenAndAcceptTcp(const std::uint8_t *dat, std::size_t dat_len,
                                                   std::uint16_t service_id,
                                                   const sockaddr_in &peer) {
    // PRS_TPSP §6.10 LISTEN_AND_ACCEPT (TCP): listenSocketId(u16) + maxCon(u16).
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
    if (::listen(*fd, max_con) < 0) {
        return tp::kRidENok;  // not a bound stream socket / listen failed
    }

    // Accept asynchronously: E_OK returns now, each accepted connection is
    // reported later as an Event to the requesting tester. The accept thread also
    // drains the kernel accept queue (a listen-only case whose injected stimulus
    // completes a handshake — FLAGS_PROCESSING_05 — must not back the queue up and
    // block later SYNs). The worker's lifetime is owned by the listen socket
    // (stopWorker on close), so re-arm the slot (stop any prior worker on this
    // socket_id) before installing the new one.
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

void TestabilityServer::acceptLoop(int listen_fd, std::uint16_t service_id,
                                   std::uint16_t listen_socket_id, std::uint16_t max_con,
                                   sockaddr_in peer, std::shared_ptr<std::atomic<bool>> stop) {
    const int flags = ::fcntl(listen_fd, F_GETFL, 0);
    ::fcntl(listen_fd, F_SETFL, flags | O_NONBLOCK);

    std::uint16_t accepted = 0;
    while (!stop_requested_ && !reset_events_ && !stop->load() && accepted < max_con) {
        fd_set rset;
        FD_ZERO(&rset);
        FD_SET(listen_fd, &rset);
        timeval tv{};
        tv.tv_usec = kEventThreadWakeUs;
        const int sr = ::select(listen_fd + 1, &rset, nullptr, nullptr, &tv);
        if (sr == 0 || (sr < 0 && errno == EINTR)) {
            continue;  // 200 ms timeout or a signal — re-check stop flags
        }
        if (sr < 0) {
            // The listen fd was closed out from under us (EBADF after a
            // CLOSE_SOCKET on a listen-only socket that never accepted) or a
            // fatal select error: the listener is gone, so exit instead of
            // spinning on the dead fd. The thread is reclaimed at the next
            // joinEventThreads (END_TEST / stop).
            break;
        }
        sockaddr_in client{};
        socklen_t clen = sizeof(client);
        const int conn = ::accept(listen_fd, reinterpret_cast<sockaddr *>(&client), &clen);
        if (conn < 0) {
            continue;
        }
        const std::uint16_t new_socket_id = registerSocket(conn);
        ++accepted;

        // PRS_TPSP §6.10 LISTEN_AND_ACCEPT Event: listenSocketId + newSocketId +
        // clientPort + clientAddr(ipxaddr).
        std::vector<std::uint8_t> ev_dat;
        tp::appendU16(ev_dat, listen_socket_id);
        tp::appendU16(ev_dat, new_socket_id);
        tp::appendU16(ev_dat, ntohs(client.sin_port));
        tp::appendIpv4Addr(ev_dat, client.sin_addr.s_addr);
        emitEvent(service_id, tp::kGidTcp, tp::kPidListenAndAccept, ev_dat, peer);
    }
    ::fcntl(listen_fd, F_SETFL, flags);  // restore (listen fd lives in the table)
}

std::uint8_t TestabilityServer::closeSocket(const std::uint8_t *dat, std::size_t dat_len) {
    // PRS_TPSP §6.10 CLOSE_SOCKET request: socketId(uint16) + optional abort(bool,
    // TCP). abort=true closes the socket immediately (SO_LINGER {1,0} -> RST), not
    // waiting for outstanding transmissions and acknowledgements; the byte is
    // absent (or 0) for a graceful close and for UDP.
    if (dat_len < 2) {
        return tp::kRidEInv;
    }
    const std::uint16_t socket_id = tp::readU16(dat);
    const bool abort = (dat_len >= 3) && (dat[2] != 0);
    return eraseSocket(socket_id, abort) ? tp::kRidEOk : tp::kRidEIsd;
}

std::uint8_t TestabilityServer::shutdownSocket(const std::uint8_t *dat, std::size_t dat_len) {
    // PRS_TPSP §6.10 SHUTDOWN request: socketId(uint16) + typeId(uint8). typeId
    // selects the direction disallowed: 0x00 reception, 0x01 transmission, 0x02
    // both. Unlike CLOSE_SOCKET the fd lives on (a half-close), so the socket
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
    return ::shutdown(*fd, how) == 0 ? tp::kRidEOk : tp::kRidENok;
}

std::uint8_t TestabilityServer::receiveAndForward(const std::uint8_t *dat, std::size_t dat_len,
                                                  std::uint16_t service_id,
                                                  const sockaddr_in &peer,
                                                  std::vector<std::uint8_t> &resp_dat, bool udp) {
    // PRS_TPSP §6.10 RECEIVE_AND_FORWARD (UDP/TCP): socketId(u16) + maxFwd(u16) +
    // maxLen(u16). Response: dropCnt(u16). The request shape is group-independent;
    // `udp` selects the forward loop (datagram source-bearing Event vs TCP stream).
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
    // call (TCP: reopen the receive window; UDP: drop pre-call datagrams) and
    // report the count as dropCnt. Non-blocking so an empty queue does not stall
    // the dispatch loop.
    const int flags = ::fcntl(*fd, F_GETFL, 0);
    ::fcntl(*fd, F_SETFL, flags | O_NONBLOCK);
    std::uint32_t dropped = 0;
    std::uint8_t drain[2048];
    for (;;) {
        const ssize_t n = ::recv(*fd, drain, sizeof(drain), 0);
        if (n <= 0) {
            break;
        }
        dropped += static_cast<std::uint32_t>(n);
    }
    ::fcntl(*fd, F_SETFL, flags);
    // dropCnt is a u16 field (PRS_TPSP §6.10); saturate rather than wrap so an
    // overlong inactive phase reports the max instead of a small modulo value.
    tp::appendU16(resp_dat, static_cast<std::uint16_t>(dropped > 0xFFFF ? 0xFFFF : dropped));

    // Active phase: forward subsequently-received data as Events on a worker
    // thread — the same async lifecycle (and socket-owned lifetime) as
    // LISTEN_AND_ACCEPT. Re-arm the slot before installing the new worker.
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
                                       sockaddr_in peer,
                                       std::shared_ptr<std::atomic<bool>> stop) {
    const bool limitless = (max_len == 0xFFFF);  // PRS_TPSP §6.10 maxLen 0xFFFF
    const int flags = ::fcntl(conn_fd, F_GETFL, 0);
    ::fcntl(conn_fd, F_SETFL, flags | O_NONBLOCK);

    std::uint32_t consumed = 0;
    while (!stop_requested_ && !reset_events_ && !stop->load() && (limitless || consumed < max_len)) {
        fd_set rset;
        FD_ZERO(&rset);
        FD_SET(conn_fd, &rset);
        timeval tv{};
        tv.tv_usec = kEventThreadWakeUs;
        const int sr = ::select(conn_fd + 1, &rset, nullptr, nullptr, &tv);
        if (sr == 0 || (sr < 0 && errno == EINTR)) {
            continue;  // timeout or signal — re-check the stop/reset flags
        }
        if (sr < 0) {
            break;  // conn fd closed under us / fatal select error — stop
        }
        std::uint8_t buf[2048];
        std::size_t want = sizeof(buf);
        if (!limitless) {
            const std::uint32_t remaining = max_len - consumed;
            if (remaining < want) {
                want = remaining;
            }
        }
        const ssize_t n = ::recv(conn_fd, buf, want, 0);
        if (n <= 0) {
            if (n == 0) {
                break;  // peer closed the connection
            }
            continue;
        }
        consumed += static_cast<std::uint32_t>(n);
        const std::uint16_t full_len = static_cast<std::uint16_t>(n);
        const std::uint16_t fwd_len =
            static_cast<std::uint16_t>(n < static_cast<ssize_t>(max_fwd) ? n : max_fwd);

        // PRS_TPSP §6.10 RECEIVE_AND_FORWARD Event (TCP): fullLen(u16) + payload(vint8).
        // TCP has no srcPort/srcAddr (connection-oriented). fullLen is THIS
        // recv()'s length, not a whole logical message — a stream split across
        // recv()s emits one Event each.
        std::vector<std::uint8_t> ev_dat;
        tp::appendU16(ev_dat, full_len);
        tp::appendVint8(ev_dat, buf, fwd_len);
        emitEvent(service_id, tp::kGidTcp, tp::kPidReceiveAndForward, ev_dat, peer);
    }
    ::fcntl(conn_fd, F_SETFL, flags);  // restore (conn fd lives in the table)
}

void TestabilityServer::receiveLoopUdp(int sock_fd, std::uint16_t service_id,
                                       std::uint16_t max_fwd, std::uint16_t max_len,
                                       sockaddr_in peer,
                                       std::shared_ptr<std::atomic<bool>> stop) {
    const bool limitless = (max_len == 0xFFFF);  // PRS_TPSP §6.10 maxLen 0xFFFF
    const int flags = ::fcntl(sock_fd, F_GETFL, 0);
    ::fcntl(sock_fd, F_SETFL, flags | O_NONBLOCK);

    std::uint32_t consumed = 0;
    while (!stop_requested_ && !reset_events_ && !stop->load() &&
           (limitless || consumed < max_len)) {
        fd_set rset;
        FD_ZERO(&rset);
        FD_SET(sock_fd, &rset);
        timeval tv{};
        tv.tv_usec = kEventThreadWakeUs;
        const int sr = ::select(sock_fd + 1, &rset, nullptr, nullptr, &tv);
        if (sr == 0 || (sr < 0 && errno == EINTR)) {
            continue;  // timeout or signal — re-check the stop/reset flags
        }
        if (sr < 0) {
            break;  // sock fd closed under us / fatal select error — stop
        }
        std::uint8_t buf[2048];
        sockaddr_in src{};
        socklen_t srclen = sizeof(src);
        // MSG_TRUNC: the return value is the true datagram length even when it
        // overflows `buf`, so fullLen is exact while the buffer holds at most
        // sizeof(buf) bytes to forward from.
        const ssize_t n = ::recvfrom(sock_fd, buf, sizeof(buf), MSG_TRUNC,
                                     reinterpret_cast<sockaddr *>(&src), &srclen);
        if (n < 0) {
            continue;  // spurious wakeup on the non-blocking socket
        }
        // A zero-length UDP datagram is a valid event (fullLen 0), NOT a peer
        // close — the key behavioural split from the TCP body above.
        const std::size_t in_buf =
            (static_cast<std::size_t>(n) < sizeof(buf)) ? static_cast<std::size_t>(n) : sizeof(buf);
        consumed += static_cast<std::uint32_t>(n);
        const std::uint16_t full_len = static_cast<std::uint16_t>(n > 0xFFFF ? 0xFFFF : n);
        const std::uint16_t fwd_len =
            static_cast<std::uint16_t>(in_buf < max_fwd ? in_buf : max_fwd);

        // PRS_TPSP §6.10 RECEIVE_AND_FORWARD Event (UDP): fullLen(u16) +
        // srcPort(u16) + srcAddr(ipxaddr) + payload(vint8). The connectionless
        // variant reports each datagram's source endpoint.
        std::vector<std::uint8_t> ev_dat;
        tp::appendU16(ev_dat, full_len);
        tp::appendU16(ev_dat, ntohs(src.sin_port));
        tp::appendIpv4Addr(ev_dat, src.sin_addr.s_addr);
        tp::appendVint8(ev_dat, buf, fwd_len);
        emitEvent(service_id, tp::kGidUdp, tp::kPidReceiveAndForward, ev_dat, peer);
    }
    ::fcntl(sock_fd, F_SETFL, flags);  // restore (sock fd lives in the table)
}

void TestabilityServer::emitEvent(std::uint16_t service_id, std::uint8_t gid, std::uint8_t pid,
                                  const std::vector<std::uint8_t> &dat,
                                  const sockaddr_in &peer) {
    // PRS_TPSP §6.2 Event: EVB-set method id for group `gid` + TID 0x02. fd_ is
    // written here concurrently by the event worker threads and serverLoop; each
    // ::sendto emits a single sub-MTU datagram, which the kernel serialises, so
    // these writes need no lock (unlike the socket table, whose multi-step
    // operations are guarded by sockets_mu_).
    tp::Header ev;
    ev.service_id = service_id;
    ev.method_id = tp::methodId(gid, pid, /*event=*/true);
    ev.tid = tp::kTidEvent;
    ev.rid = tp::kRidEOk;
    const auto out = tp::buildMessage(ev, dat.data(), dat.size());
    ::sendto(fd_, out.data(), out.size(), 0, reinterpret_cast<const sockaddr *>(&peer),
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
    // fd, so the worker has exited and can never select/accept on the fd once it
    // is closed and the number reused. Done outside sockets_mu_ (stopWorker takes
    // only workers_mu_) so a worker blocked in registerSocket cannot deadlock the
    // join.
    stopWorker(id);

    std::optional<TcpConnTuple> tuple;
    {
        std::lock_guard<std::mutex> lk(sockets_mu_);
        const auto it = sockets_.find(id);
        if (it == sockets_.end()) {
            return false;
        }
        if (abort) {
            // Abortive close: SO_LINGER {on, linger=0} makes ::close emit a RST
            // and skip the graceful FIN — "closes immediately, not waiting for
            // outstanding transmissions and acknowledgements" (PRS_TPSP §6.10
            // CLOSE_SOCKET abort). Reaches CLOSED from EST / FIN-WAIT / CLOSING /
            // LAST-ACK on its own; a TIME-WAIT residual needs the SOCK_DESTROY
            // below.
            const linger lg{/*l_onoff=*/1, /*l_linger=*/0};
            ::setsockopt(it->second, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
        }
        ::close(it->second);
        sockets_.erase(it);
        const auto ct = tcp_conn_.find(id);
        if (ct != tcp_conn_.end()) {
            tuple = ct->second;
            tcp_conn_.erase(ct);
        }
    }
    // Outside the lock (SOCK_DESTROY shells out): a TIME-WAIT abort needs
    // sock_diag to kill the detached tw_sock SO_LINGER + close cannot reach.
    if (abort && tuple.has_value()) {
        destroyTimeWaitResidual(*tuple);
    }
    return true;
}

void TestabilityServer::destroyTimeWaitResidual(const TcpConnTuple &t) {
    // sock_diag SOCK_DESTROY over a direct netlink request — terminate the
    // TIME-WAIT residual that SO_LINGER + close left behind (the detached tw_sock
    // no longer maps to the fd, so close cannot reach it). A direct netlink send,
    // not a shell-out to `ss -K`: fork+exec from this multi-threaded server is
    // both slow and unsafe (the child inherits locks held by other threads).
    // Best-effort and fire-and-forget — a kernel lacking CAP_NET_ADMIN or a
    // 4-tuple already CLOSED simply ignores it; the case's verify-probe is the
    // authoritative CLOSED check. idiag_states = ~0 so any state (TIME-WAIT
    // included) matches.
    const int nl = ::socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);
    if (nl < 0) {
        return;
    }
    struct {
        ::nlmsghdr nlh;
        ::inet_diag_req_v2 req;
    } msg{};
    msg.nlh.nlmsg_len        = sizeof(msg);
    msg.nlh.nlmsg_type       = SOCK_DESTROY;
    msg.nlh.nlmsg_flags      = NLM_F_REQUEST;
    msg.req.sdiag_family     = AF_INET;
    msg.req.sdiag_protocol   = IPPROTO_TCP;
    msg.req.idiag_states     = ~0U;
    msg.req.id.idiag_sport   = t.local.sin_port;  // already network byte order
    msg.req.id.idiag_dport   = t.peer.sin_port;
    msg.req.id.idiag_src[0]  = t.local.sin_addr.s_addr;
    msg.req.id.idiag_dst[0]  = t.peer.sin_addr.s_addr;
    msg.req.id.idiag_cookie[0] = INET_DIAG_NOCOOKIE;
    msg.req.id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;
    const ssize_t sent = ::send(nl, &msg, sizeof(msg), 0);
    (void)sent;
    ::close(nl);
}

void TestabilityServer::closeAllSockets() {
    std::lock_guard<std::mutex> lk(sockets_mu_);
    for (const auto &kv : sockets_) {
        ::close(kv.second);
    }
    sockets_.clear();
    tcp_conn_.clear();  // keep the connected-4-tuple map in lockstep with sockets_
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

}  // namespace tc8::dut
