#include "testability_server.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>

namespace tc8::dut {

namespace tp = ::tc8::testability;

namespace {

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
                rid_out = receiveAndForward(dat, dat_len, req.service_id, peer, resp_dat);
                return;
            default:
                rid_out = tp::kRidENtf;  // remaining TCP SPs (CONFIGURE_SOCKET) not served
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
    // reported later as an Event to the requesting tester.
    event_threads_.emplace_back(&TestabilityServer::acceptLoop, this, *fd, service_id,
                                 listen_socket_id, max_con, peer);
    return tp::kRidEOk;
}

void TestabilityServer::acceptLoop(int listen_fd, std::uint16_t service_id,
                                   std::uint16_t listen_socket_id, std::uint16_t max_con,
                                   sockaddr_in peer) {
    const int flags = ::fcntl(listen_fd, F_GETFL, 0);
    ::fcntl(listen_fd, F_SETFL, flags | O_NONBLOCK);

    std::uint16_t accepted = 0;
    while (!stop_requested_ && !reset_events_ && accepted < max_con) {
        fd_set rset;
        FD_ZERO(&rset);
        FD_SET(listen_fd, &rset);
        timeval tv{};
        tv.tv_usec = 200 * 1000;  // 200 ms wake to re-check stop_requested_
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
        // clientPort + clientAddr(ipxaddr), TID 0x02 / EVB set in the method id.
        std::vector<std::uint8_t> ev_dat;
        tp::appendU16(ev_dat, listen_socket_id);
        tp::appendU16(ev_dat, new_socket_id);
        tp::appendU16(ev_dat, ntohs(client.sin_port));
        tp::appendIpv4Addr(ev_dat, client.sin_addr.s_addr);

        tp::Header ev;
        ev.service_id = service_id;
        ev.method_id = tp::methodId(tp::kGidTcp, tp::kPidListenAndAccept, /*event=*/true);
        ev.tid = tp::kTidEvent;
        ev.rid = tp::kRidEOk;
        const auto out = tp::buildMessage(ev, ev_dat.data(), ev_dat.size());
        ::sendto(fd_, out.data(), out.size(), 0, reinterpret_cast<const sockaddr *>(&peer),
                 sizeof(peer));
    }
    ::fcntl(listen_fd, F_SETFL, flags);  // restore (listen fd lives in the table)
}

std::uint8_t TestabilityServer::closeSocket(const std::uint8_t *dat, std::size_t dat_len) {
    // PRS_TPSP §6.10 CLOSE_SOCKET request: socketId(uint16).
    if (dat_len < 2) {
        return tp::kRidEInv;
    }
    const std::uint16_t socket_id = tp::readU16(dat);
    return eraseSocket(socket_id) ? tp::kRidEOk : tp::kRidEIsd;
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
                                                  std::vector<std::uint8_t> &resp_dat) {
    // PRS_TPSP §6.10 RECEIVE_AND_FORWARD (TCP): socketId(u16) + maxFwd(u16) +
    // maxLen(u16). Response: dropCnt(u16).
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

    // PRS_TPSP §6.12.4 inactive-phase drain: consume the bytes queued before
    // this call to reopen the receive window and report the count as dropCnt.
    // Non-blocking so an empty queue does not stall the dispatch loop.
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
    // thread — the same async lifecycle LISTEN_AND_ACCEPT uses.
    event_threads_.emplace_back(&TestabilityServer::receiveLoop, this, *fd, service_id, socket_id,
                                max_fwd, max_len, peer);
    return tp::kRidEOk;
}

void TestabilityServer::receiveLoop(int conn_fd, std::uint16_t service_id,
                                    std::uint16_t socket_id, std::uint16_t max_fwd,
                                    std::uint16_t max_len, sockaddr_in peer) {
    (void)socket_id;  // the connection fd is the routing key; socketId is the caller's handle
    const bool limitless = (max_len == 0xFFFF);  // PRS_TPSP §6.10 maxLen 0xFFFF
    const int flags = ::fcntl(conn_fd, F_GETFL, 0);
    ::fcntl(conn_fd, F_SETFL, flags | O_NONBLOCK);

    std::uint32_t consumed = 0;
    while (!stop_requested_ && !reset_events_ && (limitless || consumed < max_len)) {
        fd_set rset;
        FD_ZERO(&rset);
        FD_SET(conn_fd, &rset);
        timeval tv{};
        tv.tv_usec = 200 * 1000;  // 200 ms wake to re-check stop/reset
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

        // PRS_TPSP §6.10 RECEIVE_AND_FORWARD Event: fullLen(u16) + payload(vint8),
        // TID 0x02 / EVB set. TCP has no srcPort/srcAddr (connection-oriented).
        std::vector<std::uint8_t> ev_dat;
        tp::appendU16(ev_dat, full_len);
        tp::appendVint8(ev_dat, buf, fwd_len);

        tp::Header ev;
        ev.service_id = service_id;
        ev.method_id = tp::methodId(tp::kGidTcp, tp::kPidReceiveAndForward, /*event=*/true);
        ev.tid = tp::kTidEvent;
        ev.rid = tp::kRidEOk;
        const auto out = tp::buildMessage(ev, ev_dat.data(), ev_dat.size());
        ::sendto(fd_, out.data(), out.size(), 0, reinterpret_cast<const sockaddr *>(&peer),
                 sizeof(peer));
    }
    ::fcntl(conn_fd, F_SETFL, flags);  // restore (conn fd lives in the table)
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

bool TestabilityServer::eraseSocket(std::uint16_t id) {
    std::lock_guard<std::mutex> lk(sockets_mu_);
    const auto it = sockets_.find(id);
    if (it == sockets_.end()) {
        return false;
    }
    ::close(it->second);
    sockets_.erase(it);
    return true;
}

void TestabilityServer::closeAllSockets() {
    std::lock_guard<std::mutex> lk(sockets_mu_);
    for (const auto &kv : sockets_) {
        ::close(kv.second);
    }
    sockets_.clear();
}

void TestabilityServer::joinEventThreads() {
    for (std::thread &t : event_threads_) {
        if (t.joinable()) {
            t.join();
        }
    }
    event_threads_.clear();
}

}  // namespace tc8::dut
