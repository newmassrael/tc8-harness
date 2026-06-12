#include "testability_server.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>

namespace tc8::dut {

namespace tp = ::tc8::testability;

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
        dispatch(*header, dat, dat_len, rid, resp_dat);

        tp::Header resp = *header;     // echo service_id + method_id
        resp.tid = tp::kTidResponse;   // PRS_TPSP §6.2 Response
        resp.rid = rid;
        const auto out = tp::buildMessage(resp, resp_dat.empty() ? nullptr : resp_dat.data(),
                                          resp_dat.size());
        ::sendto(fd_, out.data(), out.size(), 0, reinterpret_cast<sockaddr *>(&peer), plen);
    }
}

void TestabilityServer::dispatch(const testability::Header &req, const std::uint8_t *dat,
                                 std::size_t dat_len, std::uint8_t &rid_out,
                                 std::vector<std::uint8_t> &resp_dat) {
    const std::uint8_t gid = tp::gidOf(req.method_id);
    const std::uint8_t pid = tp::pidOf(req.method_id);

    if (gid == tp::kGidGeneral) {
        switch (pid) {
            case tp::kPidGetVersion: {
                // PRS_TPSP §6.10 GET_VERSION response: major/minor/patch (uint16 x3).
                const std::uint16_t ver[3] = {tp::kVersionMajor, tp::kVersionMinor,
                                              tp::kVersionPatch};
                for (std::uint16_t v : ver) {
                    resp_dat.push_back(static_cast<std::uint8_t>(v >> 8));
                    resp_dat.push_back(static_cast<std::uint8_t>(v & 0xFF));
                }
                rid_out = tp::kRidEOk;
                return;
            }
            case tp::kPidStartTest:
                // PRS_TPSP §6.10 entry tag — no state change beyond marking the session.
                rid_out = tp::kRidEOk;
                return;
            case tp::kPidEndTest:
                // PRS_TPSP §6.10 reset: close all test-channel sockets, clear state.
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
            case tp::kPidCreateAndBind: {
                std::uint16_t id = 0;
                rid_out = createAndBind(dat, dat_len, id);
                if (rid_out == tp::kRidEOk) {
                    resp_dat.push_back(static_cast<std::uint8_t>(id >> 8));
                    resp_dat.push_back(static_cast<std::uint8_t>(id & 0xFF));
                }
                return;
            }
            case tp::kPidSendData:
                rid_out = sendData(dat, dat_len);
                return;
            case tp::kPidCloseSocket:
                rid_out = closeSocket(dat, dat_len);
                return;
            default:
                rid_out = tp::kRidENtf;
                return;
        }
    }

    rid_out = tp::kRidENtf;  // group not implemented by this DUT
}

std::uint8_t TestabilityServer::createAndBind(const std::uint8_t *dat, std::size_t dat_len,
                                              std::uint16_t &socket_id_out) {
    // PRS_TPSP §6.10 CREATE_AND_BIND request: doBind(bool) + localPort(uint16) +
    // localAddr(ipxaddr). UDP group => SOCK_DGRAM.
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

    const int s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
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

    const std::uint16_t id = next_socket_id_++;
    sockets_[id] = s;
    socket_id_out = id;
    return tp::kRidEOk;
}

std::uint8_t TestabilityServer::sendData(const std::uint8_t *dat, std::size_t dat_len) {
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

    const auto it = sockets_.find(socket_id);
    if (it == sockets_.end()) {
        return tp::kRidEIsd;  // invalid socket id
    }

    // totalLen: repeat data up to that length; if smaller than data, send the
    // full data (PRS_TPSP §6.10).
    std::vector<std::uint8_t> payload;
    const std::size_t want = (total_len > data_len) ? total_len : data_len;
    payload.reserve(want);
    if (data_len == 0) {
        payload.assign(want, 0);
    } else {
        while (payload.size() < want) {
            const std::size_t take = ((want - payload.size()) < data_len)
                                         ? (want - payload.size())
                                         : data_len;
            payload.insert(payload.end(), data_body, data_body + take);
        }
    }

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(dest_port);
    std::memcpy(&dst.sin_addr.s_addr, addr_body, 4);  // wire bytes are NBO
    const ssize_t sent = ::sendto(it->second, payload.data(), payload.size(), 0,
                                  reinterpret_cast<sockaddr *>(&dst), sizeof(dst));
    // Non-blocking semantics (PRS_TPSP §6.10): E_OK signals the transmission was issued,
    // not that it was delivered. A hard send failure surfaces as E_NOK.
    return sent < 0 ? tp::kRidENok : tp::kRidEOk;
}

std::uint8_t TestabilityServer::closeSocket(const std::uint8_t *dat, std::size_t dat_len) {
    // PRS_TPSP §6.10 CLOSE_SOCKET request: socketId(uint16).
    if (dat_len < 2) {
        return tp::kRidEInv;
    }
    const std::uint16_t socket_id = tp::readU16(dat);
    const auto it = sockets_.find(socket_id);
    if (it == sockets_.end()) {
        return tp::kRidEIsd;
    }
    ::close(it->second);
    sockets_.erase(it);
    return tp::kRidEOk;
}

void TestabilityServer::closeAllSockets() {
    for (const auto &kv : sockets_) {
        ::close(kv.second);
    }
    sockets_.clear();
}

}  // namespace tc8::dut
