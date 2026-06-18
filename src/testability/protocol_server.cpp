#include "testability/protocol_server.h"

#include <cstring>
#include <utility>

#include "wire/icmp_echo.h"

namespace tc8::testability {

namespace {

// Wake interval for the async-event SP worker threads' wait loop — bounds how
// fast acceptLoop / receiveLoop notice the stop / reset flags.
constexpr int kEventThreadWakeUs = 200 * 1000;  // 200 ms

// PRS_TPSP §6.10 SEND_DATA totalLen rule, shared by the UDP and TCP backends:
// repeat `data` up to `total_len` bytes; if total_len < data_len send the full
// data. data_len == 0 yields `total_len` zero bytes. Pure byte math — the single
// source for both groups and (post-refactor) both platforms.
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

// Endpoint from 4 network-byte-order address bytes + a host-order port.
Endpoint endpointFromWire(const std::uint8_t *addr_be4, std::uint16_t host_port) {
    Endpoint e;
    e.port = host_port;
    std::memcpy(&e.addr_be, addr_be4, 4);
    return e;
}

}  // namespace

ProtocolServer::ProtocolServer(std::unique_ptr<SocketBackend> backend)
    : backend_(std::move(backend)) {}

ProtocolServer::~ProtocolServer() {
    stop();
}

bool ProtocolServer::start(std::uint16_t port) {
    fd_ = backend_->createUdp();
    if (fd_ < 0) {
        return false;
    }
    backend_->setReuseAddr(fd_);
    // 200 ms recv timeout so the loop wakes to check stop_requested_.
    backend_->setRecvTimeoutMs(fd_, 200);
    if (!backend_->bindV4(fd_, /*addr_be=*/0, port)) {  // 0 == INADDR_ANY
        backend_->closeFd(fd_);
        fd_ = -1;
        return false;
    }
    thread_ = std::thread([this] { serverLoop(); });
    return true;
}

void ProtocolServer::stop() {
    stop_requested_ = true;
    if (thread_.joinable()) {
        thread_.join();
    }
    joinEventThreads();
    if (fd_ >= 0) {
        backend_->closeFd(fd_);
        fd_ = -1;
    }
    closeAllSockets();
}

void ProtocolServer::registerPrimitive(std::uint8_t gid, std::uint8_t pid, SpHandler handler) {
    oem_handlers_[methodId(gid, pid)] = std::move(handler);
}

void ProtocolServer::serverLoop() {
    std::uint8_t buf[2048];
    while (!stop_requested_) {
        Endpoint peer;
        const int n = backend_->recvFromV4(fd_, buf, sizeof(buf), peer);
        // recvFromV4 reports the true datagram length (may exceed the buffer);
        // cap to what is actually in `buf` for parsing.
        if (n < static_cast<int>(kHeaderSize)) {
            continue;  // timeout or runt
        }
        const std::size_t avail =
            (static_cast<std::size_t>(n) < sizeof(buf)) ? static_cast<std::size_t>(n) : sizeof(buf);
        const auto header = parseHeader(buf, avail);
        if (!header || header->tid != kTidRequest) {
            continue;  // not a request addressed to us
        }

        const std::uint8_t *dat = buf + kHeaderSize;
        const std::size_t dat_len = avail - kHeaderSize;

        std::uint8_t rid = kRidEOk;
        std::vector<std::uint8_t> resp_dat;
        dispatch(*header, dat, dat_len, peer, rid, resp_dat);

        Header resp = *header;     // echo service_id + method_id
        resp.tid = kTidResponse;   // PRS_TPSP §6.2 Response
        resp.rid = rid;
        const auto out =
            buildMessage(resp, resp_dat.empty() ? nullptr : resp_dat.data(), resp_dat.size());
        std::lock_guard<std::mutex> lk(send_mu_);
        backend_->sendToV4(fd_, out.data(), out.size(), peer);
    }
}

void ProtocolServer::dispatch(const Header &req, const std::uint8_t *dat, std::size_t dat_len,
                              const Endpoint &peer, std::uint8_t &rid_out,
                              std::vector<std::uint8_t> &resp_dat) {
    const std::uint8_t gid = gidOf(req.method_id);
    const std::uint8_t pid = pidOf(req.method_id);

    // PRS_TPSP §6.6 OEM extension/override seam: a registered handler for this
    // (gid, pid) takes precedence over the built-in standard groups.
    if (const auto it = oem_handlers_.find(methodId(gid, pid)); it != oem_handlers_.end()) {
        it->second(req, dat, dat_len, peer, rid_out, resp_dat);
        return;
    }

    if (gid == kGidGeneral) {
        switch (pid) {
            case kPidGetVersion:
                appendU16(resp_dat, kVersionMajor);
                appendU16(resp_dat, kVersionMinor);
                appendU16(resp_dat, kVersionPatch);
                rid_out = kRidEOk;
                return;
            case kPidStartTest:
                rid_out = kRidEOk;
                return;
            case kPidEndTest:
                reset_events_ = true;
                joinEventThreads();
                reset_events_ = false;
                closeAllSockets();
                rid_out = kRidEOk;
                return;
            default:
                rid_out = kRidENtf;  // PRS_TPSP §6.8 service primitive not found
                return;
        }
    }

    if (gid == kGidUdp) {
        switch (pid) {
            case kPidCreateAndBind:
                respondCreateAndBind(/*tcp=*/false, dat, dat_len, rid_out, resp_dat);
                return;
            case kPidSendData:
                rid_out = sendDataUdp(dat, dat_len);
                return;
            case kPidCloseSocket:
                rid_out = closeSocket(dat, dat_len);
                return;
            case kPidShutdown:
                rid_out = shutdownSocket(dat, dat_len);
                return;
            case kPidReceiveAndForward:
                rid_out = receiveAndForward(dat, dat_len, req.service_id, peer, resp_dat,
                                            /*udp=*/true);
                return;
            case kPidConfigureSocket:
                rid_out = configureSocket(dat, dat_len);
                return;
            default:
                rid_out = kRidENtf;
                return;
        }
    }

    if (gid == kGidTcp) {
        switch (pid) {
            case kPidCreateAndBind:
                respondCreateAndBind(/*tcp=*/true, dat, dat_len, rid_out, resp_dat);
                return;
            case kPidConnect:
                rid_out = connectTcp(dat, dat_len);
                return;
            case kPidListenAndAccept:
                rid_out = listenAndAcceptTcp(dat, dat_len, req.service_id, peer);
                return;
            case kPidSendData:
                rid_out = sendDataTcp(dat, dat_len);
                return;
            case kPidCloseSocket:
                rid_out = closeSocket(dat, dat_len);
                return;
            case kPidShutdown:
                rid_out = shutdownSocket(dat, dat_len);
                return;
            case kPidReceiveAndForward:
                rid_out = receiveAndForward(dat, dat_len, req.service_id, peer, resp_dat,
                                            /*udp=*/false);
                return;
            case kPidConfigureSocket:
                rid_out = configureSocket(dat, dat_len);
                return;
            default:
                rid_out = kRidENtf;
                return;
        }
    }

    if (gid == kGidIcmp) {
        switch (pid) {
            case kPidEchoRequest:
                rid_out = echoRequest(dat, dat_len);
                return;
            default:
                rid_out = kRidENtf;  // ICMP group defines only ECHO_REQUEST
                return;
        }
    }

    if (gid == kGidIcmpv6) {
        switch (pid) {
            case kPidEchoRequest:
                rid_out = echoRequestV6(dat, dat_len);
                return;
            default:
                rid_out = kRidENtf;  // ICMPv6 group defines only ECHO_REQUEST
                return;
        }
    }

    if (gid == kGidIp) {
        switch (pid) {
            case kPidStaticAddress:
                rid_out = staticAddress(dat, dat_len);
                return;
            case kPidStaticRoute:
                rid_out = staticRoute(dat, dat_len);
                return;
            default:
                rid_out = kRidENtf;  // IP group defines only STATIC_ADDRESS/ROUTE
                return;
        }
    }

    if (gid == kGidEth) {
        switch (pid) {
            case kPidInterfaceUp:
                rid_out = setInterface(dat, dat_len, /*up=*/true);
                return;
            case kPidInterfaceDown:
                rid_out = setInterface(dat, dat_len, /*up=*/false);
                return;
            default:
                rid_out = kRidENtf;  // ETH group defines only INTERFACE_UP/DOWN
                return;
        }
    }

    rid_out = kRidENtf;  // group not implemented
}

std::uint8_t ProtocolServer::createAndBind(const std::uint8_t *dat, std::size_t dat_len, bool tcp,
                                           std::uint16_t &socket_id_out) {
    // PRS_TPSP §6.10 CREATE_AND_BIND: doBind(bool) + localPort(uint16) +
    // localAddr(ipxaddr). Shape identical for UDP/TCP; `tcp` selects the kind.
    if (dat_len < 1 + 2 + 2) {
        return kRidEInv;
    }
    const bool do_bind = dat[0] != 0;
    const std::uint16_t local_port = readU16(dat + 1);
    std::size_t off = 3;
    const std::uint8_t *addr_body = nullptr;
    std::uint16_t addr_len = 0;
    if (!readVint8(dat, dat_len, off, addr_body, addr_len)) {
        return kRidEInv;
    }
    if (addr_len != 0 && addr_len != 4) {
        return kRidEInv;  // IPv6 (n=16) not implemented in this iteration
    }

    const int s = tcp ? backend_->createTcp() : backend_->createUdp();
    if (s < 0) {
        return kRidEUcs;  // unable to create socket
    }
    if (do_bind) {
        backend_->setReuseAddr(s);
        std::uint32_t addr_be = 0;  // INADDR_ANY
        if (addr_len == 4) {
            const bool all_zero = addr_body[0] == 0 && addr_body[1] == 0 && addr_body[2] == 0 &&
                                  addr_body[3] == 0;
            if (!all_zero) {
                std::memcpy(&addr_be, addr_body, 4);  // wire bytes are NBO
            }
        }
        // localPort 0xFFFF == PORT_ANY (PRS_TPSP §6.10) => 0 (kernel-assigned).
        const std::uint16_t bind_port = (local_port == 0xFFFF) ? 0 : local_port;
        if (!backend_->bindV4(s, addr_be, bind_port)) {
            backend_->closeFd(s);
            return kRidEUbs;  // unable to bind, port taken
        }
    }

    socket_id_out = registerSocket(s);
    return kRidEOk;
}

void ProtocolServer::respondCreateAndBind(bool tcp, const std::uint8_t *dat, std::size_t dat_len,
                                          std::uint8_t &rid_out,
                                          std::vector<std::uint8_t> &resp_dat) {
    std::uint16_t id = 0;
    rid_out = createAndBind(dat, dat_len, tcp, id);
    if (rid_out == kRidEOk) {
        appendU16(resp_dat, id);  // PRS_TPSP §6.10 response: socketId(uint16)
    }
}

std::uint8_t ProtocolServer::sendDataUdp(const std::uint8_t *dat, std::size_t dat_len) {
    // PRS_TPSP §6.10 SEND_DATA (UDP): socketId + totalLen + destPort +
    // destAddr(ipxaddr) + data(vint8).
    if (dat_len < 2 + 2 + 2) {
        return kRidEInv;
    }
    const std::uint16_t socket_id = readU16(dat);
    const std::uint16_t total_len = readU16(dat + 2);
    const std::uint16_t dest_port = readU16(dat + 4);
    std::size_t off = 6;
    const std::uint8_t *addr_body = nullptr;
    std::uint16_t addr_len = 0;
    if (!readVint8(dat, dat_len, off, addr_body, addr_len) || addr_len != 4) {
        return kRidEInv;
    }
    const std::uint8_t *data_body = nullptr;
    std::uint16_t data_len = 0;
    if (!readVint8(dat, dat_len, off, data_body, data_len)) {
        return kRidEInv;
    }

    const auto fd = lookupSocket(socket_id);
    if (!fd) {
        return kRidEIsd;  // invalid socket id
    }

    const std::vector<std::uint8_t> payload =
        buildRepeatedPayload(data_body, data_len, total_len);
    const Endpoint dst = endpointFromWire(addr_body, dest_port);
    const int sent = backend_->sendToV4(*fd, payload.data(), payload.size(), dst);
    // Non-blocking semantics (PRS_TPSP §6.10): E_OK means the transmission was
    // issued; a hard send failure surfaces as E_NOK.
    return sent < 0 ? kRidENok : kRidEOk;
}

std::uint8_t ProtocolServer::echoRequest(const std::uint8_t *dat, std::size_t dat_len) {
    // PRS_TPSP §6.10 ECHO_REQUEST (ICMP): ifName(text) + destAddr(ipxaddr) + data(vint8).
    std::size_t off = 0;
    std::string ifname;
    if (!readText(dat, dat_len, off, ifname)) {
        return kRidEInv;
    }
    const std::uint8_t *addr_body = nullptr;
    std::uint16_t addr_len = 0;
    if (!readVint8(dat, dat_len, off, addr_body, addr_len) || addr_len != 4) {
        return kRidEInv;  // IPv4 ipxaddr only — ICMPv6 is a separate GID
    }
    std::uint32_t dest_be = 0;
    std::memcpy(&dest_be, addr_body, 4);
    const std::uint8_t *data_body = nullptr;
    std::uint16_t data_len = 0;
    if (!readVint8(dat, dat_len, off, data_body, data_len)) {
        return kRidEInv;
    }

    // Frame the Echo Request via the shared wire builder — the same source the
    // tester stimulus echoes from, so DUT-emitted and tester-observed bytes
    // agree by construction. The backend only sends it (and resolves ifName).
    const std::vector<std::uint8_t> msg =
        tc8::wire::buildIcmpEchoRequestBody(/*id=*/0, /*seq=*/1, data_body, data_len);
    return backend_->sendIcmpEcho(ifname, dest_be, msg.data(), msg.size());
}

std::uint8_t ProtocolServer::echoRequestV6(const std::uint8_t *dat, std::size_t dat_len) {
    // PRS_TPSP §6.10 ECHO_REQUEST (ICMPv6): ifName(text) + destAddr(ipxaddr n=16)
    // + data(vint8) — the same shape as the IPv4 echo above with a 16-byte address.
    std::size_t off = 0;
    std::string ifname;
    if (!readText(dat, dat_len, off, ifname)) {
        return kRidEInv;
    }
    const std::uint8_t *addr_body = nullptr;
    std::uint16_t addr_len = 0;
    if (!readVint8(dat, dat_len, off, addr_body, addr_len) || addr_len != 16) {
        return kRidEInv;  // IPv6 ipxaddr only — the IPv4 echo is kGidIcmp
    }
    const std::uint8_t *data_body = nullptr;
    std::uint16_t data_len = 0;
    if (!readVint8(dat, dat_len, off, data_body, data_len)) {
        return kRidEInv;
    }

    // The IPPROTO_ICMPV6 socket completes the checksum (it spans the IPv6
    // pseudo-header), so the wire builder leaves it zero — see
    // buildIcmpv6EchoRequestBody. The backend only sends it and resolves ifName.
    const std::vector<std::uint8_t> msg =
        tc8::wire::buildIcmpv6EchoRequestBody(/*id=*/0, /*seq=*/1, data_body, data_len);
    return backend_->sendIcmpv6Echo(ifname, addr_body, msg.data(), msg.size());
}

std::uint8_t ProtocolServer::setInterface(const std::uint8_t *dat, std::size_t dat_len, bool up) {
    // PRS_TPSP §6.10 INTERFACE_UP / INTERFACE_DOWN (ETH): the sole request
    // parameter is ifName(text). The administrative link-state change is the
    // backend's (an unknown interface is E_IIF); this primitive does not affect
    // persistent configuration, matching the spec.
    std::size_t off = 0;
    std::string ifname;
    if (!readText(dat, dat_len, off, ifname)) {
        return kRidEInv;
    }
    return backend_->setInterfaceUp(ifname, up);
}

std::uint8_t ProtocolServer::staticAddress(const std::uint8_t *dat, std::size_t dat_len) {
    // PRS_TPSP §6.10 STATIC_ADDRESS (IP): ifName(text) + addr(ipxaddr n=4) +
    // netMask(uint8 CIDR). The address assignment is the backend's (an unknown
    // interface is E_IIF); IPv6 is a separate GID (0x06), so only the n=4 ipxaddr
    // is accepted here.
    std::size_t off = 0;
    std::string ifname;
    if (!readText(dat, dat_len, off, ifname)) {
        return kRidEInv;
    }
    const std::uint8_t *addr_body = nullptr;
    std::uint16_t addr_len = 0;
    if (!readVint8(dat, dat_len, off, addr_body, addr_len) || addr_len != 4) {
        return kRidEInv;  // IPv4 ipxaddr only
    }
    std::uint32_t addr_be = 0;
    std::memcpy(&addr_be, addr_body, 4);
    if (off >= dat_len) {
        return kRidEInv;  // missing netMask(uint8)
    }
    const std::uint8_t cidr = dat[off];
    return backend_->setStaticAddressV4(ifname, addr_be, cidr);
}

std::uint8_t ProtocolServer::staticRoute(const std::uint8_t *dat, std::size_t dat_len) {
    // PRS_TPSP §6.10 STATIC_ROUTE (IP): ifName(text) + subNet(ipxaddr n=4) +
    // netMask(uint8 CIDR) + gateway(ipxaddr n=4). Non-persistent; the route
    // install is the backend's (unknown interface => E_IIF, no routing table =>
    // E_NOK). IPv6 is a separate GID (0x06), so only n=4 ipxaddrs are accepted.
    std::size_t off = 0;
    std::string ifname;
    if (!readText(dat, dat_len, off, ifname)) {
        return kRidEInv;
    }
    const std::uint8_t *subnet_body = nullptr;
    std::uint16_t subnet_len = 0;
    if (!readVint8(dat, dat_len, off, subnet_body, subnet_len) || subnet_len != 4) {
        return kRidEInv;
    }
    std::uint32_t subnet_be = 0;
    std::memcpy(&subnet_be, subnet_body, 4);
    if (off >= dat_len) {
        return kRidEInv;  // missing netMask(uint8)
    }
    const std::uint8_t cidr = dat[off];
    off += 1;
    const std::uint8_t *gw_body = nullptr;
    std::uint16_t gw_len = 0;
    if (!readVint8(dat, dat_len, off, gw_body, gw_len) || gw_len != 4) {
        return kRidEInv;
    }
    std::uint32_t gateway_be = 0;
    std::memcpy(&gateway_be, gw_body, 4);
    return backend_->setStaticRouteV4(ifname, subnet_be, cidr, gateway_be);
}

std::uint8_t ProtocolServer::connectTcp(const std::uint8_t *dat, std::size_t dat_len) {
    // PRS_TPSP §6.10 CONNECT (TCP): socketId + destPort + destAddr(ipxaddr).
    if (dat_len < 2 + 2) {
        return kRidEInv;
    }
    const std::uint16_t socket_id = readU16(dat);
    const std::uint16_t dest_port = readU16(dat + 2);
    std::size_t off = 4;
    const std::uint8_t *addr_body = nullptr;
    std::uint16_t addr_len = 0;
    if (!readVint8(dat, dat_len, off, addr_body, addr_len) || addr_len != 4) {
        return kRidEInv;
    }

    const auto fd = lookupSocket(socket_id);
    if (!fd) {
        return kRidEIsd;  // invalid socket id
    }

    const Endpoint dst = endpointFromWire(addr_body, dest_port);
    // Bounded so an absent peer times out instead of freezing the dispatch loop.
    // The backend records whatever it needs (e.g. the 4-tuple) for a later abort.
    if (!backend_->connectBoundedV4(*fd, dst, /*timeout_ms=*/1000)) {
        return kRidENok;  // connection refused / unreachable / timed out
    }
    return kRidEOk;
}

std::uint8_t ProtocolServer::sendDataTcp(const std::uint8_t *dat, std::size_t dat_len) {
    // PRS_TPSP §6.10 SEND_DATA (TCP): socketId + totalLen + flags(u8) + data(vint8).
    if (dat_len < 2 + 2 + 1) {
        return kRidEInv;
    }
    const std::uint16_t socket_id = readU16(dat);
    const std::uint16_t total_len = readU16(dat + 2);
    std::size_t off = 5;  // skip flags(u8) at dat[4]
    const std::uint8_t *data_body = nullptr;
    std::uint16_t data_len = 0;
    if (!readVint8(dat, dat_len, off, data_body, data_len)) {
        return kRidEInv;
    }

    const auto fd = lookupSocket(socket_id);
    if (!fd) {
        return kRidEIsd;  // invalid socket id
    }

    const std::vector<std::uint8_t> payload =
        buildRepeatedPayload(data_body, data_len, total_len);
    const int sent = backend_->send(*fd, payload.data(), payload.size());
    return sent < 0 ? kRidENok : kRidEOk;
}

std::uint8_t ProtocolServer::listenAndAcceptTcp(const std::uint8_t *dat, std::size_t dat_len,
                                                std::uint16_t service_id, const Endpoint &peer) {
    // PRS_TPSP §6.10 LISTEN_AND_ACCEPT (TCP): listenSocketId + maxCon.
    if (dat_len < 2 + 2) {
        return kRidEInv;
    }
    const std::uint16_t listen_socket_id = readU16(dat);
    std::uint16_t max_con = readU16(dat + 2);
    if (max_con == 0) {
        max_con = 1;  // a zero backlog cannot accept anything; treat as one
    }

    const auto fd = lookupSocket(listen_socket_id);
    if (!fd) {
        return kRidEIsd;  // invalid socket id
    }
    if (!backend_->listen(*fd, max_con)) {
        return kRidENok;  // not a bound stream socket / listen failed
    }

    // Accept asynchronously: E_OK now, each accepted connection reported later as
    // an Event. The worker's lifetime is owned by the listen socket (stopWorker
    // on close), so re-arm the slot before installing.
    stopWorker(listen_socket_id);
    auto stop = std::make_shared<std::atomic<bool>>(false);
    std::thread t(&ProtocolServer::acceptLoop, this, *fd, service_id, listen_socket_id, max_con,
                  peer, stop);
    {
        std::lock_guard<std::mutex> lk(workers_mu_);
        auto &w = event_workers_[listen_socket_id];  // fresh: stopWorker erased any prior
        w.stop = std::move(stop);
        w.thread = std::move(t);
    }
    return kRidEOk;
}

void ProtocolServer::runEventWorkerLoop(int fd, const std::shared_ptr<std::atomic<bool>> &stop,
                                        const std::function<bool()> &again,
                                        const std::function<bool()> &on_readable) {
    // PRS_TPSP §6.2 async-SP worker skeleton, shared by acceptLoop /
    // receiveLoopTcp / receiveLoopUdp. The fd is non-blocking only for the span
    // of the loop (restored on exit) so the wait never blocks past the wake
    // window — that bounds how fast the stop / reset flags are noticed.
    backend_->setNonBlocking(fd, true);
    while (!stop_requested_ && !reset_events_ && !stop->load() && again()) {
        const int sr = backend_->waitReadable(fd, kEventThreadWakeUs);
        if (sr == 0) {
            continue;  // timeout / signal — re-check the stop / reset flags
        }
        if (sr < 0) {
            break;  // fd closed under us / fatal error — stop
        }
        if (!on_readable()) {
            break;  // the body signalled end-of-stream (e.g. a TCP peer close)
        }
    }
    backend_->setNonBlocking(fd, false);  // restore (the fd lives on in the table)
}

void ProtocolServer::acceptLoop(int listen_fd, std::uint16_t service_id,
                                std::uint16_t listen_socket_id, std::uint16_t max_con,
                                Endpoint peer, std::shared_ptr<std::atomic<bool>> stop) {
    std::uint16_t accepted = 0;
    runEventWorkerLoop(
        listen_fd, stop, [&] { return accepted < max_con; },
        [&] {
            Endpoint client;
            const int conn = backend_->accept(listen_fd, client);
            if (conn < 0) {
                return true;  // spurious wakeup — keep waiting (not end-of-stream)
            }
            const std::uint16_t new_socket_id = registerSocket(conn);
            ++accepted;

            // PRS_TPSP §6.10 LISTEN_AND_ACCEPT Event: listenSocketId + newSocketId
            // + clientPort + clientAddr(ipxaddr).
            std::vector<std::uint8_t> ev_dat;
            appendU16(ev_dat, listen_socket_id);
            appendU16(ev_dat, new_socket_id);
            appendU16(ev_dat, client.port);
            appendIpv4Addr(ev_dat, client.addr_be);
            emitEvent(service_id, kGidTcp, kPidListenAndAccept, ev_dat, peer);
            return true;
        });
}

std::uint8_t ProtocolServer::closeSocket(const std::uint8_t *dat, std::size_t dat_len) {
    // PRS_TPSP §6.10 CLOSE_SOCKET: socketId + optional abort(bool, TCP). abort=true
    // RSTs immediately; the byte is absent (or 0) for a graceful close and for UDP.
    if (dat_len < 2) {
        return kRidEInv;
    }
    const std::uint16_t socket_id = readU16(dat);
    const bool abort = (dat_len >= 3) && (dat[2] != 0);
    return eraseSocket(socket_id, abort) ? kRidEOk : kRidEIsd;
}

std::uint8_t ProtocolServer::shutdownSocket(const std::uint8_t *dat, std::size_t dat_len) {
    // PRS_TPSP §6.10 SHUTDOWN: socketId + typeId(uint8). 0x00 reception, 0x01
    // transmission, 0x02 both. The fd lives on (half-close).
    if (dat_len < 2 + 1) {
        return kRidEInv;
    }
    const std::uint16_t socket_id = readU16(dat);
    int how = 0;
    switch (dat[2]) {
        case kShutdownRd:
            how = 0;
            break;
        case kShutdownWr:
            how = 1;
            break;
        case kShutdownRdWr:
            how = 2;
            break;
        default:
            return kRidEInv;  // unknown typeId
    }
    const auto fd = lookupSocket(socket_id);
    if (!fd) {
        return kRidEIsd;  // invalid socket id
    }
    return backend_->shutdown(*fd, how) ? kRidEOk : kRidENok;
}

std::uint8_t ProtocolServer::configureSocket(const std::uint8_t *dat, std::size_t dat_len) {
    // PRS_TPSP §6.10.10 CONFIGURE_SOCKET: socketId + paramId + paramVal(vint8).
    // The core does the generic parse + socket lookup; the backend owns the
    // paramId -> action mapping (its supported set is platform-specific).
    if (dat_len < 2 + 2) {
        return kRidEInv;
    }
    const std::uint16_t socket_id = readU16(dat);
    const std::uint16_t param_id = readU16(dat + 2);
    std::size_t off = 4;
    const std::uint8_t *val = nullptr;
    std::uint16_t val_len = 0;
    if (!readVint8(dat, dat_len, off, val, val_len)) {
        return kRidEInv;
    }
    const auto fd = lookupSocket(socket_id);
    if (!fd) {
        return kRidEIsd;  // PRS_TPSP §6.8 invalid socket descriptor
    }
    return backend_->configureOption(*fd, param_id, val, val_len);
}

std::uint8_t ProtocolServer::receiveAndForward(const std::uint8_t *dat, std::size_t dat_len,
                                               std::uint16_t service_id, const Endpoint &peer,
                                               std::vector<std::uint8_t> &resp_dat, bool udp) {
    // PRS_TPSP §6.10 RECEIVE_AND_FORWARD (UDP/TCP): socketId + maxFwd + maxLen.
    // Response: dropCnt(u16). `udp` selects the forward loop.
    if (dat_len < 2 + 2 + 2) {
        return kRidEInv;
    }
    const std::uint16_t socket_id = readU16(dat);
    const std::uint16_t max_fwd = readU16(dat + 2);
    const std::uint16_t max_len = readU16(dat + 4);

    const auto fd = lookupSocket(socket_id);
    if (!fd) {
        return kRidEIsd;  // invalid socket id
    }

    // PRS_TPSP §6.10 inactive-phase drain: consume the bytes queued before this
    // call and report the count as dropCnt. Non-blocking so an empty queue does
    // not stall the dispatch loop.
    backend_->setNonBlocking(*fd, true);
    std::uint32_t dropped = 0;
    std::uint8_t drain[2048];
    for (;;) {
        const int n = backend_->recv(*fd, drain, sizeof(drain));
        if (n <= 0) {
            break;
        }
        dropped += static_cast<std::uint32_t>(n);
    }
    backend_->setNonBlocking(*fd, false);
    // dropCnt is a u16 field; saturate rather than wrap.
    appendU16(resp_dat, static_cast<std::uint16_t>(dropped > 0xFFFF ? 0xFFFF : dropped));

    // Active phase: forward subsequently-received data as Events on a worker
    // thread — same async lifecycle as the accept worker. Re-arm the slot first.
    stopWorker(socket_id);
    auto stop = std::make_shared<std::atomic<bool>>(false);
    std::thread t = udp ? std::thread(&ProtocolServer::receiveLoopUdp, this, *fd, service_id,
                                      max_fwd, max_len, peer, stop)
                        : std::thread(&ProtocolServer::receiveLoopTcp, this, *fd, service_id,
                                      max_fwd, max_len, peer, stop);
    {
        std::lock_guard<std::mutex> lk(workers_mu_);
        auto &w = event_workers_[socket_id];  // fresh: stopWorker erased any prior
        w.stop = std::move(stop);
        w.thread = std::move(t);
    }
    return kRidEOk;
}

void ProtocolServer::receiveLoopTcp(int conn_fd, std::uint16_t service_id, std::uint16_t max_fwd,
                                    std::uint16_t max_len, Endpoint peer,
                                    std::shared_ptr<std::atomic<bool>> stop) {
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
            const int n = backend_->recv(conn_fd, buf, want);
            if (n <= 0) {
                return n != 0;  // n==0 peer close -> stop; n<0 spurious -> keep waiting
            }
            consumed += static_cast<std::uint32_t>(n);
            const std::uint16_t full_len = static_cast<std::uint16_t>(n);
            const std::uint16_t fwd_len =
                static_cast<std::uint16_t>(n < static_cast<int>(max_fwd) ? n : max_fwd);

            // PRS_TPSP §6.10 RECEIVE_AND_FORWARD Event (TCP): fullLen + payload(vint8).
            std::vector<std::uint8_t> ev_dat;
            appendU16(ev_dat, full_len);
            appendVint8(ev_dat, buf, fwd_len);
            emitEvent(service_id, kGidTcp, kPidReceiveAndForward, ev_dat, peer);
            return true;
        });
}

void ProtocolServer::receiveLoopUdp(int sock_fd, std::uint16_t service_id, std::uint16_t max_fwd,
                                    std::uint16_t max_len, Endpoint peer,
                                    std::shared_ptr<std::atomic<bool>> stop) {
    const bool limitless = (max_len == 0xFFFF);  // PRS_TPSP §6.10 maxLen 0xFFFF
    std::uint32_t consumed = 0;
    runEventWorkerLoop(
        sock_fd, stop, [&] { return limitless || consumed < max_len; },
        [&]() -> bool {
            std::uint8_t buf[2048];
            Endpoint src;
            // recvFromV4 reports the true datagram length even when it overflows
            // `buf`, so fullLen is exact while the buffer holds at most
            // sizeof(buf) bytes to forward from.
            const int n = backend_->recvFromV4(sock_fd, buf, sizeof(buf), src);
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
            // srcAddr(ipxaddr) + payload(vint8).
            std::vector<std::uint8_t> ev_dat;
            appendU16(ev_dat, full_len);
            appendU16(ev_dat, src.port);
            appendIpv4Addr(ev_dat, src.addr_be);
            appendVint8(ev_dat, buf, fwd_len);
            emitEvent(service_id, kGidUdp, kPidReceiveAndForward, ev_dat, peer);
            return true;
        });
}

void ProtocolServer::emitEvent(std::uint16_t service_id, std::uint8_t gid, std::uint8_t pid,
                               const std::vector<std::uint8_t> &dat, const Endpoint &peer) {
    // PRS_TPSP §6.2 Event: EVB-set method id for group `gid` + TID 0x02. The
    // shared listener egress is serialised by send_mu_ (see its declaration).
    Header ev;
    ev.service_id = service_id;
    ev.method_id = methodId(gid, pid, /*event=*/true);
    ev.tid = kTidEvent;
    ev.rid = kRidEOk;
    const auto out = buildMessage(ev, dat.data(), dat.size());
    std::lock_guard<std::mutex> lk(send_mu_);
    backend_->sendToV4(fd_, out.data(), out.size(), peer);
}

std::uint16_t ProtocolServer::registerSocket(int fd) {
    std::lock_guard<std::mutex> lk(sockets_mu_);
    const std::uint16_t id = next_socket_id_++;
    sockets_[id] = fd;
    return id;
}

std::optional<int> ProtocolServer::lookupSocket(std::uint16_t id) const {
    std::lock_guard<std::mutex> lk(sockets_mu_);
    const auto it = sockets_.find(id);
    if (it == sockets_.end()) {
        return std::nullopt;
    }
    return it->second;
}

bool ProtocolServer::eraseSocket(std::uint16_t id, bool abort) {
    // Stop + join this socket's async-event worker (if any) BEFORE closing the
    // fd, so the worker can never act on a closed (and possibly reused) fd. Done
    // outside sockets_mu_ (stopWorker takes only workers_mu_) so a worker blocked
    // in registerSocket cannot deadlock the join.
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
    if (abort) {
        backend_->closeWithAbort(fd);
    } else {
        backend_->closeFd(fd);
    }
    return true;
}

void ProtocolServer::closeAllSockets() {
    std::lock_guard<std::mutex> lk(sockets_mu_);
    for (const auto &kv : sockets_) {
        backend_->closeFd(kv.second);
    }
    sockets_.clear();
}

void ProtocolServer::stopWorker(std::uint16_t socket_id) {
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

void ProtocolServer::joinEventThreads() {
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

}  // namespace tc8::testability
