#include "testability/protocol_server.h"

#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>

#include "wire/icmp_echo.h"

namespace tc8::testability {

namespace {

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

// Hosts one MiddlewareModule (PRS_TPSP §6.6 stateful extension): it is the
// MiddlewareContext the module sees. It holds no loop of its own — every callback
// and every timer/watch it schedules runs on the ProtocolServer's single shared
// Reactor (src/testability/reactor.h), so a module callback, the module's timers,
// and the control dispatch are all serialized run-to-completion on one thread and
// the module needs no internal locking. Because dispatch is already on that loop,
// a primitive is invoked directly (no cross-thread marshaling).
struct ProtocolServer::ModuleRuntime final : MiddlewareContext {
    ModuleRuntime(ProtocolServer *server, std::unique_ptr<MiddlewareModule> module)
        : server_(server), module_(std::move(module)), groups_(module_->groups()) {}

    const std::vector<std::uint8_t> &ownedGroups() const { return groups_; }

    // ── lifecycle (each runs on the reactor loop) ──

    void onStart() { module_->onStart(*this); }  // ready before serving
    void onStop() { module_->onStop(); }

    // Invoke a primitive directly: the caller (onControlReadable -> dispatch) is
    // already on the reactor loop, serialized with this module's timers, so the
    // synchronous request/response of PRS_TPSP §6.2 holds with no marshaling.
    void invokePrimitive(const Header &req, const std::uint8_t *dat, std::size_t dat_len,
                         const Endpoint &peer, std::uint8_t &rid_out,
                         std::vector<std::uint8_t> &resp_dat) {
        requester_ = peer;
        service_id_ = req.service_id;
        module_->onPrimitive(req, dat, dat_len, peer, rid_out, resp_dat);
    }

    void startTest() { module_->onStartTest(); }
    void endTest() { module_->onEndTest(); }

    // ── MiddlewareContext (invoked on the reactor loop by module callbacks) ──
    // Each scheduling method delegates to the shared reactor, which asserts it runs
    // on the loop thread (the "call on the module executor" precondition).

    net::SocketBackend &backend() override { return *server_->backend_; }

    TimerId scheduleEvery(std::chrono::milliseconds period, std::function<void()> fn) override {
        return server_->reactor_.armEvery(period, std::move(fn));
    }
    TimerId scheduleOnce(std::chrono::milliseconds delay, std::function<void()> fn) override {
        return server_->reactor_.armOnce(delay, std::move(fn));
    }
    void cancel(TimerId id) override { server_->reactor_.cancel(id); }
    WatchId watchReadable(int fd, std::function<void()> on_readable) override {
        return server_->reactor_.addWatch(fd, std::move(on_readable));
    }
    void unwatch(WatchId id) override { server_->reactor_.removeWatch(id); }
    void emitEvent(std::uint8_t gid, std::uint8_t pid,
                   const std::vector<std::uint8_t> &dat) override {
        // To the requester of the module's most recent primitive (PRS_TPSP §6.2);
        // an event-capable test system keeps one persistent control socket, so
        // that address stays valid across arm and fire.
        server_->emitEvent(service_id_, gid, pid, dat, requester_);
    }

private:
    ProtocolServer *server_;
    std::unique_ptr<MiddlewareModule> module_;
    std::vector<std::uint8_t> groups_;

    // The requester of the module's most recent primitive — emitEvent's target
    // (PRS_TPSP §6.2). Touched only on the reactor loop.
    Endpoint requester_{};
    std::uint16_t service_id_ = kDefaultServiceId;
};

ProtocolServer::ProtocolServer(std::unique_ptr<SocketBackend> backend)
    : backend_(std::move(backend)), reactor_(*backend_) {}

ProtocolServer::~ProtocolServer() {
    stop();
}

bool ProtocolServer::bindControl(std::uint16_t port) {
    fd_ = backend_->createUdp();
    if (fd_ < 0) {
        return false;
    }
    // DELIBERATELY no setReuseAddr() here, unlike the data-plane sockets in
    // createAndBind(). This is a unicast UDP socket, so SO_REUSEADDR buys nothing:
    // UDP has no TIME_WAIT for it to relax, and the port is free for rebinding the
    // moment closeFd() returns. What it DOES buy is a silent split brain — Linux
    // permits a duplicate bind of the same unicast UDP address:port when every
    // socket involved sets SO_REUSEADDR, and delivery then goes to the last binder.
    // A second endpoint on this port would silently steal the first's requests and
    // answer them, so the first serves nothing while both look healthy. Without the
    // option the duplicate bind fails with EADDRINUSE and start() returns false —
    // a second instance is a configuration error and must say so. (Data-plane
    // sockets keep it: there SO_REUSEADDR earns its place on TCP TIME_WAIT and on
    // multicast group binds.)
    if (!backend_->bindV4(fd_, /*addr_be=*/0, port)) {  // 0 == INADDR_ANY
        backend_->closeFd(fd_);
        fd_ = -1;
        return false;
    }
    return true;
}

#ifndef TC8_REACTOR_SINGLE_THREAD
bool ProtocolServer::start(std::uint16_t port) {
    if (!bindControl(port)) {
        return false;
    }
    reactor_.start();                          // the single loop, on its own thread
    reactor_.post([this] { setupOnLoop(); });  // control watch + module onStart, on the loop
    return true;
}
#endif  // !TC8_REACTOR_SINGLE_THREAD — a single-task deployment uses startInline()

bool ProtocolServer::startInline(std::uint16_t port) {
    if (!bindControl(port)) {
        return false;
    }
    reactor_.open();  // caller-driven: the pumping task owns the loop
    setupOnLoop();     // runs inline on the calling task
    return true;
}

bool ProtocolServer::runOnce(int timeout_ms) {
    return reactor_.runOnce(timeout_ms);
}

void ProtocolServer::run() {
    reactor_.run();
}

void ProtocolServer::stop() {
    // teardownOnLoop (module onStop + drop worker watches) runs on the loop; the
    // reactor's shutdown() marshals it to the owned thread and joins, or runs it on
    // this task for a startInline() server — so stop() is the same regardless.
    reactor_.shutdown([this] { teardownOnLoop(); });
    if (fd_ >= 0) {
        backend_->closeFd(fd_);
        fd_ = -1;
    }
    closeAllSockets();
}

void ProtocolServer::setupOnLoop() {
    // The control socket is level-triggered on the reactor; make it non-blocking so
    // a spurious wake never stalls the shared loop in recv.
    backend_->setNonBlocking(fd_, true);
    control_watch_ = reactor_.addWatch(fd_, [this] { onControlReadable(); });
    startModules();  // each module ready (onStart arms its timers/watches) before serving
}

void ProtocolServer::teardownOnLoop() {
    stopModules();       // onStop() while the control socket is still open
    stopAllWorkers();    // drop every async-event watch (their fds close in closeAllSockets)
}

void ProtocolServer::registerPrimitive(std::uint8_t gid, std::uint8_t pid, SpHandler handler) {
    oem_handlers_[methodId(gid, pid)] = std::move(handler);
}

void ProtocolServer::registerModule(std::unique_ptr<MiddlewareModule> module) {
    auto rt = std::make_unique<ModuleRuntime>(this, std::move(module));
    const auto &groups = rt->ownedGroups();
    // Fail fast on a registration clash rather than silently shadowing: GENERAL
    // is core-owned (its START_TEST/END_TEST drives the module broadcast), and a
    // GID already owned by another module would be a dispatch black hole. Validate
    // all GIDs before mutating the index so a throw leaves no partial state.
    for (const std::uint8_t gid : groups) {
        if (gid == kGidGeneral) {
            throw std::invalid_argument("registerModule: GID 0x00 (GENERAL) is core-owned");
        }
        if (gid_to_module_.count(gid) != 0) {
            throw std::invalid_argument("registerModule: GID already owned by a module");
        }
    }
    for (const std::uint8_t gid : groups) {
        gid_to_module_[gid] = rt.get();
    }
    modules_.push_back(std::move(rt));
}

void ProtocolServer::startModules() {
    for (const auto &rt : modules_) {
        rt->onStart();
    }
}

void ProtocolServer::stopModules() {
    for (const auto &rt : modules_) {
        rt->onStop();
    }
}

void ProtocolServer::broadcastStartTest() {
    for (const auto &rt : modules_) {
        rt->startTest();
    }
}

void ProtocolServer::broadcastEndTest() {
    for (const auto &rt : modules_) {
        rt->endTest();
    }
}

void ProtocolServer::onControlReadable() {
    // One datagram per readiness; the reactor is level-triggered, so a burst is
    // drained across successive polls. fd_ is non-blocking (setupOnLoop), so a
    // spurious wake just yields a short read and returns.
    std::uint8_t buf[2048];
    Endpoint peer;
    const int n = backend_->recvFromV4(fd_, buf, sizeof(buf), peer);
    // recvFromV4 reports the true datagram length (may exceed the buffer); cap to
    // what is actually in `buf` for parsing.
    if (n < static_cast<int>(kHeaderSize)) {
        return;  // would-block or runt
    }
    const std::size_t avail =
        (static_cast<std::size_t>(n) < sizeof(buf)) ? static_cast<std::size_t>(n) : sizeof(buf);
    const auto header = parseHeader(buf, avail);
    if (!header || header->tid != kTidRequest) {
        return;  // not a request addressed to us
    }

    const std::uint8_t *dat = buf + kHeaderSize;
    const std::size_t dat_len = avail - kHeaderSize;

    std::uint8_t rid = kRidEOk;
    std::vector<std::uint8_t> resp_dat;
    dispatch(*header, dat, dat_len, peer, rid, resp_dat);

    Header resp = *header;    // echo service_id + method_id
    resp.tid = kTidResponse;  // PRS_TPSP §6.2 Response
    resp.rid = rid;
    const auto out =
        buildMessage(resp, resp_dat.empty() ? nullptr : resp_dat.data(), resp_dat.size());
    backend_->sendToV4(fd_, out.data(), out.size(), peer);
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

    // PRS_TPSP §6.6 stateful extension: a module owns a whole GID. Marshaled to
    // the module's executor and awaited, after the registerPrimitive table and
    // before the built-in groups.
    if (const auto mit = gid_to_module_.find(gid); mit != gid_to_module_.end()) {
        mit->second->invokePrimitive(req, dat, dat_len, peer, rid_out, resp_dat);
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
                broadcastStartTest();  // PRS_TPSP §6.10.1 trace boundary -> modules
                rid_out = kRidEOk;
                return;
            case kPidEndTest:
                stopAllWorkers();    // drop every async-event watch (on the loop)
                closeAllSockets();
                broadcastEndTest();  // modules return to their inactive state
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

    if (gid == kGidIpv6) {
        switch (pid) {
            case kPidStaticAddress:
                rid_out = staticAddressV6(dat, dat_len);
                return;
            case kPidStaticRoute:
                rid_out = staticRouteV6(dat, dat_len);
                return;
            default:
                rid_out = kRidENtf;  // IPv6 group defines only STATIC_ADDRESS/ROUTE
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

std::uint8_t ProtocolServer::staticAddressV6(const std::uint8_t *dat, std::size_t dat_len) {
    // PRS_TPSP §6.10 STATIC_ADDRESS (IPv6): ifName(text) + addr(ipxaddr n=16) +
    // netMask(uint8 prefix length). The mirror of staticAddress with a 16-byte
    // address; IPv4 is the separate GID (0x05), so only the n=16 ipxaddr is accepted.
    std::size_t off = 0;
    std::string ifname;
    if (!readText(dat, dat_len, off, ifname)) {
        return kRidEInv;
    }
    const std::uint8_t *addr_body = nullptr;
    std::uint16_t addr_len = 0;
    if (!readVint8(dat, dat_len, off, addr_body, addr_len) || addr_len != 16) {
        return kRidEInv;  // IPv6 ipxaddr only
    }
    if (off >= dat_len) {
        return kRidEInv;  // missing netMask(uint8)
    }
    const std::uint8_t prefix = dat[off];
    return backend_->setStaticAddressV6(ifname, addr_body, prefix);
}

std::uint8_t ProtocolServer::staticRouteV6(const std::uint8_t *dat, std::size_t dat_len) {
    // PRS_TPSP §6.10 STATIC_ROUTE (IPv6): ifName(text) + subNet(ipxaddr n=16) +
    // netMask(uint8 prefix) + gateway(ipxaddr n=16). The mirror of staticRoute with
    // 16-byte addresses; IPv4 is the separate GID (0x05), so only n=16 ipxaddrs are
    // accepted. Non-persistent; the route install is the backend's (unknown
    // interface => E_IIF, no IPv6 routing table => E_NOK).
    std::size_t off = 0;
    std::string ifname;
    if (!readText(dat, dat_len, off, ifname)) {
        return kRidEInv;
    }
    const std::uint8_t *subnet_body = nullptr;
    std::uint16_t subnet_len = 0;
    if (!readVint8(dat, dat_len, off, subnet_body, subnet_len) || subnet_len != 16) {
        return kRidEInv;
    }
    if (off >= dat_len) {
        return kRidEInv;  // missing netMask(uint8)
    }
    const std::uint8_t prefix = dat[off];
    off += 1;
    const std::uint8_t *gw_body = nullptr;
    std::uint16_t gw_len = 0;
    if (!readVint8(dat, dat_len, off, gw_body, gw_len) || gw_len != 16) {
        return kRidEInv;
    }
    return backend_->setStaticRouteV6(ifname, subnet_body, prefix, gw_body);
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
    // an Event. The worker is a reactor watch on the listen socket (non-blocking so
    // accept never stalls the shared loop); its lifetime is owned by the listen
    // socket (stopWorker on close), so re-arm the slot before installing.
    stopWorker(listen_socket_id);
    backend_->setNonBlocking(*fd, true);
    EventWatch w;
    w.kind = EventWatch::kAccept;
    w.fd = *fd;
    w.service_id = service_id;
    w.peer = peer;
    w.listen_socket_id = listen_socket_id;
    w.max_con = max_con;
    armEventWatch(listen_socket_id, w);
    return kRidEOk;
}

void ProtocolServer::armEventWatch(std::uint16_t socket_id, EventWatch w) {
    // Install the watch, then record it under its socket_id so stopWorker /
    // stopAllWorkers can remove it. The handler re-looks-up the record each fire, so
    // its per-fire state (accepted / consumed) lives in event_watches_, not the
    // lambda (the reactor copies the stored std::function before invoking it).
    const WatchId id = reactor_.addWatch(w.fd, [this, socket_id] { onWorkerReadable(socket_id); });
    w.id = id;
    event_watches_[socket_id] = w;  // fresh: stopWorker erased any prior
}

void ProtocolServer::onWorkerReadable(std::uint16_t socket_id) {
    const auto it = event_watches_.find(socket_id);
    if (it == event_watches_.end()) {
        return;  // already stopped (a prior handler this round may have removed it)
    }
    EventWatch &w = it->second;
    bool keep = true;
    switch (w.kind) {
        case EventWatch::kAccept:
            keep = acceptOne(w);
            break;
        case EventWatch::kRecvTcp:
            keep = recvForwardTcpOne(w);
            break;
        case EventWatch::kRecvUdp:
            keep = recvForwardUdpOne(w);
            break;
    }
    if (!keep) {
        reactor_.removeWatch(w.id);         // read w.id before erasing the record
        event_watches_.erase(socket_id);    // do not touch w after this
    }
}

bool ProtocolServer::acceptOne(EventWatch &w) {
    if (w.accepted >= w.max_con) {
        return false;  // bound reached (the acceptLoop again() precheck)
    }
    Endpoint client;
    const int conn = backend_->accept(w.fd, client);
    if (conn < 0) {
        return true;  // spurious readiness — keep watching
    }
    const std::uint16_t new_socket_id = registerSocket(conn);
    ++w.accepted;

    // PRS_TPSP §6.10 LISTEN_AND_ACCEPT Event: listenSocketId + newSocketId +
    // clientPort + clientAddr(ipxaddr).
    std::vector<std::uint8_t> ev_dat;
    appendU16(ev_dat, w.listen_socket_id);
    appendU16(ev_dat, new_socket_id);
    appendU16(ev_dat, client.port);
    appendIpv4Addr(ev_dat, client.addr_be);
    emitEvent(w.service_id, kGidTcp, kPidListenAndAccept, ev_dat, w.peer);
    return w.accepted < w.max_con;  // stop once the bound is reached
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

    // Active phase: forward subsequently-received data as Events on a reactor watch
    // — same async lifecycle as the accept worker. Non-blocking so recv in the
    // handler never stalls the shared loop. Re-arm the slot first.
    stopWorker(socket_id);
    backend_->setNonBlocking(*fd, true);
    EventWatch w;
    w.kind = udp ? EventWatch::kRecvUdp : EventWatch::kRecvTcp;
    w.fd = *fd;
    w.service_id = service_id;
    w.peer = peer;
    w.max_fwd = max_fwd;
    w.max_len = max_len;
    w.limitless = (max_len == 0xFFFF);  // PRS_TPSP §6.10 maxLen 0xFFFF
    armEventWatch(socket_id, w);
    return kRidEOk;
}

bool ProtocolServer::recvForwardTcpOne(EventWatch &w) {
    if (!w.limitless && w.consumed >= w.max_len) {
        return false;  // total-forward bound reached (the receiveLoop again() precheck)
    }
    std::uint8_t buf[2048];
    std::size_t want = sizeof(buf);
    if (!w.limitless) {
        const std::uint32_t remaining = w.max_len - w.consumed;
        if (remaining < want) {
            want = remaining;
        }
    }
    const int n = backend_->recv(w.fd, buf, want);
    if (n <= 0) {
        return n != 0;  // n==0 peer close -> stop; n<0 spurious -> keep watching
    }
    w.consumed += static_cast<std::uint32_t>(n);
    const std::uint16_t full_len = static_cast<std::uint16_t>(n);
    const std::uint16_t fwd_len =
        static_cast<std::uint16_t>(n < static_cast<int>(w.max_fwd) ? n : w.max_fwd);

    // PRS_TPSP §6.10 RECEIVE_AND_FORWARD Event (TCP): fullLen + payload(vint8).
    std::vector<std::uint8_t> ev_dat;
    appendU16(ev_dat, full_len);
    appendVint8(ev_dat, buf, fwd_len);
    emitEvent(w.service_id, kGidTcp, kPidReceiveAndForward, ev_dat, w.peer);
    return w.limitless || w.consumed < w.max_len;
}

bool ProtocolServer::recvForwardUdpOne(EventWatch &w) {
    if (!w.limitless && w.consumed >= w.max_len) {
        return false;  // total-forward bound reached
    }
    std::uint8_t buf[2048];
    Endpoint src;
    // recvFromV4 reports the true datagram length even when it overflows `buf`, so
    // fullLen is exact while the buffer holds at most sizeof(buf) bytes to forward.
    const int n = backend_->recvFromV4(w.fd, buf, sizeof(buf), src);
    if (n < 0) {
        return true;  // spurious readiness — keep watching (UDP has no close)
    }
    // A zero-length UDP datagram is a valid event (fullLen 0), NOT a peer close —
    // the key behavioural split from the TCP body.
    const std::size_t in_buf = (static_cast<std::size_t>(n) < sizeof(buf))
                                   ? static_cast<std::size_t>(n)
                                   : sizeof(buf);
    w.consumed += static_cast<std::uint32_t>(n);
    const std::uint16_t full_len = static_cast<std::uint16_t>(n > 0xFFFF ? 0xFFFF : n);
    const std::uint16_t fwd_len =
        static_cast<std::uint16_t>(in_buf < w.max_fwd ? in_buf : w.max_fwd);

    // PRS_TPSP §6.10 RECEIVE_AND_FORWARD Event (UDP): fullLen + srcPort +
    // srcAddr(ipxaddr) + payload(vint8).
    std::vector<std::uint8_t> ev_dat;
    appendU16(ev_dat, full_len);
    appendU16(ev_dat, src.port);
    appendIpv4Addr(ev_dat, src.addr_be);
    appendVint8(ev_dat, buf, fwd_len);
    emitEvent(w.service_id, kGidUdp, kPidReceiveAndForward, ev_dat, w.peer);
    return w.limitless || w.consumed < w.max_len;
}

void ProtocolServer::emitEvent(std::uint16_t service_id, std::uint8_t gid, std::uint8_t pid,
                               const std::vector<std::uint8_t> &dat, const Endpoint &peer) {
    // PRS_TPSP §6.2 Event: EVB-set method id for group `gid` + TID 0x02. Emitted on
    // the reactor loop (a module callback or worker handler), the same thread as the
    // control responses, so the shared egress needs no lock.
    Header ev;
    ev.service_id = service_id;
    ev.method_id = methodId(gid, pid, /*event=*/true);
    ev.tid = kTidEvent;
    ev.rid = kRidEOk;
    const auto out = buildMessage(ev, dat.data(), dat.size());
    backend_->sendToV4(fd_, out.data(), out.size(), peer);
}

std::uint16_t ProtocolServer::registerSocket(int fd) {
    const std::uint16_t id = next_socket_id_++;
    sockets_[id] = fd;
    return id;
}

std::optional<int> ProtocolServer::lookupSocket(std::uint16_t id) const {
    const auto it = sockets_.find(id);
    if (it == sockets_.end()) {
        return std::nullopt;
    }
    return it->second;
}

bool ProtocolServer::eraseSocket(std::uint16_t id, bool abort) {
    // Remove this socket's async-event watch (if any) BEFORE closing the fd, so the
    // watch can never fire on a closed (and possibly reused) fd. All on the loop.
    stopWorker(id);

    const auto it = sockets_.find(id);
    if (it == sockets_.end()) {
        return false;
    }
    const int fd = it->second;
    sockets_.erase(it);
    if (abort) {
        backend_->closeWithAbort(fd);
    } else {
        backend_->closeFd(fd);
    }
    return true;
}

void ProtocolServer::closeAllSockets() {
    for (const auto &kv : sockets_) {
        backend_->closeFd(kv.second);
    }
    sockets_.clear();
}

void ProtocolServer::stopWorker(std::uint16_t socket_id) {
    const auto it = event_watches_.find(socket_id);
    if (it == event_watches_.end()) {
        return;  // no worker on this socket
    }
    reactor_.removeWatch(it->second.id);
    event_watches_.erase(it);
}

void ProtocolServer::stopAllWorkers() {
    for (auto &kv : event_watches_) {
        reactor_.removeWatch(kv.second.id);
    }
    event_watches_.clear();
}

}  // namespace tc8::testability
