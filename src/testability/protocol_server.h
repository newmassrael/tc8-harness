#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "net/socket_backend.h"
#include "tc8/testability_protocol.h"

namespace tc8::testability {

// The shared socket seam lives in tc8::net (src/net/socket_backend.h); the
// testability core speaks its endpoint type, so import the name here.
using net::Endpoint;

// The testability-specific extension of the shared socket seam
// (tc8::net::SocketBackend): the operations whose result is a PRS_TPSP
// service-primitive outcome rather than a raw socket value — CONFIGURE_SOCKET
// option application, the ICMP / ICMPv6 ECHO_REQUEST emit, and the ETH
// INTERFACE_UP / INTERFACE_DOWN link-state change. Kept off the generic net
// seam so that layer stays free of testability protocol vocabulary; the Upper
// Tester server, which has none of these primitives, depends on the generic
// base alone and reuses the very same adapters.
class SocketBackend : public net::SocketBackend {
public:
    // CONFIGURE_SOCKET parameter application -> testability result id
    // (E_OK / E_NOK / E_NTF / E_INV). The supported parameter set is
    // backend-specific (a stack lacking an option answers E_NOK).
    virtual std::uint8_t configureOption(int fd, std::uint16_t param_id,
                                         const std::uint8_t *val, std::uint16_t len) = 0;

    // ICMP ECHO_REQUEST: emit the pre-built Echo body (framed by the core via
    // the shared tc8::wire builder) to `dst_be` through `ifname` (empty / "0"
    // = any) -> result id (E_OK / E_IIF on an unknown interface / E_NOK).
    virtual std::uint8_t sendIcmpEcho(const std::string &ifname, std::uint32_t dst_be,
                                      const std::uint8_t *body, std::size_t len) = 0;

    // ICMPv6 ECHO_REQUEST: the IPv6 sibling of sendIcmpEcho — `dst16` is the
    // 16-byte destination in wire order. A stack built without IPv6 answers
    // E_NOK (surfaced, not silently dropped).
    virtual std::uint8_t sendIcmpv6Echo(const std::string &ifname, const std::uint8_t *dst16,
                                        const std::uint8_t *body, std::size_t len) = 0;

    // ETH INTERFACE_UP / INTERFACE_DOWN (PRS_TPSP §6.10): bring the named
    // interface administratively up (`up` = true) or down (`up` = false) ->
    // result id (E_OK / E_IIF on an unknown interface / E_NOK where the change
    // is not permitted, e.g. lacking the privilege to alter link state).
    virtual std::uint8_t setInterfaceUp(const std::string &ifname, bool up) = 0;
};

// AUTOSAR Testability Protocol endpoint (PRS_TPSP §6, AUTOSAR TC 1.2.0), the
// platform-agnostic core. It owns the codec dispatch, every service-primitive's
// request parsing and response framing, the socket table, and the async-event
// worker lifecycle — all written once — and delegates each network operation to
// an injected SocketBackend. A Linux deployment pairs it with a POSIX backend,
// the lwIP fixture with an lwIP backend; the wire framing is the shared SSOT in
// include/tc8/testability_protocol.h so both decode identically.
//
// Served standard groups (PRS_TPSP §6.10): GENERAL (0x00), UDP (0x01),
// TCP (0x02), ICMP (0x03), ICMPv6 (0x04), ETH (0x0B). registerPrimitive() is the
// OEM extension/override seam (PRS_TPSP §6.6). RAII: start() spawns the listener
// thread; stop()/dtor joins it and closes any open sockets.
class ProtocolServer {
public:
    explicit ProtocolServer(std::unique_ptr<SocketBackend> backend);
    ~ProtocolServer();

    ProtocolServer(const ProtocolServer &) = delete;
    ProtocolServer &operator=(const ProtocolServer &) = delete;

    // Bind the UDP listener and start the server thread. false if the bind
    // fails (the endpoint is additive — a caller may keep serving other
    // channels). No-op-safe to call once.
    bool start(std::uint16_t port = testability::kDefaultPort);

    // Signal the thread to exit, join it, and close any open sockets. Idempotent.
    void stop();

    // A synchronous service-primitive handler (PRS_TPSP §6.6): reads the parsed
    // request, its DAT and the requesting peer, fills the Result ID and any
    // response DAT for the single Response. Runs on the server thread,
    // request/response only — it cannot emit async Events or touch the socket
    // table (a vendor group needing async behaviour manages its own resources).
    using SpHandler =
        std::function<void(const Header &req, const std::uint8_t *dat, std::size_t dat_len,
                           const Endpoint &peer, std::uint8_t &rid_out,
                           std::vector<std::uint8_t> &resp_dat)>;

    // Register an OEM handler for (gid, pid). Consulted BEFORE the built-in
    // groups, so it both EXTENDS the endpoint with a non-standard group and
    // OVERRIDES a standard primitive. Call before start(): the table is
    // read-only while the server thread runs.
    void registerPrimitive(std::uint8_t gid, std::uint8_t pid, SpHandler handler);

private:
    void serverLoop();
    void dispatch(const Header &req, const std::uint8_t *dat, std::size_t dat_len,
                  const Endpoint &peer, std::uint8_t &rid_out,
                  std::vector<std::uint8_t> &resp_dat);

    std::uint8_t createAndBind(const std::uint8_t *dat, std::size_t dat_len, bool tcp,
                               std::uint16_t &socket_id_out);
    void respondCreateAndBind(bool tcp, const std::uint8_t *dat, std::size_t dat_len,
                              std::uint8_t &rid_out, std::vector<std::uint8_t> &resp_dat);
    std::uint8_t sendDataUdp(const std::uint8_t *dat, std::size_t dat_len);
    std::uint8_t sendDataTcp(const std::uint8_t *dat, std::size_t dat_len);
    std::uint8_t connectTcp(const std::uint8_t *dat, std::size_t dat_len);
    std::uint8_t listenAndAcceptTcp(const std::uint8_t *dat, std::size_t dat_len,
                                    std::uint16_t service_id, const Endpoint &peer);
    std::uint8_t closeSocket(const std::uint8_t *dat, std::size_t dat_len);
    std::uint8_t shutdownSocket(const std::uint8_t *dat, std::size_t dat_len);
    std::uint8_t configureSocket(const std::uint8_t *dat, std::size_t dat_len);
    std::uint8_t receiveAndForward(const std::uint8_t *dat, std::size_t dat_len,
                                   std::uint16_t service_id, const Endpoint &peer,
                                   std::vector<std::uint8_t> &resp_dat, bool udp);
    std::uint8_t echoRequest(const std::uint8_t *dat, std::size_t dat_len);
    std::uint8_t echoRequestV6(const std::uint8_t *dat, std::size_t dat_len);
    std::uint8_t setInterface(const std::uint8_t *dat, std::size_t dat_len, bool up);

    void runEventWorkerLoop(int fd, const std::shared_ptr<std::atomic<bool>> &stop,
                            const std::function<bool()> &again,
                            const std::function<bool()> &on_readable);
    void acceptLoop(int listen_fd, std::uint16_t service_id, std::uint16_t listen_socket_id,
                    std::uint16_t max_con, Endpoint peer, std::shared_ptr<std::atomic<bool>> stop);
    void receiveLoopTcp(int conn_fd, std::uint16_t service_id, std::uint16_t max_fwd,
                        std::uint16_t max_len, Endpoint peer,
                        std::shared_ptr<std::atomic<bool>> stop);
    void receiveLoopUdp(int sock_fd, std::uint16_t service_id, std::uint16_t max_fwd,
                        std::uint16_t max_len, Endpoint peer,
                        std::shared_ptr<std::atomic<bool>> stop);
    void emitEvent(std::uint16_t service_id, std::uint8_t gid, std::uint8_t pid,
                   const std::vector<std::uint8_t> &dat, const Endpoint &peer);

    std::uint16_t registerSocket(int fd);
    std::optional<int> lookupSocket(std::uint16_t id) const;
    bool eraseSocket(std::uint16_t id, bool abort = false);
    void closeAllSockets();

    void joinEventThreads();
    void stopWorker(std::uint16_t socket_id);

    std::unique_ptr<SocketBackend> backend_;

    int fd_ = -1;
    std::thread thread_;
    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> reset_events_{false};

    // Serialises every egress on the shared listener socket (Response +
    // async Event). The Linux kernel would serialise sub-MTU sendto on its
    // own; lwIP gives no such cross-thread guarantee — holding it on both
    // is harmless and keeps the core uniform.
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

    std::map<std::uint16_t, SpHandler> oem_handlers_;
};

}  // namespace tc8::testability
