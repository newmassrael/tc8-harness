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

#include "tc8/testability_protocol.h"

namespace tc8::testability {

// A platform-neutral IPv4 endpoint (network byte order). The protocol core
// speaks this instead of sockaddr_in so it carries no OS socket headers — the
// SocketBackend translates to/from the platform's address type.
struct Endpoint {
    std::uint32_t addr_be = 0;
    std::uint16_t port = 0;
};

// The I/O seam (ports & adapters): every operation the testability protocol
// needs from the network stack, and nothing else. The protocol logic
// (parsing, dispatch, socket-table + worker bookkeeping) lives in
// ProtocolServer; only these primitives differ between platforms, so a Linux
// (POSIX syscalls) and an lwIP (socket API + core-API) adapter implement this
// and the core is written once. Socket descriptors are opaque `int` handles
// the core stores and hands back; only the backend interprets them.
class SocketBackend {
public:
    virtual ~SocketBackend() = default;

    // Socket creation — fd >= 0 on success, -1 on failure.
    virtual int createUdp() = 0;
    virtual int createTcp() = 0;

    // Listener / bind setup.
    virtual void setReuseAddr(int fd) = 0;
    virtual void setRecvTimeoutMs(int fd, int ms) = 0;
    // addr_be == 0 means "any address". true on success.
    virtual bool bindV4(int fd, std::uint32_t addr_be, std::uint16_t port) = 0;

    // Datagram I/O. recvFromV4: byte count, or < 0 on timeout/error (fills
    // `src` on success). sendToV4: byte count, or < 0 on failure.
    virtual int recvFromV4(int fd, void *buf, std::size_t len, Endpoint &src) = 0;
    virtual int sendToV4(int fd, const void *buf, std::size_t len, const Endpoint &dst) = 0;

    // Stream I/O. < 0 error, 0 peer close, else byte count.
    virtual int recv(int fd, void *buf, std::size_t len) = 0;
    virtual int send(int fd, const void *buf, std::size_t len) = 0;

    // Bounded active connect (non-blocking connect + wait up to timeout_ms,
    // fd left blocking on return). true on an established connection. The
    // backend captures whatever per-fd state a later abortive close needs.
    virtual bool connectBoundedV4(int fd, const Endpoint &dst, int timeout_ms) = 0;

    virtual bool listen(int fd, int backlog) = 0;
    // accept: new fd, or < 0 if none ready (fills `client` on success).
    virtual int accept(int fd, Endpoint &client) = 0;

    // how: 0 reception, 1 transmission, 2 both. true on success.
    virtual bool shutdown(int fd, int how) = 0;

    // Non-blocking toggle for the select-pump / drain loops.
    virtual void setNonBlocking(int fd, bool on) = 0;
    // < 0 error, 0 timeout, > 0 readable.
    virtual int waitReadable(int fd, int timeout_us) = 0;

    // Close (clears any per-fd backend state). closeWithAbort emits a RST.
    virtual void closeFd(int fd) = 0;
    virtual void closeWithAbort(int fd) = 0;

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
// TCP (0x02), ICMP (0x03). registerPrimitive() is the OEM extension/override
// seam (PRS_TPSP §6.6). RAII: start() spawns the listener thread; stop()/dtor
// joins it and closes any open sockets.
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
