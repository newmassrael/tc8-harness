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

#include "testability/middleware.h"
#include "testability/socket_backend.h"
#include "tc8/testability_protocol.h"

namespace tc8::testability {

// The SocketBackend port (the interface adapters implement) lives in its own
// header, testability/socket_backend.h, included above — this header is the
// application that consumes it. `using net::Endpoint` and the IoMultiplexer/Waker
// reactor types come transitively through that port header.

// AUTOSAR Testability Protocol endpoint (PRS_TPSP §6, AUTOSAR TC 1.2.0), the
// platform-agnostic core. It owns the codec dispatch, every service-primitive's
// request parsing and response framing, the socket table, and the async-event
// worker lifecycle — all written once — and delegates each network operation to
// an injected SocketBackend. A Linux deployment pairs it with a POSIX backend,
// the lwIP fixture with an lwIP backend; the wire framing is the shared SSOT in
// include/tc8/testability_protocol.h so both decode identically.
//
// Served standard groups (PRS_TPSP §6.10): GENERAL (0x00), UDP (0x01),
// TCP (0x02), ICMP (0x03), ICMPv6 (0x04), IP (0x05), IPv6 (0x06), ETH (0x0B).
// registerPrimitive() is the
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

    // Register a stateful OEM service group (PRS_TPSP §6.6). Call before start():
    // the module's onStart() runs at start() and onStop() at stop()/dtor on a
    // dedicated executor; primitives for its owned GID(s) are marshaled there and
    // the single Response awaited, so the module stays lock-free. Consulted
    // before the built-in groups, after the registerPrimitive table. Throws
    // std::invalid_argument if an owned GID is GENERAL (0x00) or already taken.
    void registerModule(std::unique_ptr<MiddlewareModule> module);

private:
    // Per-module executor + timer/task scheduler + MiddlewareContext impl. Hosts
    // one MiddlewareModule on a dedicated thread (defined in the .cpp).
    struct ModuleRuntime;

    void startModules();              // launch each module's executor + onStart()
    void stopModules();               // onStop() + join each executor
    void broadcastStartTest();        // GENERAL START_TEST -> every module
    void broadcastEndTest();          // GENERAL END_TEST -> every module

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
    std::uint8_t staticAddress(const std::uint8_t *dat, std::size_t dat_len);
    std::uint8_t staticRoute(const std::uint8_t *dat, std::size_t dat_len);
    std::uint8_t staticAddressV6(const std::uint8_t *dat, std::size_t dat_len);
    std::uint8_t staticRouteV6(const std::uint8_t *dat, std::size_t dat_len);

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

    // Stateful OEM groups: the runtimes own the modules + executors; the index
    // routes a GID to its owning runtime (set at registerModule, read-only while
    // serving). Declared last so they tear down (stopModules) before the sockets.
    std::vector<std::unique_ptr<ModuleRuntime>> modules_;
    std::map<std::uint8_t, ModuleRuntime *> gid_to_module_;
};

}  // namespace tc8::testability
