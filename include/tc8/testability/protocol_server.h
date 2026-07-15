#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <vector>

#include "tc8/testability/middleware.h"
#include "tc8/testability/reactor.h"
#include "tc8/testability/socket_backend.h"
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
// registerPrimitive() is the OEM extension/override seam (PRS_TPSP §6.6).
//
// Concurrency: the whole endpoint runs on ONE Reactor loop — the control socket,
// every hosted module, and the async-event workers are all watches/timers on it,
// so no internal locking is needed. A hosted deployment calls start()/stop() and
// the reactor owns a thread; a single-task (bare-metal / RTOS) deployment calls
// startInline() and pumps runOnce()/run() from its own task, with no std::thread.
class ProtocolServer {
public:
    explicit ProtocolServer(std::unique_ptr<SocketBackend> backend);
    ~ProtocolServer();

    ProtocolServer(const ProtocolServer &) = delete;
    ProtocolServer &operator=(const ProtocolServer &) = delete;

    // Bind the UDP listener and start the reactor on its own thread. false if the
    // bind fails (the endpoint is additive — a caller may keep serving other
    // channels). No-op-safe to call once.
    bool start(std::uint16_t port = testability::kDefaultPort);

    // Signal the reactor to exit, join it, run each module's onStop(), and close
    // any open sockets. Idempotent; works whether started with start() or
    // startInline().
    void stop();

    // Bind the listener and initialise the reactor WITHOUT spawning a thread: the
    // caller's own task then drives the loop with runOnce()/run(). This is the
    // single-task entry for a platform with no std::thread. The calling task must
    // also be the one that pumps. false if the bind fails.
    bool startInline(std::uint16_t port = testability::kDefaultPort);

    // Caller-driven pump for startInline(): run one reactor iteration (blocking in
    // poll() for at most `timeout_ms`, or non-blocking at 0) — call in a loop from
    // the owning task. run() loops until stop(). Both are no-ops under start().
    bool runOnce(int timeout_ms);
    void run();

    // A synchronous service-primitive handler (PRS_TPSP §6.6): reads the parsed
    // request, its DAT and the requesting peer, fills the Result ID and any
    // response DAT for the single Response. Runs on the reactor loop,
    // request/response only — it cannot emit async Events or touch the socket
    // table (a vendor group needing async behaviour manages its own resources).
    using SpHandler =
        std::function<void(const Header &req, const std::uint8_t *dat, std::size_t dat_len,
                           const Endpoint &peer, std::uint8_t &rid_out,
                           std::vector<std::uint8_t> &resp_dat)>;

    // Register an OEM handler for (gid, pid). Consulted BEFORE the built-in
    // groups, so it both EXTENDS the endpoint with a non-standard group and
    // OVERRIDES a standard primitive. Call before start(): the table is
    // read-only while the reactor runs.
    void registerPrimitive(std::uint8_t gid, std::uint8_t pid, SpHandler handler);

    // Register a stateful OEM service group (PRS_TPSP §6.6). Call before start():
    // the module's onStart() runs at start() and onStop() at stop()/dtor on the
    // reactor loop; primitives for its owned GID(s) run there, so the module stays
    // lock-free. Consulted before the built-in groups, after the registerPrimitive
    // table. Throws std::invalid_argument if an owned GID is GENERAL (0x00) or
    // already taken.
    void registerModule(std::unique_ptr<MiddlewareModule> module);

private:
    // Per-module MiddlewareContext impl. Hosts one MiddlewareModule on the shared
    // reactor (defined in the .cpp); holds no thread of its own.
    struct ModuleRuntime;

    bool bindControl(std::uint16_t port);  // create + bind the control UDP socket (fd_)

    // On-loop lifecycle helpers (run on the reactor thread / pumping task).
    void setupOnLoop();               // add the control-socket watch + module onStart()
    void teardownOnLoop();            // module onStop() + drop every async-event watch
    void startModules();              // onStart() for each registered module
    void stopModules();               // onStop() for each registered module
    void broadcastStartTest();        // GENERAL START_TEST -> every module
    void broadcastEndTest();          // GENERAL END_TEST -> every module

    void onControlReadable();         // a datagram on the control socket -> dispatch + respond
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

    // PRS_TPSP §6.2 async-event workers, run as reactor watches (no threads). A
    // LISTEN_AND_ACCEPT / RECEIVE_AND_FORWARD arms a watch on the socket; the
    // handler accepts/receives and emits an Event on each readiness, and removes
    // itself when its bound (maxCon / maxLen / peer close) is reached.
    struct EventWatch {
        WatchId id = kNoWatch;
        int fd = -1;
        std::uint16_t service_id = 0;
        Endpoint peer{};                          // the Event's target (the requester)
        enum Kind { kAccept, kRecvTcp, kRecvUdp } kind = kAccept;
        std::uint16_t listen_socket_id = 0;       // kAccept: the listen socket's id
        std::uint16_t max_con = 0;                // kAccept: accept bound
        std::uint16_t accepted = 0;               // kAccept: accepts so far
        std::uint16_t max_fwd = 0;                // kRecv*: bytes forwarded per Event
        std::uint16_t max_len = 0;                // kRecv*: total-forward bound
        bool limitless = false;                   // kRecv*: max_len == 0xFFFF
        std::uint32_t consumed = 0;               // kRecv*: bytes consumed so far
    };
    void armEventWatch(std::uint16_t socket_id, EventWatch w);  // install watch + record under id
    void onWorkerReadable(std::uint16_t socket_id);  // dispatch one readiness for a worker
    bool acceptOne(EventWatch &w);                // kAccept body; false => stop the worker
    bool recvForwardTcpOne(EventWatch &w);        // kRecvTcp body; false => stop
    bool recvForwardUdpOne(EventWatch &w);        // kRecvUdp body; false => stop
    void emitEvent(std::uint16_t service_id, std::uint8_t gid, std::uint8_t pid,
                   const std::vector<std::uint8_t> &dat, const Endpoint &peer);

    std::uint16_t registerSocket(int fd);
    std::optional<int> lookupSocket(std::uint16_t id) const;
    bool eraseSocket(std::uint16_t id, bool abort = false);
    void closeAllSockets();

    void stopWorker(std::uint16_t socket_id);     // remove one worker's watch (if any)
    void stopAllWorkers();                        // remove every worker's watch

    std::unique_ptr<SocketBackend> backend_;
    Reactor reactor_;  // the single event loop hosting control + modules + workers

    int fd_ = -1;                       // control (testability) UDP socket
    WatchId control_watch_ = kNoWatch;  // its reactor watch

    // Async-event workers, keyed by the socket_id they serve (the listen socket for
    // kAccept, the forwarded socket for kRecv*). All touched only on the loop.
    std::map<std::uint16_t, EventWatch> event_watches_;

    std::map<std::uint16_t, int> sockets_;
    std::uint16_t next_socket_id_ = 1;

    std::map<std::uint16_t, SpHandler> oem_handlers_;

    // Stateful OEM groups: the runtimes own the modules; the index routes a GID to
    // its owning runtime (set at registerModule, read-only while serving). Declared
    // last so they tear down (stopModules) before the sockets.
    std::vector<std::unique_ptr<ModuleRuntime>> modules_;
    std::map<std::uint8_t, ModuleRuntime *> gid_to_module_;
};

}  // namespace tc8::testability
