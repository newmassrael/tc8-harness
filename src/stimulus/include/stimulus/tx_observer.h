#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace tc8::stimulus {

// "No step": what a send or a transition reports when the case declared none for it.
inline constexpr int kNoSpecStep = -1;

// What the tester put on the wire, reported to whoever asked to watch.
//
// WHY THIS EXISTS
// ---------------
// A case's state machine moves only on what the DUT does; everything the TESTER does
// is a stimulus, and a stimulus is not a transition, so nothing recorded it while the
// case ran. A watcher following a live case (`test --state-stream`) could say which
// state the machine was in but not which step of the procedure the tester had reached.
// This is the other half of that record: one report per frame or datagram the tester
// successfully sent.
//
// WHERE IT IS CALLED
// ------------------
// From the send PRIMITIVES (raw Ethernet, UDP unicast/multicast, the SOME/IP RPC
// UDP/TCP sends, the responders' TCP send), after the send succeeded, not from each
// `emit*`. There are dozens of emitters over several routes, and a case may send by a
// route no emitter wraps; a report from the primitive cannot be missed by a new
// emitter, where a report from each emitter would be forgotten by the first one added.
// What the primitive cannot know is WHY it was called, which is what TxScope carries.
//
// WHAT IT IS NOT
// --------------
// It describes nothing about the frame beyond where it went and how large it was: the
// saved pcap already holds every frame in full, and a second, harness-side description
// of each would be a second place for a description to be wrong.
struct TxEvent {
    // The `emit*` / `send*` entry point the case called, or empty when the send was
    // reached by some other route. The OUTERMOST scope wins: a case calls
    // emitFindServiceBoot, not the primitive underneath it.
    std::string_view emitter;
    // Which primitive carried it: "ethernet", "udp_unicast", "udp_multicast", "tcp",
    // or one of the TCP control segments below.
    //
    // The TCP control segments are made by the kernel, not by the tester: what the
    // tester did is a connect() or an accept(), and each segment that call put on the
    // wire for it is one report, with `bytes` 0, made once the call succeeded (a call
    // that failed is not reported):
    //   "tcp_connect"      the SYN of a connection the tester opened
    //   "tcp_connect_ack"  the ACK that completed that handshake (reported right after
    //                      "tcp_connect", since connect() returns only once it is sent)
    //   "tcp_accept"       the SYN+ACK of a connection the DUT opened to the tester; the
    //                      kernel sent it when the SYN arrived, so the report may come
    //                      well after it, whenever the tester accepted
    //   "tcp_reset"        the RST of a connection the tester aborted (close with
    //                      SO_LINGER 0), reported as the abort is made
    //   "tcp_refuse"       the RST the kernel answers a SYN with while the tester serves
    //                      no listener on a port, reported as the case sets that up, so
    //                      BEFORE the SYN it answers has arrived (or if none ever does);
    //                      only `src_port` is known, the port refused, and `dst` is absent
    // A report names its connection (dst and src_port) and the segment by its flags, not
    // by its time, so a watcher picks the frame out of the capture by both. The wire
    // itself is in the saved pcap and the live `frame` lines.
    const char *transport = "";
    std::string_view iface;  // empty when the primitive does not take one
    // IPv4 destination in network byte order and port; 0/0 when the primitive does not
    // know it (a raw frame is opaque to the sender).
    std::uint32_t dst_ip_be = 0;
    std::uint16_t dst_port = 0;
    // The tester's own port, for a send on a TCP connection; 0 when the primitive does
    // not report one. With the destination it names the connection, which is what tells
    // two connections to the same DUT port apart.
    std::uint16_t src_port = 0;
    std::size_t bytes = 0;
    // The specification step the case declared for this send (TxSpecStep), or
    // kNoSpecStep. Carried, never interpreted: the number means something only to the
    // case that wrote it and to whoever reads the case's own step table.
    int spec_step = kNoSpecStep;
};

class ITxObserver {
public:
    virtual ~ITxObserver() = default;
    // Called on the sending thread, after a successful send. It must not block and
    // must not throw: it runs inside the stimulus, whose timing is the measurement.
    virtual void onTx(const TxEvent &ev) = 0;
};

// The observer for this process, or nullptr (the default: nothing is reported and a
// send costs one pointer test). Process-scoped for the reason `setSiteDutIpv4` is: one
// harness process runs one case, set once by the runner before any stimulus. The
// caller owns the observer and must clear it (nullptr) before destroying it; clearing
// returns only once no thread is still inside a report, so a sender on a thread of its
// own (a responder, a burst a case detached) never reaches a destroyed observer.
void setTxObserver(ITxObserver *observer);

// Report a successful send. No-op without an observer. `iface` may be empty.
void reportTx(const char *transport, std::string_view iface, std::uint32_t dst_ip_be,
              std::uint16_t dst_port, std::size_t bytes);

// The same for a send on a connected IPv4 socket: the peer and the tester's own port are
// read from the socket, so the report names the connection. Without an observer it does
// not even look. `iface` may be empty.
void reportTxConnected(const char *transport, int fd, std::size_t bytes,
                       std::string_view iface = {});

// A connect() on `fd` succeeded: reports "tcp_connect" and then "tcp_connect_ack" (see
// TxEvent::transport), with the steps a TxConnectSteps on this thread names, or else
// both with the current TxSpecStep. `iface` may be empty.
void reportTcpConnected(std::string_view iface, int fd);

// accept() returned `fd` for a connection from `peer_ip_be` (network byte order) and
// `peer_port` (host order), as accept() itself reported them: reports "tcp_accept" with
// the current TxSpecStep. The peer comes from the caller and is not asked of the socket,
// because the accept can come long after the connection was made and the peer may have
// reset it by then; a reset socket answers getpeername with ENOTCONN, and the connection
// would be reported without its name.
void reportTcpAccepted(int fd, std::uint32_t peer_ip_be, std::uint16_t peer_port);

// The tester aborts a connection (close with SO_LINGER 0, which puts an RST on the wire
// in place of a FIN): reports "tcp_reset" with the current TxSpecStep. Call it as the
// abort is made, once the linger option is set. The ends come from the caller for the
// reason reportTcpAccepted's peer does: a socket being reset is not one to ask. `iface`
// may be empty.
void reportTcpReset(std::string_view iface, std::uint32_t dst_ip_be, std::uint16_t dst_port,
                    std::uint16_t src_port);

// The tester serves no listener on `port` (host order), so the kernel answers a SYN to it
// with an RST: reports "tcp_refuse" with the current TxSpecStep. There is no call of the
// tester's to hook, only a port left unserved, so the CASE says so, when it arranges it.
// It is a declaration made before the SYN it answers, and a SYN that never comes leaves
// a report with no frame behind it, which is what a watcher should see. `iface` may be
// empty.
void reportTcpRefusal(std::string_view iface, std::uint16_t port);

// Names the emitter for every send made while it is alive, on this thread. Nested
// scopes keep the outermost name. Use through TC8_TX_SCOPE().
class TxScope {
public:
    explicit TxScope(const char *emitter);
    ~TxScope();
    TxScope(const TxScope &) = delete;
    TxScope &operator=(const TxScope &) = delete;

private:
    bool owns_;
};

// Tags every send made while it is alive, on this thread, with the specification step
// the case says it performs. A case wraps the emission in its own `stimulus()`:
//
//     ::tc8::stimulus::TxSpecStep step(1);
//     ::tc8::stimulus::emitMethodRequestAfter(...);
//
// Nested scopes: the innermost wins and the outer one is restored on exit, so a case may
// name a sub-step inside a larger one. Independent of TxScope (which names the emitter):
// the emitter says what code sent it, the step says which part of the specified
// procedure it was. A send on another thread (a responder, a burst thread) is not tagged
// by a scope on this one.
class TxSpecStep {
public:
    explicit TxSpecStep(int step);
    ~TxSpecStep();
    TxSpecStep(const TxSpecStep &) = delete;
    TxSpecStep &operator=(const TxSpecStep &) = delete;

private:
    int previous_;
};

// Tags the two segments of a TCP handshake the tester opens while it is alive, on this
// thread: the SYN with `syn` and the completing ACK with `ack` (kNoSpecStep leaves that
// one untagged). A procedure may count the handshake as steps of its own, apart from the
// request sent over the connection, and the connect is made inside the emitter that
// sends the request, so the case cannot put a TxSpecStep around the connect alone:
//
//     ::tc8::stimulus::TxSpecStep request(4);
//     ::tc8::stimulus::TxConnectSteps handshake(/*syn=*/2, /*ack=*/3);
//     ::tc8::stimulus::emitMethodRequestTcpAfter(...);   // connect, then the request
//
// Without one, both segments take the current TxSpecStep, as every other send does.
// Nested scopes: the innermost wins and the outer one is restored on exit.
class TxConnectSteps {
public:
    TxConnectSteps(int syn, int ack);
    ~TxConnectSteps();
    TxConnectSteps(const TxConnectSteps &) = delete;
    TxConnectSteps &operator=(const TxConnectSteps &) = delete;

private:
    bool previous_active_;
    int  previous_syn_;
    int  previous_ack_;
};

}  // namespace tc8::stimulus

// First statement of an emit* / send* entry point. `__func__` rather than a string the
// author types, so the name cannot drift from the function it labels.
#define TC8_TX_SCOPE() ::tc8::stimulus::TxScope tc8_tx_scope_(__func__)
