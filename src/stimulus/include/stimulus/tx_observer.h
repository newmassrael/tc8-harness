#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace tc8::stimulus {

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
    // Which primitive carried it: "ethernet", "udp_unicast", "udp_multicast", "tcp".
    const char *transport = "";
    std::string_view iface;  // empty when the primitive does not take one
    // IPv4 destination in network byte order and port; 0/0 when the primitive does not
    // know it (a raw frame is opaque to the sender).
    std::uint32_t dst_ip_be = 0;
    std::uint16_t dst_port = 0;
    std::size_t bytes = 0;
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
// caller owns the observer and must clear it (nullptr) before destroying it.
void setTxObserver(ITxObserver *observer);

// Report a successful send. No-op without an observer. `iface` may be empty.
void reportTx(const char *transport, std::string_view iface, std::uint32_t dst_ip_be,
              std::uint16_t dst_port, std::size_t bytes);

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

}  // namespace tc8::stimulus

// First statement of an emit* / send* entry point. `__func__` rather than a string the
// author types, so the name cannot drift from the function it labels.
#define TC8_TX_SCOPE() ::tc8::stimulus::TxScope tc8_tx_scope_(__func__)
