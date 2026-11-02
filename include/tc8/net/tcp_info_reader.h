#pragma once

#include <cstdint>

namespace tc8::net {

// The TCP state numbering a TcpInfo speaks. The values equal the Linux kernel's TCP
// FSM numbering because the Linux adapter passes tcpi_state through verbatim, and it
// static_asserts the equivalence there. A stack with its own numbering translates at
// its adapter. SCXML conds pin these values numerically and cannot include this
// header, so the numbers never change. The Upper Tester's wire protocol names the same
// values (upper_tester_protocol.h).
inline constexpr std::uint8_t kTcpStateEstablished = 1;
inline constexpr std::uint8_t kTcpStateSynSent     = 2;
inline constexpr std::uint8_t kTcpStateSynRecv     = 3;
inline constexpr std::uint8_t kTcpStateFinWait1    = 4;
inline constexpr std::uint8_t kTcpStateFinWait2    = 5;
inline constexpr std::uint8_t kTcpStateTimeWait    = 6;
inline constexpr std::uint8_t kTcpStateClose       = 7;
inline constexpr std::uint8_t kTcpStateCloseWait   = 8;
inline constexpr std::uint8_t kTcpStateLastAck     = 9;
inline constexpr std::uint8_t kTcpStateListen      = 10;
inline constexpr std::uint8_t kTcpStateClosing     = 11;

// The state of a TCP connection and the counters a retransmission case verdicts on.
struct TcpInfo {
    std::uint8_t  state       = 0;  // kTcpState*
    std::uint32_t rto_us      = 0;  // retransmission timeout, microseconds
    std::uint8_t  retransmits = 0;  // retransmits fired, reset by forward progress
    std::uint32_t unacked     = 0;  // segments outstanding
};

// Reads a connection's TCP state from the stack. Kept out of SocketBackend on purpose:
// the testability server needs none of it, so it depends on the plain socket seam alone
// (ISP). A host that wants this read builds the adapter for its stack and hands it to
// whatever needs it, such as a middleware module (MiddlewareContext::socketHandle gives
// the module the handle to ask about). Handles are the same opaque `int`s SocketBackend
// deals in.
class TcpInfoReader {
public:
    virtual ~TcpInfoReader() = default;

    // true on success, filling `out`; false if the stack cannot report it for `fd`.
    virtual bool queryTcpInfo(int fd, TcpInfo &out) = 0;
};

}  // namespace tc8::net
