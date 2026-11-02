#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace tc8 {

// What the operator declares about the DUT's TCP implementation, for a case that grades
// a value the standards leave to the implementation. RFC 5681 bounds the initial
// congestion window from above, so 1 and 10 both conform; the recovery arithmetic depends
// on the algorithm; RFC 1122 leaves the transmit-buffer delay open.
//
// Each stays unset until the operator sets it (`--expect tcp.<key>=<value>`, or a site's
// `extra_expect`). There is deliberately no default, here or in a case: a guessed value
// fails a differently configured DUT for no fault of its own. A case that needs one
// declares that through its `applicability` trait, using tcpDeclarationMissing, so an
// undeclared value is a skip that names it and not a guess.
//
// The harness never branches on `congestion_control`. It is reported with the run so the
// assumption behind a graded window stays visible.
struct TcpDeclarations {
    std::optional<std::uint32_t> initial_cwnd_segments;  // at least 1
    std::optional<std::string> congestion_control;       // e.g. "new_reno"
    std::optional<std::uint32_t> tx_buffer_delay_ms;
};

enum class TcpDeclaration : std::uint8_t { kInitialCwnd, kCongestionControl, kTxBufferDelay };

// The `applicability` reason for a value the case needs and the operator left undeclared,
// or nullopt when it is declared.
inline std::optional<std::string> tcpDeclarationMissing(const TcpDeclarations &declared,
                                                        TcpDeclaration needed) {
    switch (needed) {
        case TcpDeclaration::kInitialCwnd:
            if (!declared.initial_cwnd_segments) {
                return "undeclared_tcp_initial_cwnd_segments";
            }
            break;
        case TcpDeclaration::kCongestionControl:
            if (!declared.congestion_control) {
                return "undeclared_tcp_congestion_control";
            }
            break;
        case TcpDeclaration::kTxBufferDelay:
            if (!declared.tx_buffer_delay_ms) {
                return "undeclared_tcp_tx_buffer_delay_ms";
            }
            break;
    }
    return std::nullopt;
}

}  // namespace tc8
