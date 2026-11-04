#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "sce_integration/declaration_enum.h"

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
//
// Two kinds of declaration, in the terms of ISO/IEC 9646: a PIXIT value is a parameter
// the implementation chose inside the latitude a standard leaves (the first three
// below); a PICS item states which of two behaviours a standard allows the
// implementation exhibits, and selects the cases that test the other one out of its
// run (`time_wait_rst`). Neither is ever inferred from the DUT's behaviour: a selection
// read off the behaviour under test would grade the DUT against itself.

// RFC 793 §3.9 ends a TIME-WAIT connection on a RST; RFC 1337 recommends ignoring it, so
// that a stray RST cannot end TIME-WAIT early and let old duplicates reach a new
// incarnation of the connection (TIME-WAIT assassination). Both are conforming; a case
// that grades one runs only for a DUT declared to do it.
enum class TimeWaitRstPolicy : std::uint8_t {
    kEndsConnection,  // RFC 793: the RST returns the connection to CLOSED
    kIgnored,         // RFC 1337: the RST is ignored, TIME-WAIT runs its course
};

template <>
struct DeclarationEnum<TimeWaitRstPolicy> {
    static constexpr std::pair<std::string_view, TimeWaitRstPolicy> kValues[] = {
        {"ends_connection", TimeWaitRstPolicy::kEndsConnection},
        {"ignored", TimeWaitRstPolicy::kIgnored},
    };
};

struct TcpDeclarations {
    // PIXIT.
    std::optional<std::uint32_t> initial_cwnd_segments;  // at least 1
    std::optional<std::string> congestion_control;       // e.g. "new_reno"
    std::optional<std::uint32_t> tx_buffer_delay_ms;
    // PICS.
    std::optional<TimeWaitRstPolicy> time_wait_rst;
};

enum class TcpDeclaration : std::uint8_t {
    kInitialCwnd,
    kCongestionControl,
    kTxBufferDelay,
    kTimeWaitRst,
};

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
        case TcpDeclaration::kTimeWaitRst:
            if (!declared.time_wait_rst) {
                return "undeclared_tcp_time_wait_rst";
            }
            break;
    }
    return std::nullopt;
}

// The `applicability` reason for a case that grades a RST in TIME-WAIT ending the
// connection: undeclared, or declared as ignored (the DUT follows RFC 1337 and is outside
// that case's scope). nullopt when the DUT is declared to end the connection.
inline std::optional<std::string> tcpTimeWaitRstEndsConnectionMissing(const TcpDeclarations &declared) {
    if (auto missing = tcpDeclarationMissing(declared, TcpDeclaration::kTimeWaitRst)) {
        return missing;
    }
    if (*declared.time_wait_rst != TimeWaitRstPolicy::kEndsConnection) {
        return "dut_declared_to_ignore_rst_in_time_wait_rfc1337";
    }
    return std::nullopt;
}

}  // namespace tc8
