#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "tc8/autosar/com.h"
#include "tc8/autosar/e2e.h"
#include "tc8/autosar/nm.h"
#include "tc8/autosar/pn_filter.h"
#include "tc8/autosar/someiptp.h"
#include "tc8/testability/middleware.h"

namespace tc8::demo {

// A synthetic Upper-Tester middleware module — the copy-from template an
// out-of-tree OEM repo starts from, and the hermetic proof that the seam plus
// the public AUTOSAR engines compose end to end. It owns an OEM-reserved service
// group (GID counts down from 0x7F, PRS_TPSP §6.6) and drives:
//   * tc8::nm   — a network-management state machine, ticked on a timer,
//     transmitting NM PDUs and emitting an EVENT on each state change;
//   * tc8::com  — a signal database, packed cyclically into an I-PDU;
//   * tc8::e2e  — Profile 5 protection (CRC-16 + counter, via tc8::crc) over the
//     transmitted signal PDU;
//   * tc8::crypto — AES-CMAC, exposed as an authenticate primitive;
//   * tc8::pn   — a Partial-Networking relevance filter, exposed as a primitive;
//   * tc8::someiptp — SOME/IP-TP transport: a tx primitive segments a payload and
//     sends each segment, and the rx path feeds the reassembler (ticked on a timer,
//     emitting an EVENT when a message reassembles or a transfer times out).
// Every value here is fabricated (no OEM frames/ports/keys); a real module would
// inject its proprietary configuration in the same shapes.
//
// All callbacks run on the module executor, serialized — no locking. The module
// also consumes inbound PDUs: its data socket is registered with the context via
// watchReadable, so the executor's poll/waker reactor delivers each received
// datagram on the same thread (no private receive thread), and the COM engine
// unpacks it — the rx counterpart of the cyclic tx path.
class DemoModule : public tc8::testability::MiddlewareModule {
public:
    DemoModule();

    // Service primitive IDs this module answers (under its owned GID).
    enum Pid : std::uint8_t {
        kPidRequestNetwork = 0x01,
        kPidReleaseNetwork = 0x02,
        kPidGetNmState = 0x03,
        kPidSetSignal = 0x04,    // dat = signal value, little-endian
        kPidAuthenticate = 0x05,  // dat = message; resp = AES-CMAC (zero key)
        kPidGetLastSignal = 0x06,  // resp = last inbound signal value (2 bytes LE)
        kPidSendLarge = 0x07,      // dat = payload to SOME/IP-TP segment and send
        kPidGetLastTpLen = 0x08,   // resp = last reassembled TP message length (2 bytes LE)
        kPidPnRelevant = 0x09,     // dat = NM PDU; resp = 1 byte PN relevance
    };
    static constexpr std::uint8_t kGroup = 0x7F;
    static constexpr std::uint8_t kPidStateEvent = 0x70;      // EVENT: NM state change
    static constexpr std::uint8_t kPidSignalRxEvent = 0x71;   // EVENT: inbound signal value
    static constexpr std::uint8_t kPidTpRxEvent = 0x72;       // EVENT: TP message reassembled (len LE)
    static constexpr std::uint8_t kPidTpTimeoutEvent = 0x73;  // EVENT: TP transfer timed out

    // The UDP port the module binds for its data plane (PDU tx + rx). Fabricated,
    // like every value here; the OEM module would inject its own. Public so a test
    // system / the hermetic test knows where to send inbound PDUs.
    static constexpr std::uint16_t kDataPort = 30491;

    std::vector<std::uint8_t> groups() const override;
    void onStart(tc8::testability::MiddlewareContext& ctx) override;
    void onStop() override;
    void onPrimitive(const tc8::testability::Header& req, const std::uint8_t* dat,
                     std::size_t dat_len, const tc8::net::Endpoint& peer,
                     std::uint8_t& rid_out, std::vector<std::uint8_t>& resp_dat) override;
    void onEndTest() override;

private:
    void transmitSignalPdu();  // pack -> E2E protect -> send
    void onDataReadable();     // recv -> COM unpack -> record + emit rx EVENT

    tc8::testability::MiddlewareContext* ctx_ = nullptr;
    int sock_ = -1;
    tc8::testability::TimerId nm_timer_ = tc8::testability::kNoTimer;
    tc8::testability::TimerId com_timer_ = tc8::testability::kNoTimer;
    tc8::testability::WatchId rx_watch_ = tc8::testability::kNoWatch;
    tc8::testability::TimerId tp_timer_ = tc8::testability::kNoTimer;
    std::optional<std::uint64_t> last_rx_signal_;  // most recent unpacked signal value
    std::optional<std::size_t> last_tp_len_;       // most recent reassembled TP message length

    tc8::nm::StateMachine nm_;
    tc8::com::SignalEngine com_;
    tc8::e2e::Profile05Protector e2e_;
    tc8::pn::PnFilter pn_;
    tc8::someiptp::Segmenter tp_seg_;
    tc8::someiptp::Reassembler tp_re_;
};

}  // namespace tc8::demo
