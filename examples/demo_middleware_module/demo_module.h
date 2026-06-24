#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "autosar/com.h"
#include "autosar/e2e.h"
#include "autosar/nm.h"
#include "testability/middleware.h"

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
//   * tc8::crypto — AES-CMAC, exposed as an authenticate primitive.
// Every value here is fabricated (no OEM frames/ports/keys); a real module would
// inject its proprietary configuration in the same shapes.
//
// All callbacks run on the module executor, serialized — no locking. (Inbound
// PDU reception via watchReadable is intentionally not exercised yet: the rx
// reactor is the deferred seam piece, so this module is transmit + control only.)
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
    };
    static constexpr std::uint8_t kGroup = 0x7F;
    static constexpr std::uint8_t kPidStateEvent = 0x70;  // EVENT pid for NM state change

    std::vector<std::uint8_t> groups() const override;
    void onStart(tc8::testability::MiddlewareContext& ctx) override;
    void onStop() override;
    void onPrimitive(const tc8::testability::Header& req, const std::uint8_t* dat,
                     std::size_t dat_len, const tc8::net::Endpoint& peer,
                     std::uint8_t& rid_out, std::vector<std::uint8_t>& resp_dat) override;
    void onEndTest() override;

private:
    void transmitSignalPdu();  // pack -> E2E protect -> send

    tc8::testability::MiddlewareContext* ctx_ = nullptr;
    int sock_ = -1;
    tc8::testability::TimerId nm_timer_ = tc8::testability::kNoTimer;
    tc8::testability::TimerId com_timer_ = tc8::testability::kNoTimer;

    tc8::nm::StateMachine nm_;
    tc8::com::SignalEngine com_;
    tc8::e2e::Profile05Protector e2e_;
};

}  // namespace tc8::demo
