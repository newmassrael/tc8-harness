#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>

namespace tc8::sce::tcp {

// How long a case waits for a DUT's next retransmission: one policy for every case
// that watches the DUT's retransmission timer.
//
// WHY A POLICY AND NOT A CONSTANT
// -------------------------------
// The retransmission cases used windows tuned to one sender. TCP_RETRANSMISSION_TO_04
// gave each retransmission 8 s, from the schedule of a Linux sender (retransmissions at
// about 200, 600 and 1400 ms). A sender that keeps the initial RTO of 3 s that RFC 1122
// gave and RFC 6298 §2.1 lowered to 1 s (lwIP up to 2.1.x) retransmits at about 2.5,
// 7.5 and 17.5 s: the gap before the third retransmission is 10 s, the window closed
// first, and a sender whose RTO doubled exactly as it must ended the case without a
// verdict. The window was grading the initial RTO, which that case does not test.
//
// THE RULE
// --------
// The DUT says how long it will wait: its RTO, read right after the transmission the
// next retransmission repeats, is the timer that retransmission waits on. The window is
// that RTO with room for scheduling and a coarse timer: a quarter more, plus one second
// (two ticks of a 500 ms timer). When the RTO cannot be read, the window falls back to
// three times the interval just observed on the wire, which admits any growth up to
// tripling; before any interval has been seen, to the 3 s initial RTO of RFC 1122,
// the largest initial value a standard has given. The window never exceeds what a
// conforming sender can need: RFC 6298 §2.5 lets a sender cap its RTO at any value of
// at least 60 s, so a window sized for 60 s with the same room covers every sender
// that caps there, and keeps a sender that never retransmits from holding a case
// longer than that.
inline constexpr std::chrono::microseconds kRfc6298MinimumRtoCap{60'000'000};
inline constexpr std::chrono::microseconds kRfc1122InitialRto{3'000'000};
inline constexpr std::chrono::microseconds kRetransmissionTimerSlack{1'000'000};

// The window for the next retransmission. `dut_rto` is the DUT's RTO read after the
// transmission being repeated (0 when it could not be read); `last_interval` the
// interval between the previous two transmissions seen on the wire (0 before there
// were two).
inline std::chrono::milliseconds nextRetransmissionBound(std::chrono::microseconds dut_rto,
                                                         std::chrono::microseconds last_interval) {
    using std::chrono::microseconds;
    microseconds expected = dut_rto;
    if (expected <= microseconds::zero()) {
        expected = last_interval > microseconds::zero() ? last_interval * 3 : kRfc1122InitialRto;
    }
    expected = std::min(expected, kRfc6298MinimumRtoCap);
    const microseconds bound = expected + expected / 4 + kRetransmissionTimerSlack;
    return std::chrono::ceil<std::chrono::milliseconds>(bound);
}

}  // namespace tc8::sce::tcp
