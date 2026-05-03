#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <unordered_map>
#include <vector>

#include "tc8/captured_event.h"

#include "someip_header.h"
#include "transport.h"

namespace tc8::dissect {

// Parses SOME/IP messages out of a byte stream and emits each one as a
// `tc8::CapturedEvent` holding a `SomeIpFrame`. UDP flows use
// `deliver()` (datagram boundary == message boundary); TCP flows use
// `feed()` with per-flow residual buffering because a single message
// may straddle multiple segments.
class SomeIpDispatcher {
public:
    using Listener = std::function<void(const ::tc8::CapturedEvent &)>;

    void deliver(const Transport &t, const std::uint8_t *data, std::size_t len, const Listener &listener);

    void feed(const Transport &t, const std::uint8_t *data, std::size_t len, const Listener &listener);

private:
    static std::uint64_t flowKey(const Transport &t);
    static ::tc8::SomeIpFrame makeFrame(const Transport &t, const SomeIpHeader &h, const std::uint8_t *payload,
                                        std::size_t payload_len);

    std::unordered_map<std::uint64_t, std::vector<std::uint8_t>> residuals_;
};

}  // namespace tc8::dissect
