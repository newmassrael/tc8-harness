#pragma once

#include <cstdint>
#include <vector>

#include "tc8/captured_event.h"

namespace tc8::sce {

// A `tc8::CapturedEvent` that owns every byte it points at.
//
// A captured event is a VIEW. Six of its seven frame types carry `payload_data` /
// `options_data` pointers into objects the packet pipeline builds on its stack for
// one frame — the libtins PDUs of `PacketPipeline::processFrame` — so the event is
// valid exactly as long as the callback that delivers it. Every consumer so far
// has read it inside that callback, and that is why the pointers could stay
// borrowed.
//
// Holding an event past its callback is a different use, and it needs its own
// type rather than a copy of the view: a plain copy of the variant copies the
// POINTERS, which then dangle, and the frame still decodes cleanly — the bytes
// read back are whatever the pipeline's next frame left there. This type copies
// each borrowed region into storage it owns and repoints the frame at it, so the
// held event stays valid until this object is destroyed.
//
// Move-only. Moving a std::vector keeps its heap buffer, so the repointed frame
// stays valid across a move; a member-wise COPY would duplicate the buffers and
// leave the copy's frame pointing into the original's. A second owner is made by
// constructing a new one from `view()`.
class OwnedCapturedEvent {
public:
    // Deep-copies every borrowed region of `ev`.
    explicit OwnedCapturedEvent(const ::tc8::CapturedEvent &ev);

    OwnedCapturedEvent(OwnedCapturedEvent &&) noexcept = default;
    OwnedCapturedEvent &operator=(OwnedCapturedEvent &&) noexcept = default;
    OwnedCapturedEvent(const OwnedCapturedEvent &) = delete;
    OwnedCapturedEvent &operator=(const OwnedCapturedEvent &) = delete;
    ~OwnedCapturedEvent() = default;

    // The event, with every pointer into storage this object owns.
    const ::tc8::CapturedEvent &view() const {
        return event_;
    }

private:
    ::tc8::CapturedEvent event_;
    // One buffer per borrowed region. A vector of vectors rather than one arena so
    // no region's address depends on another's size.
    std::vector<std::vector<std::uint8_t>> storage_;
};

}  // namespace tc8::sce
