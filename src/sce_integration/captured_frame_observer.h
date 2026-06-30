#pragma once

#include "tc8/captured_event.h"
#include "tc8/pollable_service.h"

namespace tc8::sce {

// A run-scoped observer of captured wire frames. The runner calls onCapturedFrame
// for every CapturedEvent AFTER it has dispatched that event into the SCXML state
// machine, so an adopted service can sequence its NEXT emit on an OBSERVED frame
// rather than a wall-clock delay (the brittle "wait N ms then read back" shape).
// Runs on the single capture-loop thread (same as onCaptured / tick), so it must
// not block. One physical pcap frame can fan out into several CapturedEvent
// sub-events (e.g. a TCP packet yields both an Ipv4Frame and a TcpFrame), so a
// matched observer is called once per sub-event and must filter for what it cares
// about. This seam lives in the sce layer (not tc8-core's pollable_service.h)
// because it depends on ::tc8::CapturedEvent, whose header pulls the seven
// protocol_frames/* types; pollable_service.h is deliberately dependency-free
// (zero includes), and folding this in would drag that decode surface into a
// core header that today depends on nothing.
//
// Residual caveat: this makes the reply-OBSERVED reaction shapes event-driven, but
// a no-reply / malformed-reply case that must outlast a DUT-internal timeout which
// emits no packet still needs a bounded local settle — there is no wire event to
// gate on. The seam removes the wall-clock coupling for the observed case; it does
// not turn the silent-timeout case into an event.
class ICapturedFrameObserver {
public:
    virtual ~ICapturedFrameObserver() = default;

    virtual void onCapturedFrame(const ::tc8::CapturedEvent& ev) = 0;
};

// A pollable service that ALSO observes captured frames: it is owned and polled
// like any adopted tc8::IPollableService (its own fd drained by the capture loop)
// AND receives every captured frame via ICapturedFrameObserver. A reaction
// responder is exactly this — it emits/reads on its own socket and gates its next
// emit on an observed reply. Adopt one via
// IBackgroundServiceOwner::adoptObservingService; the combined type lets the runner
// register both roles from a single owned object with no run-time type query.
class IFrameObservingService : public ::tc8::IPollableService,
                               public ICapturedFrameObserver {};

}  // namespace tc8::sce
