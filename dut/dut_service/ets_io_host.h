#pragma once

#include <memory>

#include "tc8/pollable_service.h"

namespace tc8::dut {

// The runtime-I/O facade an extension adopts a pollable receiver through — the
// symmetric DUT-side analogue of the tester-side
// IBackgroundServiceOwner::adoptService (sce_integration/test_runner.h). The DUT
// main loop owns each adopted service for the whole run, folds its pollFd() into
// the loop's poll set, and calls onReadable() only when the fd is ready.
//
// Segregated from the SOME/IP role facades (IEtsEventSink / IEtsClientControl /
// IEtsControlChannel) so an extension that needs no raw I/O never depends on it.
// The seam carries NO port, protocol, or payload semantics: the extension brings
// its own receiver (it owns the socket, binds whatever ports and joins whatever
// groups its surface needs, and decodes the datagrams itself), and the DUT owns
// only the drain. That keeps the same vendor-neutral boundary the other ETS seams
// hold — the harness gains a receive-drain model, not any product's wire.
class IEtsIoHost {
public:
    virtual ~IEtsIoHost() = default;

    // Take ownership of a pollable receiver (typically from onRegister). The
    // service's pollFd() must be non-blocking and onReadable() must drain without
    // blocking — it runs on the DUT main-loop thread (see tc8::IPollableService). A
    // service whose pollFd() is -1 is owned but never polled.
    //
    // Must be called on the DUT main-loop thread (onRegister / onTick), the same
    // thread that drains it — the host serializes nothing, so adopting from a
    // vsomeip handler thread concurrently with a drain would race the owned set.
    virtual void adoptPollable(std::unique_ptr<tc8::IPollableService> service) = 0;
};

}  // namespace tc8::dut
