#pragma once

namespace tc8 {

// A run-scoped service the conformance capture loop polls inline on its single
// thread. A case builds one during stimulus(), hands ownership to the runner via
// IBackgroundServiceOwner::adoptService (see sce_integration/test_runner.h), and
// the runner keeps it for the whole post-stimulus capture window, destroying it
// (RAII) at run teardown. The CLI capture loop folds pollFd() into its drain set
// and calls onReadable() each iteration — so the service runs on the SAME thread
// as frame dispatch and tick(), with no worker thread and no capture/emit
// concurrency (the single-thread model IStimulusScheduler::schedule and
// testability::Reactor both follow).
//
// Why the seam exists: schedule() / scheduleAfterStateEntry() run a fire-and-
// forget ACTION and return, so an object they build dies at once; but a service
// like stimulus::ArpResponder (answer the DUT's ARP for a tester-spoofed source
// IP so the DUT's unicast Response returns) must stay alive across the capture
// window, which opens only after kickStimulus returns. A stimulus() local is
// destroyed before that window; adoptService transfers it to the runner instead.
//
// This header is the canonical description of the seam; arp_responder.h and
// test_runner.h reference it rather than restate it.
class IPollableService {
public:
    virtual ~IPollableService() = default;

    // A readable fd to fold into the capture loop's drain set, or -1 if the
    // service failed to acquire one (then the loop skips it; a failed service is
    // still owned and torn down normally). The fd must be non-blocking so
    // onReadable() can drain it without stalling the single capture thread.
    virtual int pollFd() const = 0;

    // Called on the capture-loop thread to drain all ready input and act on it
    // (e.g. answer every pending ARP Request). Must not block — it returns once
    // the fd would block, so the single capture thread is never stalled.
    virtual void onReadable() = 0;
};

}  // namespace tc8
