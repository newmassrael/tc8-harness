#pragma once

namespace tc8 {

// A run-scoped service the conformance capture loop polls inline on its single
// thread. A case builds one during stimulus(), hands ownership to the runner via
// IBackgroundServiceOwner::adoptService (see sce_integration/test_runner.h), and
// the runner keeps it from then until run teardown, destroying it (RAII) there.
// The service runs on the SAME thread as frame dispatch and tick(), with no worker
// thread and no capture/emit concurrency (the single-thread model
// IStimulusScheduler::schedule and testability::Reactor both follow).
//
// WHEN onReadable() IS CALLED. On every drain of the capture after the service is
// adopted: while the stimulus that adopted it awaits an observation
// (IStimulusObserver::awaitObservation), then on each iteration of the listen
// window, then through the post-verdict drain when the run saves a pcap. A
// stimulus that blocks any other way (a sleep) drains nothing, so input queues on
// the fd until the next drain. The CLI capture loop also folds pollFd() into the
// set it waits on, so input wakes it.
//
// A SERVICE DOES NOT KNOW THE RUN'S PHASE, AND MUST NOT INFER IT. Being polled says
// only that the capture was drained. It says nothing about whether the listen window
// is open or whether the case has done what the service reacts to, and when that
// happens has changed once already. A service that stamped "the window opened" on
// its first onReadable() fired 1.5 s early once a stimulus began to await, and it
// graded a reply to a question the case had not yet asked. Anchor a reaction on the
// DUT's action itself: input on the service's own fd, or, for traffic that never
// reaches that fd, a captured frame (adopt the service as an IFrameObservingService,
// sce_integration/captured_frame_observer.h). A follow-up a fixed time after that
// anchor can be checked in onReadable(), which the drains call at the capture
// loop's cadence. There is deliberately no "window opened" callback. The window is
// the harness's bookkeeping, not something the DUT does, so anchoring on it is the
// same proxy one step removed. A step timed against the case itself belongs to
// IStimulusScheduler.
//
// The DUT side reuses this same seam: an ETS extension adopts a pollable receiver
// via IEtsIoHost (dut/dut_service/ets_io_host.h) and the DUT main loop's
// PollableHost drains it. One interface and the same single-thread, must-not-block
// drain contract, across two loops — the tester capture loop calls onReadable() on
// a fixed cadence, the DUT main loop poll()-gates it on readiness — so the contract
// below (non-blocking fd, onReadable must not block) holds for both.
//
// Why the seam exists: schedule() / scheduleAfterStateEntry() run a fire-and-
// forget ACTION and return, so an object they build dies at once; but a service
// like stimulus::ArpResponder (answer the DUT's ARP for a tester-spoofed source
// IP so the DUT's unicast Response returns) must stay alive across the capture
// window, which opens only after kickStimulus returns. A stimulus() local is
// destroyed before that window; adoptService transfers it to the runner instead.
// The same service answers while the stimulus awaits, so a stimulus can await a
// DUT frame that only arrives once the service has answered.
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

    // Called on the drain thread to consume all ready input and act on it (e.g.
    // answer every pending ARP Request, recv every queued datagram). Must not block
    // — it returns once the fd would block, so the single drain thread is never
    // stalled. On a socket it MUST also consume any pending socket error (a recv
    // that returns the error clears it): the DUT main loop poll()s for POLLIN and
    // treats POLLERR as "drain it," so an onReadable that left a socket error
    // unconsumed would make poll() wake on it every pass — a busy-spin. POLLHUP /
    // POLLNVAL, which a recv cannot clear, the DUT loop drops the service instead
    // (see PollableHost::drainReady); a peer-hangup is therefore not onReadable's
    // problem.
    virtual void onReadable() = 0;
};

}  // namespace tc8
