#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <tuple>

namespace tc8::dut {

// Request/Response session correlation for the raw vsomeip client
// (VsomeipEtsClientControl). vsomeip's application_impl::on_message routes an
// incoming Response/Error to a bare (service, instance, method) message handler
// with NO session-id correlation and NO pending-request check — so a Response
// whose SOME/IP Session ID does not belong to any Request the DUT actually sent
// is still delivered to that handler. A real CommonAPI-SomeIP proxy DROPS such a
// Response: it correlates each Response to its pending Request by request-id
// (client + session), and an unmatched session resolves to no pending call. This
// policy restores that behaviour for the raw client, so a DUT client ignores an
// uncorrelated Response (and the pending call times out) exactly as a
// proxy-backed DUT would.
//
// PURE POLICY — vsomeip-free and self-synchronised: the record side runs on the
// caller's send thread while acceptResponse() runs on a vsomeip dispatch thread,
// so the class owns its own mutex and VsomeipEtsClientControl shares one instance
// by shared_ptr (the receive-side capture is a strong copy, so an enqueued
// message callback that outlives the control never touches a dead object). The
// decision is unit-tested hermetically with plain integers.
//
// ORDERING: a Response cannot be accepted before its Request's session is
// recorded. recordSent() holds the mutex ACROSS the send, and acceptResponse()
// takes the same mutex — so even if the wire round trip were instantaneous, a
// racing acceptResponse() blocks until the send-and-record transaction lands.
// This is a real lock happens-before, not a "the send is faster than the
// network" timing assumption. The send callable must only ENQUEUE (vsomeip's
// send does), never block on the dispatch thread, or holding the lock across it
// would deadlock.
//
// Interface-version correlation is deliberately NOT done here, and this is now
// confirmed faithful (docs/tech-debt.md TD-15, RESOLVED): a real CommonAPI-SomeIP
// proxy (3.2.4 Connection::handleProxyReceive) correlates a Response by session
// alone and never reads its Interface Version, and vsomeip's on_message dispatches
// a Response by (service, instance, method) with no version gate — so nothing in
// the real DUT-as-client stack drops a correctly session-correlated Response on a
// major mismatch. Folding a version drop in here would fit the harness to a
// property real middleware does not have. Session correlation alone is well-founded
// — the request-id is the canonical Response-to-Request key.
class ResponseCorrelation {
public:
    // (service, instance, method) — the key a Response is matched under, the same
    // triple onResponse() and callMethod() name.
    using Key = std::tuple<std::uint16_t, std::uint16_t, std::uint16_t>;

    // Send an MT_REQUEST and record its vsomeip-assigned Session ID as one atomic
    // step w.r.t. acceptResponse(). `send` performs the send and returns the
    // session vsomeip stamped on the message; it runs under the correlation lock,
    // so a Response for that session cannot be accepted before the record lands
    // (see ORDERING above). Call only for MT_REQUEST — Fire & Forget
    // (MT_REQUEST_NO_RETURN) elicits no Response, so it is sent outside this path
    // and never recorded. `send` MUST only enqueue, never block on the dispatch
    // thread.
    template <class SendReturningSession>
    void recordSent(const Key& key, SendReturningSession&& send) {
        std::lock_guard<std::mutex> lock(mutex_);
        insertLocked(key, send());
    }

    // Record a Session ID directly (no send) — the primitive recordSent() and the
    // unit tests build on. Recording the same session twice for a key is a no-op;
    // two DISTINCT outstanding Requests that (after a full 16-bit session wrap)
    // reused one number would collapse to a single correlation, an accepted limit
    // at ~65535 in flight to one method — far beyond conformance's one-shot use.
    void recordRequest(const Key& key, std::uint16_t session) {
        std::lock_guard<std::mutex> lock(mutex_);
        insertLocked(key, session);
    }

    // Return true if `session` matches an outstanding Request for `key`, consuming
    // that correlation (one Response per Request). Return false if it does not — a
    // Response the DUT has no pending Request for, which the caller drops. An
    // unmatched session is exactly the wrong-Session-ID malformation the client
    // ignore property asserts the DUT rejects.
    //
    // NOTE: a recorded session is not expired on a timeout, so a correctly
    // sessioned but very-late Response is still accepted here — whereas a proxy
    // whose pending call already timed out would ignore it. Not modelled because
    // the per-case deadline (the SCXML verdict) is the timeout authority; add
    // time-based eviction here only if a case needs the raw client to enforce it.
    bool acceptResponse(const Key& key, std::uint16_t session) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = pending_.find(key);
        if (it == pending_.end()) return false;
        auto removed = it->second.erase(session);
        if (removed == 0) return false;
        if (it->second.empty()) pending_.erase(it);
        return true;
    }

private:
    // Caller holds mutex_ (recordSent holds it across the send; recordRequest
    // takes it directly). Single insertion point so both record paths agree.
    void insertLocked(const Key& key, std::uint16_t session) {
        pending_[key].insert(session);
    }

    std::mutex mutex_;
    std::map<Key, std::set<std::uint16_t>> pending_;
};

}  // namespace tc8::dut
