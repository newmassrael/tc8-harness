#pragma once

#include <cstdint>
#include <map>
#include <mutex>
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
// decision is unit-tested hermetically with plain integers, in both modes.
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
// Interface-version correlation is an OPT-IN strict mode (constructor flag; see
// docs/tech-debt.md TD-15). By DEFAULT (flag false) only the session is
// correlated — matching a stock CommonAPI-SomeIP proxy, which never re-checks a
// session-correlated Response's Interface Version (major). With the flag SET, a
// Response whose major differs from its Request's is ALSO dropped, so the pending
// call aborts by timeout. The strict mode exists for conformance profiles that
// require a client to ignore a wrong-Interface-Version Response; the specific
// requirement and its provenance live with those profiles, off this public core.
// The raw client injects the flag from an env gate, so this class stays a pure,
// vsomeip-free policy testable in either mode. The request-id (client + session)
// is the primary Response-to-Request key in both modes.
class ResponseCorrelation {
public:
    // `strict_interface_version`: when true, acceptResponse() also drops a
    // session-correlated Response whose major does not match its Request's; when
    // false (the stock default), the major is recorded but not enforced.
    explicit ResponseCorrelation(bool strict_interface_version)
        : strict_interface_version_(strict_interface_version) {}

    // (service, instance, method) — the key a Response is matched under, the same
    // triple onResponse() and callMethod() name.
    using Key = std::tuple<std::uint16_t, std::uint16_t, std::uint16_t>;

    // Send an MT_REQUEST and record its vsomeip-assigned Session ID paired with the
    // Request's `major`, as one atomic step w.r.t. acceptResponse(). `send`
    // performs the send and returns the session vsomeip stamped on the message; it
    // runs under the correlation lock, so a Response for that session cannot be
    // accepted before the record lands (see ORDERING above). Call only for
    // MT_REQUEST — Fire & Forget (MT_REQUEST_NO_RETURN) elicits no Response, so it
    // is sent outside this path and never recorded. `send` MUST only enqueue, never
    // block on the dispatch thread.
    template <class SendReturningSession>
    void recordSent(const Key& key, std::uint8_t major, SendReturningSession&& send) {
        std::lock_guard<std::mutex> lock(mutex_);
        insertLocked(key, send(), major);
    }

    // Record a Session ID with the Request's `major` directly (no send) — the
    // primitive recordSent() and the unit tests build on. Recording the same
    // session twice for a key is a no-op (the first major recorded is kept); two
    // DISTINCT outstanding Requests that (after a full 16-bit session wrap) reused
    // one number would collapse to a single correlation, an accepted limit at
    // ~65535 in flight to one method — far beyond conformance's one-shot use.
    void recordRequest(const Key& key, std::uint16_t session, std::uint8_t major) {
        std::lock_guard<std::mutex> lock(mutex_);
        insertLocked(key, session, major);
    }

    // Return true (deliver the reply) when `session` matches an outstanding Request
    // for `key` AND — in strict mode only — `response_major` equals that Request's
    // recorded major. Return false (the caller drops the reply) when:
    //   - no pending Request for `session` — the wrong-Session-ID malformation; a
    //     pending correlation under a different session is left intact.
    //   - strict mode, correct session, mismatched major — the wrong-Interface-
    //     Version malformation; the correlation is consumed (one Response per
    //     Request) and the reply dropped.
    // Either drop leaves the DUT's pending request to resolve to E_TIMEOUT, exactly
    // as a no-reply would. In the default (non-strict) mode the major is ignored,
    // matching a stock proxy.
    //
    // NOTE: a recorded session is not expired on a timeout, so a correctly
    // correlated but very-late Response is still accepted here — whereas a proxy
    // whose pending call already timed out would ignore it. Not modelled because
    // the per-case deadline (the SCXML verdict) is the timeout authority; add
    // time-based eviction here only if a case needs the raw client to enforce it.
    bool acceptResponse(const Key& key, std::uint16_t session, std::uint8_t response_major) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = pending_.find(key);
        if (it == pending_.end()) return false;
        auto sit = it->second.find(session);
        if (sit == it->second.end()) return false;  // no pending Request for this session (wrong-Session drop)
        const bool major_ok = !strict_interface_version_ || sit->second == response_major;
        it->second.erase(sit);                       // one Response per Request: consume the correlation
        if (it->second.empty()) pending_.erase(it);
        return major_ok;  // strict + wrong major -> drop; the pending call aborts by timeout
    }

private:
    // Caller holds mutex_ (recordSent holds it across the send; recordRequest takes
    // it directly). Single insertion point so both record paths agree. emplace
    // keeps the first major recorded for a session (a duplicate session is a no-op),
    // matching the wrap-collision note on recordRequest.
    void insertLocked(const Key& key, std::uint16_t session, std::uint8_t major) {
        pending_[key].emplace(session, major);
    }

    bool strict_interface_version_;
    std::mutex mutex_;
    std::map<Key, std::map<std::uint16_t /*session*/, std::uint8_t /*major*/>> pending_;
};

}  // namespace tc8::dut
