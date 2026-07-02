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
// PURE POLICY — vsomeip-free and self-synchronised: recordRequest() runs on the
// caller's send thread while acceptResponse() runs on a vsomeip dispatch thread,
// so the class owns its own mutex and VsomeipEtsClientControl shares one instance
// by shared_ptr (the receive-side capture is a strong copy, so an enqueued
// message callback that outlives the control never touches a dead object). The
// decision is unit-tested hermetically with plain integers.
//
// Interface-version correlation is deliberately NOT done here. vsomeip does not
// version-check incoming Responses, and whether a proxy rejects a correctly
// session-correlated Response on major-version mismatch is unconfirmed; folding a
// version drop in here would risk fitting a property real middleware may not have
// (see docs/tech-debt.md TD-15). Session correlation alone is well-founded — the
// request-id is the canonical Response-to-Request key.
class ResponseCorrelation {
public:
    // (service, instance, method) — the key a Response is matched under, the same
    // triple onResponse() and callMethod() name.
    using Key = std::tuple<std::uint16_t, std::uint16_t, std::uint16_t>;

    // Record the Session ID vsomeip assigned to an outgoing MT_REQUEST. Call once
    // per Request, AFTER send stamps the session on the message. Fire & Forget
    // (MT_REQUEST_NO_RETURN) is never recorded: it elicits no Response, so there is
    // nothing to correlate. Recording the same session twice for a key is a no-op.
    void recordRequest(const Key& key, std::uint16_t session) {
        std::lock_guard<std::mutex> lock(mutex_);
        pending_[key].insert(session);
    }

    // Return true if `session` matches an outstanding Request for `key`, consuming
    // that correlation (one Response per Request). Return false if it does not — a
    // Response the DUT has no pending Request for, which the caller drops. An
    // unmatched session is exactly the wrong-Session-ID malformation the client
    // ignore property asserts the DUT rejects.
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
    std::mutex mutex_;
    std::map<Key, std::set<std::uint16_t>> pending_;
};

}  // namespace tc8::dut
