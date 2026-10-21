#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "ets_event_sink.h"
#include "ets_reply.h"
#include "tc8/someip/protocol.h"

namespace tc8::dut {

// A dynamic UTF-8 string FIELD the ETS service serves through the IEtsEventSink seam: a
// getter, a setter whose Response carries the stored value, and a notifier that fires when
// the stored value changes. The ids are the caller's, so the component carries no vendor
// id; an extension binds it to the ids its own interface definition fixes (see
// docs/ets_dut_extension_seams.md).
//
// WIRE SHAPE. The payload is the one echoUTF8DYNAMIC uses: a 32-bit big-endian byte length,
// then the UTF-8 byte-order mark (EF BB BF), the characters, and one trailing NUL; the
// length counts everything after itself. The string a caller sets and reads back is the
// characters only, without BOM or NUL.
//
// WHAT A SETTER REQUEST DOES. A well-formed request stores the value, answers a Response
// with E_OK carrying the stored value, and notifies the notifier when the value differs
// from the one it replaces (a field notifies on change). A malformed request (length that
// disagrees with the payload, missing BOM, missing or interior NUL) answers an Error with
// E_MALFORMED_MESSAGE, stores nothing and notifies nothing. The getter answers the stored
// value whatever its request carries.
//
// RELIABILITY. The component is transport-blind: a Request arriving over TCP is answered
// on that connection by the stack, and a Notification reaches a subscriber over the
// transport that subscriber's SubscribeEventgroup named.

// Encode `chars` as the dynamic UTF-8 string payload.
inline std::vector<std::uint8_t> encodeUtf8Dynamic(const std::string& chars) {
    const std::uint32_t body = static_cast<std::uint32_t>(3 + chars.size() + 1);
    std::vector<std::uint8_t> out;
    out.reserve(4 + body);
    out.push_back(static_cast<std::uint8_t>(body >> 24));
    out.push_back(static_cast<std::uint8_t>(body >> 16));
    out.push_back(static_cast<std::uint8_t>(body >> 8));
    out.push_back(static_cast<std::uint8_t>(body));
    out.push_back(0xEF);
    out.push_back(0xBB);
    out.push_back(0xBF);
    out.insert(out.end(), chars.begin(), chars.end());
    out.push_back(0x00);
    return out;
}

// Decode a dynamic UTF-8 string payload to its characters, or nullopt when malformed.
inline std::optional<std::string> decodeUtf8Dynamic(const std::vector<std::uint8_t>& p) {
    if (p.size() < 4 + 3 + 1) return std::nullopt;
    const std::uint32_t body = (static_cast<std::uint32_t>(p[0]) << 24) |
                               (static_cast<std::uint32_t>(p[1]) << 16) |
                               (static_cast<std::uint32_t>(p[2]) << 8) |
                               static_cast<std::uint32_t>(p[3]);
    if (body != p.size() - 4) return std::nullopt;
    if (p[4] != 0xEF || p[5] != 0xBB || p[6] != 0xBF) return std::nullopt;
    if (p.back() != 0x00) return std::nullopt;
    const auto first = p.begin() + 7;
    const auto last = p.end() - 1;
    for (auto it = first; it != last; ++it) {
        if (*it == 0x00) return std::nullopt;
    }
    return std::string(first, last);
}

// The stored value and the rule for changing it. Thread-safe: the request handlers run on
// vsomeip threads. The notification is issued under the same lock as the store, so
// notifications reach the stack in the order the values were stored.
class Utf8DynamicField {
public:
    // Called with the encoded payload each time the stored value changes.
    using Notifier = std::function<void(const std::vector<std::uint8_t>&)>;

    Utf8DynamicField(std::string initial, Notifier notifier)
        : value_(std::move(initial)), notifier_(std::move(notifier)) {}

    std::string value() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return value_;
    }

    EtsReply get() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return response(value_);
    }

    EtsReply set(const std::vector<std::uint8_t>& request) {
        auto chars = decodeUtf8Dynamic(request);
        if (!chars) {
            return EtsReply{someip::MessageType::ERROR,
                            someip::ReturnCode::E_MALFORMED_MESSAGE, {}};
        }
        std::lock_guard<std::mutex> lock(mutex_);
        if (*chars != value_) {
            value_ = std::move(*chars);
            if (notifier_) notifier_(encodeUtf8Dynamic(value_));
        }
        return response(value_);
    }

    // Put the value back without notifying: for the owner's reset to defaults, which is
    // not a change the field announces.
    void reset(std::string value) {
        std::lock_guard<std::mutex> lock(mutex_);
        value_ = std::move(value);
    }

private:
    static EtsReply response(const std::string& chars) {
        return EtsReply{someip::MessageType::RESPONSE, someip::ReturnCode::E_OK,
                        encodeUtf8Dynamic(chars)};
    }

    mutable std::mutex mutex_;
    std::string value_;
    Notifier notifier_;
};

struct StringFieldIds {
    std::uint16_t getter;
    std::uint16_t setter;
    std::uint16_t notifier;
    std::vector<std::uint16_t> eventgroups;
};

// Serve a dynamic UTF-8 string field on `sink`: offer the notifier as a field (so a
// subscriber receives the current value on its SubscribeEventgroupAck), seed it with
// `initial`, and register the getter and setter. Returns the field, which the caller keeps
// to read or reset the value; the registered handlers share ownership of it. `sink` must
// outlive the handlers, as for every sink registration.
inline std::shared_ptr<Utf8DynamicField> serveUtf8DynamicField(
    IEtsEventSink& sink, const StringFieldIds& ids, std::string initial = {}) {
    IEtsEventSink* const s = &sink;
    const std::uint16_t notifier = ids.notifier;
    auto field = std::make_shared<Utf8DynamicField>(
        initial, [s, notifier](const std::vector<std::uint8_t>& payload) {
            s->notify(notifier, payload);
        });
    sink.offerField(ids.notifier, ids.eventgroups);
    sink.notify(ids.notifier, encodeUtf8Dynamic(initial));
    sink.onRequestEx(ids.getter, [field](const std::vector<std::uint8_t>&) {
        return field->get();
    });
    sink.onRequestEx(ids.setter, [field](const std::vector<std::uint8_t>& request) {
        return field->set(request);
    });
    return field;
}

}  // namespace tc8::dut
