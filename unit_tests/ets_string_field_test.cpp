#include "ets_string_field.h"

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace tc8::dut {
namespace {

using Bytes = std::vector<std::uint8_t>;

// Synthetic ids, outside every public ETS range: the component takes ids from its caller.
const StringFieldIds kIds{0x0701, 0x0702, 0x8701, {0x00F1, 0x00F2}};

// Records what the field asks of the sink, and lets a test drive the registered handlers.
class RecordingSink : public IEtsEventSink {
public:
    struct Offer {
        bool field;
        std::uint16_t event_id;
        std::vector<std::uint16_t> eventgroups;
    };
    struct Notification {
        std::uint16_t event_id;
        Bytes payload;
    };

    void offerEvent(std::uint16_t id, const std::vector<std::uint16_t>& egs) override {
        offers.push_back({false, id, egs});
    }
    void offerField(std::uint16_t id, const std::vector<std::uint16_t>& egs) override {
        offers.push_back({true, id, egs});
    }
    void notify(std::uint16_t id, const Bytes& payload) override {
        notifications.push_back({id, payload});
    }
    void onMethod(std::uint16_t, std::function<void(const Bytes&)>) override {}
    void onRequestEx(std::uint16_t id, std::function<EtsReply(const Bytes&)> h) override {
        handlers[id] = std::move(h);
    }

    EtsReply request(std::uint16_t method, const Bytes& payload) {
        return handlers.at(method)(payload);
    }

    std::vector<Offer> offers;
    std::vector<Notification> notifications;
    std::map<std::uint16_t, std::function<EtsReply(const Bytes&)>> handlers;
};

Bytes wire(const std::string& chars) { return encodeUtf8Dynamic(chars); }

TEST(Utf8DynamicCodec, EncodesLengthBomCharactersAndNul) {
    EXPECT_EQ(wire("hi"), (Bytes{0, 0, 0, 6, 0xEF, 0xBB, 0xBF, 'h', 'i', 0}));
    EXPECT_EQ(wire(""), (Bytes{0, 0, 0, 4, 0xEF, 0xBB, 0xBF, 0}));
}

TEST(Utf8DynamicCodec, DecodesWhatItEncodes) {
    for (const char* s : {"", "a", "hello", "\xEA\xB0\x80\xEB\x82\x98"}) {
        EXPECT_EQ(decodeUtf8Dynamic(wire(s)), std::string(s));
    }
}

TEST(Utf8DynamicCodec, RejectsEachMalformedShape) {
    EXPECT_FALSE(decodeUtf8Dynamic({}));                                      // empty
    EXPECT_FALSE(decodeUtf8Dynamic({0, 0, 0, 3, 0xEF, 0xBB, 0xBF}));          // no NUL
    EXPECT_FALSE(decodeUtf8Dynamic({0, 0, 0, 7, 0xEF, 0xBB, 0xBF, 'h', 'i', 0}));  // too long
    EXPECT_FALSE(decodeUtf8Dynamic({0, 0, 0, 5, 0xEF, 0xBB, 0xBF, 'h', 'i', 0}));  // too short
    EXPECT_FALSE(decodeUtf8Dynamic({0, 0, 0, 6, 0xEF, 0xBB, 0xBE, 'h', 'i', 0}));  // wrong BOM
    EXPECT_FALSE(decodeUtf8Dynamic({0, 0, 0, 6, 0xEF, 0xBB, 0xBF, 'h', 'i', 'x'}));  // no NUL
    EXPECT_FALSE(decodeUtf8Dynamic({0, 0, 0, 7, 0xEF, 0xBB, 0xBF, 'h', 0, 'i', 0}));  // interior NUL
}

TEST(Utf8DynamicField, ServingOffersTheNotifierAsAFieldAndSeedsIt) {
    RecordingSink sink;
    serveUtf8DynamicField(sink, kIds, "init");
    ASSERT_EQ(sink.offers.size(), 1u);
    EXPECT_TRUE(sink.offers[0].field);
    EXPECT_EQ(sink.offers[0].event_id, 0x8701);
    EXPECT_EQ(sink.offers[0].eventgroups, (std::vector<std::uint16_t>{0x00F1, 0x00F2}));
    ASSERT_EQ(sink.notifications.size(), 1u);
    EXPECT_EQ(sink.notifications[0].event_id, 0x8701);
    EXPECT_EQ(sink.notifications[0].payload, wire("init"));
}

TEST(Utf8DynamicField, GetterAnswersTheStoredValueAsAResponse) {
    RecordingSink sink;
    serveUtf8DynamicField(sink, kIds, "init");
    const EtsReply r = sink.request(kIds.getter, {});
    EXPECT_EQ(r.message_type, someip::MessageType::RESPONSE);
    EXPECT_EQ(r.return_code, someip::ReturnCode::E_OK);
    EXPECT_EQ(r.payload, wire("init"));
}

TEST(Utf8DynamicField, SetterStoresRepliesWithTheStoredValueAndNotifiesOnce) {
    RecordingSink sink;
    auto field = serveUtf8DynamicField(sink, kIds, "init");
    sink.notifications.clear();

    const EtsReply r = sink.request(kIds.setter, wire("new value"));
    EXPECT_EQ(r.message_type, someip::MessageType::RESPONSE);
    EXPECT_EQ(r.return_code, someip::ReturnCode::E_OK);
    EXPECT_EQ(r.payload, wire("new value"));
    EXPECT_EQ(field->value(), "new value");
    ASSERT_EQ(sink.notifications.size(), 1u);
    EXPECT_EQ(sink.notifications[0].event_id, 0x8701);
    EXPECT_EQ(sink.notifications[0].payload, wire("new value"));

    // The getter now reads what the setter stored.
    EXPECT_EQ(sink.request(kIds.getter, {}).payload, wire("new value"));
}

TEST(Utf8DynamicField, SettingTheValueItAlreadyHasRepliesButDoesNotNotify) {
    RecordingSink sink;
    serveUtf8DynamicField(sink, kIds, "same");
    sink.notifications.clear();
    const EtsReply r = sink.request(kIds.setter, wire("same"));
    EXPECT_EQ(r.return_code, someip::ReturnCode::E_OK);
    EXPECT_EQ(r.payload, wire("same"));
    EXPECT_TRUE(sink.notifications.empty());
}

TEST(Utf8DynamicField, AMalformedSetterRequestIsAnErrorThatChangesNothing) {
    RecordingSink sink;
    auto field = serveUtf8DynamicField(sink, kIds, "keep");
    sink.notifications.clear();

    const EtsReply r = sink.request(kIds.setter, Bytes{0, 0, 0, 9, 0xEF, 0xBB, 0xBF, 'x', 0});
    EXPECT_EQ(r.message_type, someip::MessageType::ERROR);
    EXPECT_EQ(r.return_code, someip::ReturnCode::E_MALFORMED_MESSAGE);
    EXPECT_TRUE(r.payload.empty());
    EXPECT_EQ(field->value(), "keep");
    EXPECT_TRUE(sink.notifications.empty());
}

TEST(Utf8DynamicField, ResetPutsTheDefaultBackWithoutAnnouncingIt) {
    RecordingSink sink;
    auto field = serveUtf8DynamicField(sink, kIds, "default");
    sink.request(kIds.setter, wire("changed"));
    sink.notifications.clear();
    field->reset("default");
    EXPECT_EQ(sink.request(kIds.getter, {}).payload, wire("default"));
    EXPECT_TRUE(sink.notifications.empty());
}

}  // namespace
}  // namespace tc8::dut
