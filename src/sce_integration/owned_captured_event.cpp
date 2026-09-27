#include "sce_integration/owned_captured_event.h"

#include <type_traits>
#include <variant>

namespace tc8::sce {

namespace {

// The borrowed regions are listed per frame type, by hand, because C++17 cannot
// enumerate a struct's members. Two things keep the list honest:
//   - a variant alternative with no overload below fails to compile (the visitor
//     has no generic fallback), so a new protocol cannot be held unowned;
//   - a pointer added to an EXISTING frame always grows it (an 8-byte member never
//     fits in tail padding smaller than the struct's 8-byte alignment), so the
//     sizes pinned here fail the build at exactly that moment. A non-pointer field
//     trips them too; that is a false alarm, and the cost of it is reading this
//     list once and updating a number.
static_assert(sizeof(void *) == 8, "the frame sizes below were measured on LP64");
static_assert(sizeof(::tc8::ArpFrame) == 64,
              "ArpFrame changed: review whether it now borrows bytes (owned_captured_event.cpp)");
static_assert(sizeof(::tc8::Icmpv4Frame) == 56,
              "Icmpv4Frame changed: review its borrowed regions (owned_captured_event.cpp)");
static_assert(sizeof(::tc8::Ipv4Frame) == 56,
              "Ipv4Frame changed: review its borrowed regions (owned_captured_event.cpp)");
static_assert(sizeof(::tc8::UdpFrame) == 64,
              "UdpFrame changed: review its borrowed regions (owned_captured_event.cpp)");
static_assert(sizeof(::tc8::Dhcpv4Frame) == 112,
              "Dhcpv4Frame changed: review its borrowed regions (owned_captured_event.cpp)");
static_assert(sizeof(::tc8::TcpFrame) == 80,
              "TcpFrame changed: review its borrowed regions (owned_captured_event.cpp)");
static_assert(sizeof(::tc8::SomeIpFrame) == 64,
              "SomeIpFrame changed: review its borrowed regions (owned_captured_event.cpp)");

class Owner {
public:
    explicit Owner(std::vector<std::vector<std::uint8_t>> &storage) : storage_(storage) {}

    void operator()(::tc8::ArpFrame &) const {}
    void operator()(::tc8::Icmpv4Frame &f) const { own(f.payload_data, f.payload_len); }
    void operator()(::tc8::Ipv4Frame &f) const { own(f.options_data, f.options_len); }
    void operator()(::tc8::UdpFrame &f) const { own(f.payload_data, f.payload_len); }
    void operator()(::tc8::Dhcpv4Frame &f) const { own(f.options_data, f.options_len); }
    void operator()(::tc8::TcpFrame &f) const {
        own(f.options_data, f.options_len);
        own(f.payload_data, f.payload_len);
    }
    void operator()(::tc8::SomeIpFrame &f) const { own(f.payload_data, f.payload_len); }

private:
    // Copies [data, data+len) into a buffer this event owns and repoints `data`
    // at it. A null or empty region stays exactly as it was: null means "absent"
    // to the frame's readers, and repointing it at an empty buffer would change
    // that answer.
    void own(const std::uint8_t *&data, std::uint32_t len) const {
        if (data == nullptr || len == 0U) {
            return;
        }
        storage_.emplace_back(data, data + len);
        data = storage_.back().data();
    }

    std::vector<std::vector<std::uint8_t>> &storage_;
};

}  // namespace

OwnedCapturedEvent::OwnedCapturedEvent(const ::tc8::CapturedEvent &ev) : event_(ev) {
    // Reserve first: a reallocation of the outer vector would MOVE the inner
    // buffers (keeping their addresses), but reserving makes that independent of
    // the standard library's growth policy. Two regions at most, in TcpFrame.
    storage_.reserve(2);
    std::visit(Owner{storage_}, event_);
}

}  // namespace tc8::sce
