#pragma once

#include <cstdint>
#include <optional>
#include <vector>

namespace tc8::dut {

// The field-access facade: an extension reads and sets the value of a field the
// DUT serves from the public interface, so an extension that serves the field's
// methods itself (an OEM superset interface's getter or set methods for the same
// field) keeps no second store. One store means a set through the public setter is
// what the extension's getter returns, and a suspendInterface re-offer republishes
// the value the extension set.
//
// Segregated from the event sink (IEtsEventSink offers and notifies events the
// extension owns) because these fields are the DUT's: their identifiers,
// deployment and initial values stay in the public interface, and the extension
// reaches only their values. It reaches the primary instance (SERVICE-ID-1,
// instance 1).
//
// Only fields an extension has asked for have accessors (TestFieldUINT8Array, for an
// extension serving the setUINT8Array methods). The calls are safe from any thread:
// they take the attribute's own lock, as a remote get or set does.
class IEtsFieldAccess {
public:
    virtual ~IEtsFieldAccess() = default;

    // TestFieldUINT8Array (getter 0x28, setter 0x29, notifier 0x8007): the stored
    // value, as a get without the getter fault returns it. Nullopt when the DUT
    // serves no field (the client-only topology offers no service).
    virtual std::optional<std::vector<std::uint8_t>> testFieldUint8Array() const = 0;

    // Store `value` as a remote set through 0x29 does: 0x8007 notifies when the value
    // changed and stays quiet when it did not. False when the DUT serves no field.
    virtual bool setTestFieldUint8Array(std::vector<std::uint8_t> value) = 0;
};

// The facade of a DUT that serves no field: the client-only topology, and a test
// that hands an extension a context without a server.
class NoFieldAccess final : public IEtsFieldAccess {
public:
    std::optional<std::vector<std::uint8_t>> testFieldUint8Array() const override { return std::nullopt; }
    bool setTestFieldUint8Array(std::vector<std::uint8_t> /*value*/) override { return false; }
};

}  // namespace tc8::dut
