#pragma once

#include <cstddef>
#include <cstdint>

namespace tc8::e2e {

// Receiver-side verdict of an E2E check (subset of AUTOSAR E2E_PCheckStatusType).
// The per-message check produces these four; timeout / no-data status belongs to
// the higher module layer that drives the check, not to the check itself.
enum class CheckStatus {
    kOk,             // CRC valid and the counter advanced within the allowed delta
    kRepeated,       // CRC valid but the counter did not advance (duplicate frame)
    kWrongSequence,  // CRC valid but the counter jumped further than max_delta_counter
    kError,          // CRC mismatch — the data is corrupt
};

// AUTOSAR FO PRS E2EProtocol Profile 5: CRC-16/CCITT-FALSE, an 8-bit counter, and
// a 16-bit Data ID. The 3-byte E2E header sits at byte `offset` within the PDU —
// CRC (little-endian) at offset+0..1, counter at offset+2. The Data ID is never
// transmitted; it is mixed into the CRC so a receiver with the wrong Data ID sees
// a CRC error. data_id / offset / max_delta_counter are injected OEM config; the
// CRC math and header layout are the public standard.
struct Profile05Config {
    std::uint16_t data_id;
    std::size_t   offset;             // byte offset of the E2E header in the PDU
    std::uint8_t  max_delta_counter;  // largest tolerated counter gap on the receiver
};

// Sender side. Holds the counter as state (AUTOSAR E2E_PProtectStateType): each
// protect() advances it, so the caller may pass a fresh buffer every cycle.
class Profile05Protector {
public:
    explicit Profile05Protector(Profile05Config config);

    // Advance the counter, compute the CRC over the data and Data ID, and write
    // the counter and CRC into the header. `len` must cover the header
    // (offset + 3) or std::invalid_argument is thrown.
    void protect(std::uint8_t* data, std::size_t len);

private:
    Profile05Config config_;
    std::uint8_t counter_;
};

// Receiver side. Tracks the last accepted counter to classify the sequence.
class Profile05Checker {
public:
    explicit Profile05Checker(Profile05Config config);

    // Verify the CRC and classify the counter progression. `len` must cover the
    // header (offset + 3) or std::invalid_argument is thrown.
    CheckStatus check(const std::uint8_t* data, std::size_t len);

private:
    Profile05Config config_;
    std::uint8_t last_counter_;
    bool have_last_;
};

}  // namespace tc8::e2e
