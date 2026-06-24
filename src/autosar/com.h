#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <utility>
#include <vector>

namespace tc8::com {

// AUTOSAR COM signal byte order (ComSignalEndianness). Little endian numbers bits
// LSb-first in a linear bit stream; big endian (Motorola) numbers them MSb-first
// in the "sawtooth" convention, where start_bit is the signal MSB and the
// network bit number is 8*(s/8) + (7 - s%8) (AUTOSAR ComBitPosition / DBC).
enum class Endianness { kBig, kLittle };

// AUTOSAR COM transmission mode (ComTxModeMode). Carried as config for the module
// that schedules transmission; the packing engine itself does not time anything.
enum class SendType { kCyclic, kOnChange, kCyclicAndOnChange };

// One signal's placement inside an I-PDU. All fields are injected OEM config; the
// packing mechanism is the public standard. bit_size is 1..64 (integer signals);
// start_bit is the LSb position (little endian) or the sawtooth MSb position
// (big endian).
struct SignalDef {
    std::uint32_t id;
    std::size_t   start_bit;
    std::size_t   bit_size;
    Endianness    endian;
};

// One I-PDU: a fixed-length byte buffer carrying its signals, plus the cyclic
// transmission timing the owning module uses to schedule sends.
struct PduDef {
    std::uint32_t             id;
    std::size_t               length;  // bytes
    std::chrono::milliseconds cycle;
    std::chrono::milliseconds start_delay;
    SendType                  send_type;
    std::vector<SignalDef>    signals;
};

// AUTOSAR COM signal packing/unpacking (SWS COM). Holds the PDU/signal database
// (injected OEM config), packs set signal values into an I-PDU buffer, and
// unpacks received I-PDUs back into signal values. Integer signals up to 64 bits;
// the value is masked to bit_size. The cyclic send timing lives in the config for
// the module's scheduler — this engine is the byte-layout mechanism only.
class SignalEngine {
public:
    // Throws std::invalid_argument on a malformed database: a duplicate signal or
    // PDU id, bit_size outside 1..64, or a signal whose bits fall outside its PDU.
    explicit SignalEngine(std::vector<PduDef> db);

    // Set the value a later packPdu() will write for this signal (default 0).
    void setSignal(std::uint32_t sig_id, std::uint64_t value);

    // Pack every signal of the PDU into a freshly zeroed length-byte buffer.
    std::vector<std::uint8_t> packPdu(std::uint32_t pdu_id) const;

    // Extract every signal of the PDU from `pdu` into the last-received store.
    // `len` must be at least the PDU length.
    void unpackInto(std::uint32_t pdu_id, const std::uint8_t* pdu, std::size_t len);

    // The value most recently unpacked for this signal, or empty if never seen.
    std::optional<std::uint64_t> lastReceived(std::uint32_t sig_id) const;

private:
    std::map<std::uint32_t, PduDef>                                pdus_;
    std::map<std::uint32_t, std::pair<std::uint32_t, std::size_t>> sig_index_;  // sig -> (pdu, idx)
    std::map<std::uint32_t, std::uint64_t>                         tx_values_;
    std::map<std::uint32_t, std::uint64_t>                         rx_values_;
};

}  // namespace tc8::com
