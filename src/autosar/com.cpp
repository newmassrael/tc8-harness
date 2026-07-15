#include "tc8/autosar/com.h"

#include <algorithm>
#include <stdexcept>

namespace tc8::com {
namespace {

// Physical (byte, bit-in-byte) of an absolute bit position in the buffer.
struct BitRef {
    std::size_t byte;
    std::uint8_t mask;
};

// Little endian numbers bits linearly, LSb of byte 0 = position 0.
BitRef littleBit(std::size_t pos) {
    return {pos / 8, static_cast<std::uint8_t>(1U << (pos % 8))};
}

// Big endian (Motorola) maps a "network" bit number to the physical byte/bit via
// the sawtooth: network 0 is the MSb of byte 0. (cantools sawtooth_to_network.)
BitRef bigBit(std::size_t network) {
    return {network / 8, static_cast<std::uint8_t>(1U << (7 - (network % 8)))};
}

// Network bit number of a big-endian signal's MSb from its sawtooth start bit.
std::size_t sawtoothToNetwork(std::size_t start_bit) {
    return 8 * (start_bit / 8) + (7 - (start_bit % 8));
}

std::uint64_t maskFor(std::size_t bit_size) {
    return bit_size >= 64 ? ~0ULL : ((1ULL << bit_size) - 1ULL);
}

// The buffer bit each signal bit k (0 = LSb of the value) occupies.
BitRef signalBit(const SignalDef& sig, std::size_t k) {
    if (sig.endian == Endianness::kLittle) {
        return littleBit(sig.start_bit + k);
    }
    // Big endian: the MSb (k = bit_size-1) sits at the network start; less
    // significant bits run to higher network numbers.
    const std::size_t network = sawtoothToNetwork(sig.start_bit) + (sig.bit_size - 1 - k);
    return bigBit(network);
}

// Highest buffer byte a signal touches, for bounds checking against the PDU.
std::size_t maxByte(const SignalDef& sig) {
    std::size_t hi = 0;
    for (std::size_t k = 0; k < sig.bit_size; ++k) {
        hi = std::max(hi, signalBit(sig, k).byte);
    }
    return hi;
}

}  // namespace

SignalEngine::SignalEngine(std::vector<PduDef> db) {
    for (PduDef& pdu : db) {
        if (pdus_.count(pdu.id) != 0) {
            throw std::invalid_argument("tc8::com::SignalEngine: duplicate PDU id");
        }
        for (std::size_t i = 0; i < pdu.signals.size(); ++i) {
            const SignalDef& sig = pdu.signals[i];
            if (sig.bit_size == 0 || sig.bit_size > 64) {
                throw std::invalid_argument("tc8::com::SignalEngine: signal bit_size must be 1..64");
            }
            if (maxByte(sig) >= pdu.length) {
                throw std::invalid_argument("tc8::com::SignalEngine: signal exceeds PDU length");
            }
            if (sig_index_.count(sig.id) != 0) {
                throw std::invalid_argument("tc8::com::SignalEngine: duplicate signal id");
            }
            sig_index_[sig.id] = {pdu.id, i};
        }
        pdus_[pdu.id] = std::move(pdu);
    }
}

void SignalEngine::setSignal(std::uint32_t sig_id, std::uint64_t value) {
    const auto it = sig_index_.find(sig_id);
    if (it == sig_index_.end()) {
        throw std::invalid_argument("tc8::com::SignalEngine::setSignal: unknown signal id");
    }
    tx_values_[sig_id] = value;
}

bool SignalEngine::hasSignal(std::uint32_t sig_id) const {
    return sig_index_.find(sig_id) != sig_index_.end();
}

std::size_t SignalEngine::signalWidth(std::uint32_t sig_id) const {
    const auto it = sig_index_.find(sig_id);
    if (it == sig_index_.end()) {
        return 0;
    }
    const PduDef& pdu = pdus_.at(it->second.first);
    const std::size_t bits = pdu.signals[it->second.second].bit_size;
    return (bits + 7u) / 8u;  // ceil(bit_size / 8)
}

std::vector<std::uint32_t> SignalEngine::pduSignals(std::uint32_t pdu_id) const {
    const auto it = pdus_.find(pdu_id);
    if (it == pdus_.end()) {
        return {};
    }
    std::vector<std::uint32_t> ids;
    ids.reserve(it->second.signals.size());
    for (const SignalDef& sig : it->second.signals) {
        ids.push_back(sig.id);
    }
    return ids;
}

std::size_t SignalEngine::pduLength(std::uint32_t pdu_id) const {
    const auto it = pdus_.find(pdu_id);
    return it == pdus_.end() ? 0 : it->second.length;
}

std::vector<std::uint8_t> SignalEngine::packPdu(std::uint32_t pdu_id) const {
    const auto it = pdus_.find(pdu_id);
    if (it == pdus_.end()) {
        throw std::invalid_argument("tc8::com::SignalEngine::packPdu: unknown PDU id");
    }
    const PduDef& pdu = it->second;
    std::vector<std::uint8_t> buf(pdu.length, 0x00);
    for (const SignalDef& sig : pdu.signals) {
        const auto vit = tx_values_.find(sig.id);
        const std::uint64_t value = (vit == tx_values_.end() ? 0ULL : vit->second) & maskFor(sig.bit_size);
        for (std::size_t k = 0; k < sig.bit_size; ++k) {
            if ((value >> k) & 1ULL) {
                const BitRef ref = signalBit(sig, k);
                buf[ref.byte] = static_cast<std::uint8_t>(buf[ref.byte] | ref.mask);
            }
        }
    }
    return buf;
}

void SignalEngine::unpackInto(std::uint32_t pdu_id, const std::uint8_t* pdu, std::size_t len) {
    const auto it = pdus_.find(pdu_id);
    if (it == pdus_.end()) {
        throw std::invalid_argument("tc8::com::SignalEngine::unpackInto: unknown PDU id");
    }
    const PduDef& def = it->second;
    if (len < def.length) {
        throw std::invalid_argument("tc8::com::SignalEngine::unpackInto: buffer shorter than PDU");
    }
    for (const SignalDef& sig : def.signals) {
        std::uint64_t value = 0;
        for (std::size_t k = 0; k < sig.bit_size; ++k) {
            const BitRef ref = signalBit(sig, k);
            if (pdu[ref.byte] & ref.mask) {
                value |= (1ULL << k);
            }
        }
        rx_values_[sig.id] = value;
    }
}

std::optional<std::uint64_t> SignalEngine::lastReceived(std::uint32_t sig_id) const {
    const auto it = rx_values_.find(sig_id);
    if (it == rx_values_.end()) {
        return std::nullopt;
    }
    return it->second;
}

}  // namespace tc8::com
