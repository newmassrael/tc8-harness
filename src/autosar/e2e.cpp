#include "autosar/e2e.h"

#include <stdexcept>
#include <vector>

#include "autosar/crc.h"

namespace tc8::e2e {
namespace {

constexpr std::size_t kP05HeaderLen = 3;   // CRC (2 bytes) + counter (1 byte)
constexpr std::size_t kP05CounterPos = 2;  // counter offset within the header
constexpr std::size_t kP11HeaderLen = 2;   // CRC (1 byte) + counter/nibble (1 byte)
constexpr std::uint8_t kP11CounterModulus = 15;  // P11 counter wraps 0..14 (mod 15)

// Shared receiver verdict given a CRC-valid frame and the counter step (already
// reduced to the profile's counter range). delta 0 = duplicate, within the
// allowed window = accepted (possibly some lost), beyond it = sequence break.
CheckStatus classifyCounter(std::uint8_t delta, std::uint8_t max_delta) {
    if (delta == 0) {
        return CheckStatus::kRepeated;
    }
    if (delta <= max_delta) {
        return CheckStatus::kOk;
    }
    return CheckStatus::kWrongSequence;
}

// Profile 5 CRC (FO PRS E2EProtocol): CRC-16/CCITT-FALSE over every data byte
// except the two CRC bytes, followed by the Data ID low byte then high byte. The
// counter byte IS covered; only the CRC field itself is excluded. Assembled into
// one contiguous buffer so the verified tc8::crc::crc16Ccitt computes it in a
// single pass (this is a test/UTM tool, not a hot embedded path).
std::uint16_t computeCrc(const std::uint8_t* data, std::size_t len, const Profile05Config& cfg) {
    std::vector<std::uint8_t> buf;
    buf.reserve(len);
    for (std::size_t i = 0; i < cfg.offset; ++i) {
        buf.push_back(data[i]);
    }
    for (std::size_t i = cfg.offset + kP05CounterPos; i < len; ++i) {
        buf.push_back(data[i]);
    }
    buf.push_back(static_cast<std::uint8_t>(cfg.data_id & 0xFFU));
    buf.push_back(static_cast<std::uint8_t>((cfg.data_id >> 8) & 0xFFU));
    // CCITT-FALSE has no final XOR, so one pass over the concatenation equals the
    // profile's chained Crc_CalculateCRC16 calls.
    return tc8::crc::crc16Ccitt(buf.data(), buf.size(), 0x0000, true);
}

}  // namespace

Profile05Protector::Profile05Protector(Profile05Config config)
    : config_(config), counter_(0) {}

void Profile05Protector::protect(std::uint8_t* data, std::size_t len) {
    if (len < config_.offset + kP05HeaderLen) {
        throw std::invalid_argument("tc8::e2e::Profile05Protector: PDU shorter than the E2E header");
    }
    counter_ = static_cast<std::uint8_t>(counter_ + 1);  // 8-bit wrap
    data[config_.offset + kP05CounterPos] = counter_;
    const std::uint16_t crc = computeCrc(data, len, config_);
    data[config_.offset] = static_cast<std::uint8_t>(crc & 0xFFU);             // low byte
    data[config_.offset + 1] = static_cast<std::uint8_t>((crc >> 8) & 0xFFU);  // high byte
}

Profile05Checker::Profile05Checker(Profile05Config config)
    : config_(config), last_counter_(0), have_last_(false) {}

CheckStatus Profile05Checker::check(const std::uint8_t* data, std::size_t len) {
    if (len < config_.offset + kP05HeaderLen) {
        throw std::invalid_argument("tc8::e2e::Profile05Checker: PDU shorter than the E2E header");
    }
    const std::uint16_t stored = static_cast<std::uint16_t>(
        data[config_.offset] | (static_cast<std::uint16_t>(data[config_.offset + 1]) << 8));
    if (stored != computeCrc(data, len, config_)) {
        return CheckStatus::kError;
    }
    const std::uint8_t rx = data[config_.offset + kP05CounterPos];
    if (!have_last_) {
        have_last_ = true;
        last_counter_ = rx;
        return CheckStatus::kOk;
    }
    const std::uint8_t delta = static_cast<std::uint8_t>(rx - last_counter_);  // 8-bit wrap
    last_counter_ = rx;
    return classifyCounter(delta, config_.max_delta_counter);
}

// ── Profile 11 ──

namespace {

constexpr std::uint8_t kP11CrcXor = 0xFF;  // SAE-J1850 XOR value (FO PRS P11 uses it)

// Profile 11 CRC (FO PRS E2EProtocol): CRC-8/SAE-J1850, computed as the profile
// specifies — the Data ID first (both bytes in BOTH mode; the low byte then a
// zero byte in NIBBLE mode), then the data before the CRC byte, then the data
// after it (so the counter/nibble byte at offset+1 is covered, the CRC byte is
// not). Each segment is a resumed Crc_CalculateCRC8 call (is_first_call = false,
// seeded with the SAE-J1850 XOR value), and the profile applies one more final
// XOR — a faithful transcription, not a single-shot shortcut.
std::uint8_t computeP11Crc(const std::uint8_t* data, std::size_t len, const Profile11Config& cfg) {
    const std::uint8_t id_lo = static_cast<std::uint8_t>(cfg.data_id & 0xFFU);
    const std::uint8_t id_hi = cfg.data_id_mode == DataIdMode::kBoth
                                   ? static_cast<std::uint8_t>((cfg.data_id >> 8) & 0xFFU)
                                   : static_cast<std::uint8_t>(0x00U);
    std::uint8_t crc = tc8::crc::crc8SaeJ1850(&id_lo, 1, kP11CrcXor, false);
    crc = tc8::crc::crc8SaeJ1850(&id_hi, 1, crc, false);
    if (cfg.offset > 0) {
        crc = tc8::crc::crc8SaeJ1850(data, cfg.offset, crc, false);
    }
    const std::size_t after = cfg.offset + 1;  // skip the CRC byte at cfg.offset
    if (after < len) {
        crc = tc8::crc::crc8SaeJ1850(data + after, len - after, crc, false);
    }
    return static_cast<std::uint8_t>(crc ^ kP11CrcXor);
}

}  // namespace

Profile11Protector::Profile11Protector(Profile11Config config)
    : config_(config), counter_(0) {}

void Profile11Protector::protect(std::uint8_t* data, std::size_t len) {
    if (len < config_.offset + kP11HeaderLen) {
        throw std::invalid_argument("tc8::e2e::Profile11Protector: PDU shorter than the E2E header");
    }
    const std::size_t hdr1 = config_.offset + 1;  // counter + Data ID nibble byte
    counter_ = static_cast<std::uint8_t>((counter_ + 1) % kP11CounterModulus);
    data[hdr1] = static_cast<std::uint8_t>((data[hdr1] & 0xF0U) | counter_);  // counter in low nibble
    if (config_.data_id_mode == DataIdMode::kNibble) {
        const std::uint8_t nibble = static_cast<std::uint8_t>((config_.data_id >> 8) & 0x0FU);
        data[hdr1] = static_cast<std::uint8_t>((data[hdr1] & 0x0FU) | (nibble << 4));  // high nibble
    }
    data[config_.offset] = computeP11Crc(data, len, config_);
}

Profile11Checker::Profile11Checker(Profile11Config config)
    : config_(config), last_counter_(0), have_last_(false) {}

CheckStatus Profile11Checker::check(const std::uint8_t* data, std::size_t len) {
    if (len < config_.offset + kP11HeaderLen) {
        throw std::invalid_argument("tc8::e2e::Profile11Checker: PDU shorter than the E2E header");
    }
    if (data[config_.offset] != computeP11Crc(data, len, config_)) {
        return CheckStatus::kError;
    }
    const std::uint8_t rx = static_cast<std::uint8_t>(data[config_.offset + 1] & 0x0FU);
    if (!have_last_) {
        have_last_ = true;
        last_counter_ = rx;
        return CheckStatus::kOk;
    }
    const std::uint8_t delta =
        static_cast<std::uint8_t>((rx + kP11CounterModulus - last_counter_) % kP11CounterModulus);
    last_counter_ = rx;
    return classifyCounter(delta, config_.max_delta_counter);
}

}  // namespace tc8::e2e
