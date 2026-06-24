#include "autosar/e2e.h"

#include <stdexcept>
#include <vector>

#include "autosar/crc.h"

namespace tc8::e2e {
namespace {

constexpr std::size_t kP05HeaderLen = 3;   // CRC (2 bytes) + counter (1 byte)
constexpr std::size_t kP05CounterPos = 2;  // counter offset within the header

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
    return tc8::crc::crc16Ccitt(buf.data(), buf.size());
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
    if (delta == 0) {
        return CheckStatus::kRepeated;
    }
    if (delta <= config_.max_delta_counter) {
        return CheckStatus::kOk;  // advanced (delta 1) or a tolerable number lost
    }
    return CheckStatus::kWrongSequence;
}

}  // namespace tc8::e2e
