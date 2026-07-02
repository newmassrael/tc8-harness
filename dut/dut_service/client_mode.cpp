#include "client_mode.h"

#include "client_mode_wire.h"
#include "someip/wire.h"
#include "tc8/dut_config.h"  // kSdPort / kSdMcastGroup — SD port/group SSOT

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace tc8::dut {

// Big-endian appenders + the 16-byte SOME/IP header layout are the shared wire
// SSOT (someip/wire.h, header-only — no link edge into the firmware).
using someip::putBe16;
using someip::putBe24;
using someip::putBe32;

namespace {

// SERVICE-ID-2 (0xF4E8) is the natural target — the DUT itself offers
// SERVICE-ID-1 (0xF4E7) as a server, and the spec defaults section
// (TC8 §5.1.2.3) carves out SERVICE-ID-2 for client-side scenarios. Using
// instance 0xFFFF means "any instance" so a tester offering 0xF4E8 with any
// instance id can answer the FindService.
constexpr std::uint16_t kClientTargetServiceId  = 0xF4E8;
constexpr std::uint16_t kClientTargetInstanceId = 0xFFFF;
constexpr std::uint8_t  kClientTargetMajor      = 0xFF;
constexpr std::uint32_t kClientTargetTtl        = 3;
constexpr std::uint32_t kClientTargetMinor      = 0xFFFFFFFFu;

// SD §4.2.1 cadence — base delay 200 ms with exponential doubling, capped
// at three repetitions (matches vsomeip default `repetitions_max = 3`).
constexpr int kRepetitionsMax        = 3;
constexpr std::chrono::milliseconds kRepetitionBaseDelay{200};

// Initial wait before the first emit. Short — the SCXML phase 2 deadline
// for ETS_099 is 4 s, so a 50 ms initial gives plenty of margin.
constexpr std::chrono::milliseconds kInitialWait{50};

// 44-byte SOME/IP-SD FindService datagram (16 B SOME/IP + 28 B SD payload
// with one entry, no options). The 16-byte header routes through the shared
// someip/wire.h SSOT (header-only, no link edge); the SD-payload shape mirrors
// `tc8::stimulus::buildFindService` and stays firmware-local so tc8-dut does not
// link the harness/tester library (reverse dependency that would taint the
// cross-build path for real ECUs).
std::vector<std::uint8_t> buildFindServiceWire(std::uint16_t session_id) {
    std::vector<std::uint8_t> b;
    b.reserve(44);

    // SOME/IP header via the shared wire SSOT.
    someip::Header h;
    h.service_id = 0xFFFF;  // SD
    h.method_id = 0x8100;   // SD
    h.length = 36;          // 8 (request id..return code) + 28 (SD payload).
    h.session_id = session_id;
    h.message_type = static_cast<std::uint8_t>(someip::MessageType::NOTIFICATION);
    someip::appendHeader(b, h);

    // SD header.
    b.push_back(0xC0);     // Reboot=1 Unicast=1 Reserved=0
    putBe24(b, 0);
    putBe32(b, 16);        // entries_len: 1 entry × 16 B

    // FindService entry (Type 0x00).
    b.push_back(0x00);
    b.push_back(0);        // index 1st option run
    b.push_back(0);        // index 2nd option run
    b.push_back(0);        // #opts1 (4b) | #opts2 (4b)
    putBe16(b, kClientTargetServiceId);
    putBe16(b, kClientTargetInstanceId);
    b.push_back(kClientTargetMajor);
    putBe24(b, kClientTargetTtl);
    putBe32(b, kClientTargetMinor);

    // Options length (no options).
    putBe32(b, 0);

    return b;
}

// First non-loopback IPv4 address bound to any interface — used as the
// IP_MULTICAST_IF egress pin so the FindService leaves on the same leg as
// the vsomeip server-side OfferService stream.
std::uint32_t firstNonLoopbackIpv4() {
    ifaddrs *head = nullptr;
    if (getifaddrs(&head) != 0 || head == nullptr) {
        return 0;
    }
    std::uint32_t addr = 0;
    const std::uint32_t loopback = htonl(0x7F000001);
    for (ifaddrs *a = head; a != nullptr; a = a->ifa_next) {
        if (a->ifa_addr == nullptr) continue;
        if (a->ifa_addr->sa_family != AF_INET) continue;
        std::uint32_t candidate = reinterpret_cast<sockaddr_in *>(a->ifa_addr)->sin_addr.s_addr;
        if (candidate == loopback) continue;
        addr = candidate;
        break;
    }
    freeifaddrs(head);
    return addr;
}

int sendFindServiceOnce(const std::vector<std::uint8_t> &wire) {
    int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        std::fprintf(stderr, "client_mode: socket() failed: %s\n", std::strerror(errno));
        return -1;
    }
    int one = 1;
    if (::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) {
        std::fprintf(stderr, "client_mode: SO_REUSEADDR failed: %s\n", std::strerror(errno));
        ::close(s);
        return -1;
    }

    // Bind source port to SD port — vsomeip silently drops SD frames from
    // ephemeral source ports, see reference_subscribe_sd_port memory. The
    // tester's vsomeip routing manager would log "Ignored SD message from
    // unknown port" for any other source port.
    sockaddr_in src{};
    src.sin_family      = AF_INET;
    src.sin_addr.s_addr = INADDR_ANY;
    src.sin_port        = htons(kSdPort);
    if (::bind(s, reinterpret_cast<sockaddr *>(&src), sizeof(src)) != 0) {
        std::fprintf(stderr, "client_mode: bind() to SD port failed: %s\n", std::strerror(errno));
        ::close(s);
        return -1;
    }

    in_addr ifaddr{};
    ifaddr.s_addr = firstNonLoopbackIpv4();
    if (ifaddr.s_addr != 0) {
        ::setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF, &ifaddr, sizeof(ifaddr));
    }

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    inet_pton(AF_INET, kSdMcastGroup, &dst.sin_addr);
    dst.sin_port = htons(kSdPort);

    auto rc = ::sendto(s, wire.data(), wire.size(), 0,
                       reinterpret_cast<sockaddr *>(&dst), sizeof(dst));
    int err = (rc < 0) ? errno : 0;
    ::close(s);
    if (rc < 0) {
        std::fprintf(stderr, "client_mode: sendto() failed: %s\n", std::strerror(err));
        return -1;
    }
    return 0;
}

}  // namespace

std::vector<std::uint8_t> buildMethodRequestWire(const MethodCall &call) {
    std::vector<std::uint8_t> b;
    b.reserve(16 + call.payload.size());
    someip::Header h;
    h.service_id = call.service_id;
    h.method_id = call.method_id;
    h.length = static_cast<std::uint32_t>(8 + call.payload.size());  // from Request ID.
    h.client_id = call.client_id;
    h.session_id = call.session_id;
    h.message_type = static_cast<std::uint8_t>(call.message_type);
    someip::appendHeader(b, h);  // proto/iface = 0x01, return_code = E_OK by default.
    b.insert(b.end(), call.payload.begin(), call.payload.end());
    return b;
}

ClientModeRunner::ClientModeRunner() = default;

ClientModeRunner::~ClientModeRunner() { stop(); }

void ClientModeRunner::start(std::uint8_t delay_ms) {
    bool expected = true;
    if (!stop_flag_.compare_exchange_strong(expected, false)) {
        // Already running — idempotent re-activation.
        return;
    }
    emit_thread_ = std::thread([this, delay_ms] {
        if (delay_ms > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
        }
        run();
    });
}

void ClientModeRunner::stop() {
    bool expected = false;
    if (!stop_flag_.compare_exchange_strong(expected, true)) {
        return;
    }
    if (emit_thread_.joinable()) {
        emit_thread_.join();
    }
}

void ClientModeRunner::run() {
    std::uint16_t session_id = 0x0001;

    if (stop_flag_.load()) return;
    std::this_thread::sleep_for(kInitialWait);
    if (stop_flag_.load()) return;

    sendFindServiceOnce(buildFindServiceWire(session_id));
    ++session_id;

    auto delay = kRepetitionBaseDelay;
    for (int i = 0; i < kRepetitionsMax && !stop_flag_.load(); ++i) {
        std::this_thread::sleep_for(delay);
        if (stop_flag_.load()) return;
        sendFindServiceOnce(buildFindServiceWire(session_id));
        ++session_id;
        delay = delay * 2;
    }

    // Main Phase: per PRS_SOMEIPSD_00351 / ETS_100 the DUT must NOT emit
    // FindService once the Repetition Phase ends. Idle until stopped.
    while (!stop_flag_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

}  // namespace tc8::dut
