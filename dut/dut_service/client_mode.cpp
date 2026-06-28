#include "client_mode.h"

#include "client_mode_wire.h"

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

constexpr std::uint16_t kSdPort       = 30490;
constexpr const char *  kSdMcastGroup = "224.244.224.245";

// SD §4.2.1 cadence — base delay 200 ms with exponential doubling, capped
// at three repetitions (matches vsomeip default `repetitions_max = 3`).
constexpr int kRepetitionsMax        = 3;
constexpr std::chrono::milliseconds kRepetitionBaseDelay{200};

// Initial wait before the first emit. Short — the SCXML phase 2 deadline
// for ETS_099 is 4 s, so a 50 ms initial gives plenty of margin.
constexpr std::chrono::milliseconds kInitialWait{50};

void putBe16(std::vector<std::uint8_t> &b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    b.push_back(static_cast<std::uint8_t>(v & 0xFF));
}
void putBe24(std::vector<std::uint8_t> &b, std::uint32_t v) {
    b.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    b.push_back(static_cast<std::uint8_t>(v & 0xFF));
}
void putBe32(std::vector<std::uint8_t> &b, std::uint32_t v) {
    b.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    b.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

// 44-byte SOME/IP-SD FindService datagram (16 B SOME/IP + 28 B SD payload
// with one entry, no options). Mirrors `tc8::stimulus::buildFindService`
// at src/stimulus/someip_sd_builder.cpp; duplicated here so tc8-dut
// firmware does not link the harness/tester library (reverse-direction
// dependency that would taint the cross-build path for real ECUs).
std::vector<std::uint8_t> buildFindServiceWire(std::uint16_t session_id) {
    std::vector<std::uint8_t> b;
    b.reserve(44);

    // SOME/IP header.
    putBe16(b, 0xFFFF);    // service_id (SD)
    putBe16(b, 0x8100);    // method_id (SD)
    putBe32(b, 36);        // length: 8 (request_id + proto/iface/msgtype/retcode)
                           //       + 28 (SD payload) = 36, counted from request_id.
    putBe16(b, 0);         // client_id
    putBe16(b, session_id);
    b.push_back(0x01);     // proto_ver
    b.push_back(0x01);     // iface_ver
    b.push_back(0x02);     // msg_type = NOTIFICATION
    b.push_back(0x00);     // return_code

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

std::vector<std::uint8_t> buildMethodRequestWire(std::uint16_t service_id, std::uint16_t method_id,
                                                 std::uint16_t client_id, std::uint16_t session_id,
                                                 std::uint8_t message_type,
                                                 const std::vector<std::uint8_t> &payload) {
    std::vector<std::uint8_t> b;
    b.reserve(16 + payload.size());
    putBe16(b, service_id);
    putBe16(b, method_id);
    putBe32(b, static_cast<std::uint32_t>(8 + payload.size()));  // length from Request ID.
    putBe16(b, client_id);
    putBe16(b, session_id);
    b.push_back(0x01);  // protocol_version
    b.push_back(0x01);  // interface_version
    b.push_back(message_type);
    b.push_back(0x00);  // return_code E_OK (a request carries E_OK).
    b.insert(b.end(), payload.begin(), payload.end());
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
