#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include "tc8/autosar/someiptp.h"
#include "stimulus/someip_tp_emit.h"
#include "stimulus/tx_observer.h"

namespace tc8::stimulus {
namespace {

// Records the step of every reported send, in order.
class StepRecorder : public ITxObserver {
public:
    void onTx(const TxEvent &ev) override { steps.push_back(ev.spec_step); }
    std::vector<int> steps;
};

// A loopback receiver bound to an ephemeral port, so a test can emit to it.
struct LoopbackReceiver {
    LoopbackReceiver() {
        fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        sockaddr_in ra{};
        ra.sin_family = AF_INET;
        ra.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ::bind(fd, reinterpret_cast<sockaddr *>(&ra), sizeof(ra));
        sockaddr_in bound{};
        socklen_t bl = sizeof(bound);
        ::getsockname(fd, reinterpret_cast<sockaddr *>(&bound), &bl);
        port = ntohs(bound.sin_port);
    }
    ~LoopbackReceiver() { ::close(fd); }
    int fd = -1;
    std::uint16_t port = 0;
};

// End-to-end: emit a 40-byte SOME/IP message as 16-byte TP segments over loopback,
// receive each datagram, and reassemble via the engine — the round trip proves the
// tester-side emit produces spec-valid segments the Reassembler accepts.
TEST(SomeIpTpEmit, SegmentsRoundTripThroughLoopback) {
    const int rx = ::socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(rx, 0);
    sockaddr_in ra{};
    ra.sin_family = AF_INET;
    ra.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ra.sin_port = 0;
    ASSERT_EQ(::bind(rx, reinterpret_cast<sockaddr *>(&ra), sizeof(ra)), 0);
    sockaddr_in bound{};
    socklen_t bl = sizeof(bound);
    ASSERT_EQ(::getsockname(rx, reinterpret_cast<sockaddr *>(&bound), &bl), 0);
    const std::uint16_t rx_port = ntohs(bound.sin_port);
    timeval tv{1, 0};
    ::setsockopt(rx, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    someiptp::MessageHeader hdr{0x01010009, 0x00010005, 0x01, 0x01, 0x00, 0x00};
    std::vector<std::uint8_t> payload(40);
    for (std::size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<std::uint8_t>(i);
    }

    // A fixed source port below the ephemeral range, so the OS will not have
    // auto-assigned it (mirrors udp_emit_test's rationale).
    const std::uint16_t kSrcPort = 23460;
    const int rc = emitSomeIpTpSegments("lo", kSrcPort, hdr, payload.data(), payload.size(),
                                        htonl(INADDR_LOOPBACK), rx_port, /*max_segment_payload=*/16);
    ASSERT_EQ(rc, 0);

    someiptp::Reassembler re(/*max_message=*/4096, /*max_concurrent=*/4, std::chrono::milliseconds(1000));
    someiptp::Reassembler::Result result;
    for (int i = 0; i < 3; ++i) {  // 40 bytes / 16 = 3 segments
        std::uint8_t buf[256] = {};
        const ssize_t n = ::recvfrom(rx, buf, sizeof(buf), 0, nullptr, nullptr);
        ASSERT_GT(n, 0);
        result = re.feed(buf, static_cast<std::size_t>(n));
    }
    ::close(rx);

    ASSERT_EQ(result.status, someiptp::Reassembler::Status::kComplete);
    EXPECT_EQ(result.payload, payload);
}

// A procedure that counts each segment as a step of its own gets each segment tagged
// with that step, and a segment the list does not name keeps the caller's.
TEST(SomeIpTpEmit, EachSegmentTakesItsStepAndAnUnnamedOneKeepsTheCallers) {
    LoopbackReceiver rx;
    ASSERT_GE(rx.fd, 0);
    someiptp::MessageHeader hdr{0x01010009, 0x00010005, 0x01, 0x01, 0x00, 0x00};
    const std::vector<std::uint8_t> payload(40, 0x5A);  // 3 segments of at most 16 bytes

    StepRecorder recorder;
    setTxObserver(&recorder);
    int rc = 0;
    {
        TxSpecStep callers(9);
        rc = emitSomeIpTpSegments("lo", 23461, hdr, payload.data(), payload.size(),
                                  htonl(INADDR_LOOPBACK), rx.port, /*max_segment_payload=*/16,
                                  /*reserved=*/0, /*segment_steps=*/{2, 3});
    }
    setTxObserver(nullptr);

    ASSERT_EQ(rc, 0);
    EXPECT_EQ(recorder.steps, (std::vector<int>{2, 3, 9}));
}

}  // namespace
}  // namespace tc8::stimulus
