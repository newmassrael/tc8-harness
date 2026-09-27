#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>

#include "tc8/net/socket_backend.h"

namespace tc8::test {

// A net::SocketBackend whose every operation is an inert success, for tests that
// exercise ONE of its operations and must still instantiate the whole interface.
// Derive and override what the test is about; everything else stays out of the
// way. Socket-returning calls hand out a fixed descriptor and I/O moves no bytes,
// so a test that accidentally reaches them sees nothing rather than a crash.
class StubSocketBackend : public net::SocketBackend {
public:
    int createUdp() override { return 1; }
    int createTcp() override { return 2; }
    void setReuseAddr(int) override {}
    void setBroadcast(int) override {}
    void setRecvTimeoutMs(int, int) override {}
    bool bindV4(int, std::uint32_t, std::uint16_t) override { return true; }
    int recvFromV4(int, void *, std::size_t, net::Endpoint &) override { return -1; }
    int sendToV4(int, const void *, std::size_t len, const net::Endpoint &) override {
        return static_cast<int>(len);
    }
    net::OpStatus joinMulticast(int, std::uint32_t, std::uint32_t) override {
        return net::OpStatus::Ok;
    }
    net::OpStatus leaveMulticast(int, std::uint32_t, std::uint32_t) override {
        return net::OpStatus::Ok;
    }
    net::OpStatus flushDynamicArp(const std::string &) override { return net::OpStatus::Ok; }
    net::OpStatus addStaticNeighbor(const std::string &, std::uint32_t,
                                    const std::uint8_t *) override {
        return net::OpStatus::Ok;
    }
    net::OpStatus removeNeighbor(const std::string &, std::uint32_t) override {
        return net::OpStatus::Ok;
    }
    net::OpStatus setNeighborReachableMs(const std::string &, int) override {
        return net::OpStatus::Ok;
    }
    int recv(int, void *, std::size_t) override { return -1; }
    int send(int, const void *, std::size_t len) override { return static_cast<int>(len); }
    bool connectBoundedV4(int, const net::Endpoint &, int, const std::atomic<bool> *) override {
        return false;
    }
    bool listen(int, int) override { return true; }
    int accept(int, net::Endpoint &) override { return -1; }
    bool shutdown(int, int) override { return true; }
    void setNonBlocking(int, bool) override {}
    int waitReadable(int, int) override { return 0; }
    void closeFd(int) override {}
    void closeWithAbort(int) override {}
};

}  // namespace tc8::test
