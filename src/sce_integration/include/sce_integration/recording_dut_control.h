#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "sce_integration/dut_call_intent.h"
#include "sce_integration/dut_control.h"
#include "tc8/unperformed_stimulus.h"

namespace tc8::sce {

// Decorates a DUT-control backend so that an ACTION the case asked the DUT for and
// the DUT did not perform is recorded as an unperformed stimulus
// (tc8/unperformed_stimulus.h), named "dut_control_<operation>".
//
// Why here. An observed_quiescence fail (docs/verdict_policy.md Section 2.1,
// hypothesis S) is sound only when the stimulus was performed, and a DUT-control
// action is a stimulus: "abort the connection", then "the DUT sent no RST". Cases
// discard these results in dozens of places, so a refused or lost Upper Tester
// request would have been graded as the DUT's silence. The send primitives already
// record their own failures (stimulus/tx_observer.h, reportTxFailed); this is the
// same rule one layer up, applied once where the backend is built
// (makeDutControl), so it holds for every backend and every case without either
// having to remember it.
//
// What an action's answer means depends on why the case made the call: a stimulus
// the case relies on, an answer it grades, or cleanup after the graded part
// (DutCallIntent, dut_call_intent.h, set by a DutCallIntentScope around the call).
//
// A query's answer is an observation of the DUT, whatever it says: acceptTcp
// (whether a peer connected), queryReceived, queryCommittedAddress and the state
// probe pass through untouched, as do probe/startTest/endTest, which the
// start-order barrier already accounts for. The two receives say apart an answer
// from no answer (DutReceiveOutcome), so for them no answer, and only that, is
// recorded: the question never came back.
class RecordingDutControl final : public IDutControl {
public:
    explicit RecordingDutControl(std::unique_ptr<IDutControl> inner) : inner_(std::move(inner)) {}

    bool probe() override { return inner_->probe(); }
    bool startTest() override { return inner_->startTest(); }
    bool endTest() override { return inner_->endTest(); }
    const char *backendName() const override { return inner_->backendName(); }
    std::uint16_t controlPort() const override { return inner_->controlPort(); }
    DutCapabilities capabilities() const override { return inner_->capabilities(); }
    DutCapabilities staticCapabilities() const override { return inner_->staticCapabilities(); }
    bool faultCapsResolved() const override { return inner_->faultCapsResolved(); }

    ITcpControl *tcpControl() override { return tcp_.bind(inner_->tcpControl()); }
    IUdpControl *udpControl() override { return udp_.bind(inner_->udpControl()); }
    IDhcpClientControl *dhcpClientControl() override {
        return dhcp_.bind(inner_->dhcpClientControl());
    }
    ILinkLocalControl *linkLocalControl() override {
        return link_local_.bind(inner_->linkLocalControl());
    }
    IUdpReceiveControl *udpReceiveControl() override {
        return udp_receive_.bind(inner_->udpReceiveControl());
    }
    IArpControl *arpControl() override { return arp_.bind(inner_->arpControl()); }

    // A query whose answer, any answer, is the observation: nothing to record.
    ITcpStateProbe *tcpStateProbe() override { return inner_->tcpStateProbe(); }
    // A receive: only no answer is recorded, as for receiveTcp.
    ITcpRecvOob *tcpRecvOob() override { return recv_oob_.bind(inner_->tcpRecvOob()); }

private:
    static void record(const char *operation) {
        ::tc8::UnperformedStimulus::record(std::string("dut_control_") + operation);
    }

    // A bool action: false is recorded unless the call is cleanup (a bool cannot
    // tell a refusal from a lost request, so kGraded records it too).
    static bool performedOrRecord(bool performed, const char *operation) {
        if (!performed && DutCallIntentScope::current() != DutCallIntent::kCleanup) {
            record(operation);
        }
        return performed;
    }

    // A query: whatever the DUT answered is an observation, so only no answer at all
    // is recorded (the question did not come back, which is the tester's loss).
    static DutReceiveOutcome receivedOrRecord(DutReceiveOutcome outcome, const char *operation) {
        if (!outcome.answered() && DutCallIntentScope::current() != DutCallIntent::kCleanup) {
            record(operation);
        }
        return outcome;
    }

    // A typed action: what is recorded follows the call's intent (dut_call_intent.h).
    static DutCallOutcome accountFor(DutCallOutcome outcome, const char *operation) {
        switch (DutCallIntentScope::current()) {
            case DutCallIntent::kStimulus:
                if (!outcome.isDone()) {
                    record(operation);
                }
                break;
            case DutCallIntent::kGraded:
                if (outcome.kind == DutCallOutcome::Kind::kNoAnswer) {
                    record(operation);
                }
                break;
            case DutCallIntent::kCleanup:
                break;
        }
        return outcome;
    }

    // Each decorator wraps whatever the backend's accessor returns, re-bound on
    // every call, and is absent (nullptr) exactly when the backend's is, so the
    // capability gate sees the backend unchanged.
    template <typename Interface>
    struct Bound : Interface {
        Interface *inner = nullptr;
        Interface *bind(Interface *backend) {
            inner = backend;
            return backend != nullptr ? this : nullptr;
        }
    };

    struct Tcp final : Bound<ITcpControl> {
        std::optional<DutConnection> connectTcp(const Endpoint &peer,
                                                const BindSpec &local) override {
            auto conn = inner->connectTcp(peer, local);
            performedOrRecord(conn.has_value(), "connect_tcp");
            return conn;
        }
        std::optional<DutConnection> acceptTcp(const BindSpec &listen,
                                               const std::function<void()> &trigger) override {
            return inner->acceptTcp(listen, trigger);
        }
        std::optional<DutSocket> listenTcp(const BindSpec &listen) override {
            auto sock = inner->listenTcp(listen);
            performedOrRecord(sock.has_value(), "listen_tcp");
            return sock;
        }
        std::optional<DutSocket> createTcp(const BindSpec &local) override {
            auto sock = inner->createTcp(local);
            performedOrRecord(sock.has_value(), "create_tcp");
            return sock;
        }
        bool sendTcp(DutSocket sock, const std::vector<std::uint8_t> &data) override {
            return performedOrRecord(inner->sendTcp(sock, data), "send_tcp");
        }
        bool sendTcpWithFlags(DutSocket sock, const std::vector<std::uint8_t> &data,
                              TcpSendFlags flags) override {
            return performedOrRecord(inner->sendTcpWithFlags(sock, data, flags),
                                     "send_tcp_with_flags");
        }
        bool sendTcpPattern(DutSocket sock, std::uint8_t pattern,
                            std::uint16_t total_len) override {
            return performedOrRecord(inner->sendTcpPattern(sock, pattern, total_len),
                                     "send_tcp_pattern");
        }
        DutReceiveOutcome receiveTcp(DutSocket sock, std::uint16_t max_len,
                                     const std::function<void()> &trigger) override {
            return receivedOrRecord(inner->receiveTcp(sock, max_len, trigger), "receive_tcp");
        }
        bool shutdownTcpWr(DutSocket sock) override {
            return performedOrRecord(inner->shutdownTcpWr(sock), "shutdown_tcp_wr");
        }
        DutCallOutcome closeTcp(DutSocket sock) override {
            return accountFor(inner->closeTcp(sock), "close_tcp");
        }
        DutCallOutcome abortTcp(DutSocket sock) override {
            return accountFor(inner->abortTcp(sock), "abort_tcp");
        }
    };

    struct RecvOob final : Bound<ITcpRecvOob> {
        DutReceiveOutcome receiveTcpOob(DutSocket sock, std::uint16_t max_len) override {
            return receivedOrRecord(inner->receiveTcpOob(sock, max_len), "receive_tcp_oob");
        }
    };

    struct Udp final : Bound<IUdpControl> {
        bool sendDatagram(const Endpoint &src, const Endpoint &dest,
                          const std::vector<std::uint8_t> &data) override {
            return performedOrRecord(inner->sendDatagram(src, dest, data), "send_datagram");
        }
    };

    struct UdpReceive final : Bound<IUdpReceiveControl> {
        bool createReceivePorts(std::uint8_t count) override {
            return performedOrRecord(inner->createReceivePorts(count), "create_receive_ports");
        }
        bool queryReceived(const Endpoint &listen) override { return inner->queryReceived(listen); }
    };

    struct Dhcp final : Bound<IDhcpClientControl> {
        bool startClient(const dhcpv4::Dhcpv4StartConfig &spec) override {
            return performedOrRecord(inner->startClient(spec), "start_dhcp_client");
        }
    };

    struct LinkLocal final : Bound<ILinkLocalControl> {
        bool startAutoconf(const linklocal::LinkLocalStartConfig &spec) override {
            return performedOrRecord(inner->startAutoconf(spec), "start_link_local_autoconf");
        }
        ::tc8::net::OpStatus queryCommittedAddress(std::uint32_t &addr_be) override {
            return inner->queryCommittedAddress(addr_be);
        }
    };

    // The ARP operations return the backend's status: 0 is done, anything else is not.
    struct Arp final : Bound<IArpControl> {
        int provokeEgress(const ::tc8::stimulus::BootTiming &timing) override {
            const int rc = inner->provokeEgress(timing);
            performedOrRecord(rc == 0, "provoke_arp_egress");
            return rc;
        }
        int conditionCache(std::uint8_t action, std::uint16_t param) override {
            const int rc = inner->conditionCache(action, param);
            performedOrRecord(rc == 0, "condition_arp_cache");
            return rc;
        }
        int addStaticEntry(std::uint32_t ip_be, const std::array<std::uint8_t, 6> &mac) override {
            const int rc = inner->addStaticEntry(ip_be, mac);
            performedOrRecord(rc == 0, "add_static_arp_entry");
            return rc;
        }
        int removeStaticEntry(std::uint32_t ip_be) override {
            const int rc = inner->removeStaticEntry(ip_be);
            performedOrRecord(rc == 0, "remove_static_arp_entry");
            return rc;
        }
    };

    std::unique_ptr<IDutControl> inner_;
    Tcp tcp_;
    RecvOob recv_oob_;
    Udp udp_;
    UdpReceive udp_receive_;
    Dhcp dhcp_;
    LinkLocal link_local_;
    Arp arp_;
};

}  // namespace tc8::sce
