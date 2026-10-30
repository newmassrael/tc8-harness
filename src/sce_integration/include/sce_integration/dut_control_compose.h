#pragma once

#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "sce_integration/dut_control.h"
#include "sce_integration/dut_control_extension.h"

// The DUT-control handle that composes a backend with the extensions registered for
// it (dut_control_extension.h). Header-only so the composition rules can be tested
// without a runner; `makeDutControl` is the one production caller.
//
// The rules, each a startup error (DutControlExtensionError) and never a silent
// choice, because a run that picked one provider of a seam over another would grade
// a DUT through code nobody named:
//   1. An extension offers a seam the backend does not provide.
//   2. Two extensions never offer the same seam.
//   3. An extension's capabilities() are exactly the bits of the seams it provides.
//      A claim wider than the answer runs cases into a nullptr; a narrower one hides
//      a seam the cases could use.
// The capabilities the handle reports are the backend's OR the extensions'.

namespace tc8::sce {

namespace compose_detail {

struct Loaded {
    std::unique_ptr<DutControlExtension> ext;
    DutCapabilities provided = 0;
};

}  // namespace compose_detail

class ExtendedDutControl final : public IDutControl {
public:
    // `transport` is the backend's service-primitive call, which every extension is
    // built over. The backend must outlive the handle, and does: it is owned here.
    ExtendedDutControl(std::unique_ptr<IDutControl> backend,
                       const std::vector<DutControlExtensionFactory> &factories)
        : backend_(std::move(backend)) {
        IServicePrimitiveControl *transport = backend_->servicePrimitiveControl();
        if (transport == nullptr && !factories.empty()) {
            throw DutControlExtensionError(
                std::string("a DUT-control extension is registered for the '") +
                backend_->backendName() +
                "' backend, which has no service-primitive call to build it over");
        }
        for (const auto &make : factories) {
            compose_detail::Loaded loaded;
            loaded.ext = make(*transport);
            if (!loaded.ext) {
                throw DutControlExtensionError(
                    "a DUT-control extension factory returned no extension");
            }
            loaded_.push_back(std::move(loaded));
        }

        tcp_ = resolve("tcpControl", kCapTcpControl, backend_->tcpControl(),
                       &IDutControlSeams::tcpControl);
        udp_ = resolve("udpControl", kCapUdpControl, backend_->udpControl(),
                       &IDutControlSeams::udpControl);
        state_query_ = resolve("tcpStateQuery", kCapTcpStateQuery, backend_->tcpStateQuery(),
                               &IDutControlSeams::tcpStateQuery);
        info_probe_ = resolve("tcpInfoProbe", kCapTcpInfoProbe, backend_->tcpInfoProbe(),
                              &IDutControlSeams::tcpInfoProbe);
        recv_oob_ = resolve("tcpRecvOob", kCapTcpRecvOob, backend_->tcpRecvOob(),
                            &IDutControlSeams::tcpRecvOob);
        dhcp_ = resolve("dhcpClientControl", kCapDhcpClientControl, backend_->dhcpClientControl(),
                        &IDutControlSeams::dhcpClientControl);
        link_local_ = resolve("linkLocalControl", kCapLinkLocalControl,
                              backend_->linkLocalControl(), &IDutControlSeams::linkLocalControl);
        udp_receive_ = resolve("udpReceiveControl", kCapUdpReceiveControl,
                               backend_->udpReceiveControl(), &IDutControlSeams::udpReceiveControl);
        arp_ = resolve("arpControl", kCapArpConditioning, backend_->arpControl(),
                       &IDutControlSeams::arpControl);
        primitive_ = resolve("servicePrimitiveControl", kCapServicePrimitive,
                             backend_->servicePrimitiveControl(),
                             &IDutControlSeams::servicePrimitiveControl);
        socket_config_ = resolve("socketConfigControl", kCapSocketConfigure,
                                 backend_->socketConfigControl(),
                                 &IDutControlSeams::socketConfigControl);
        icmp_ = resolve("icmpControl", kCapIcmpEcho, backend_->icmpControl(),
                        &IDutControlSeams::icmpControl);
        udp_socket_ = resolve("udpSocketControl", kCapUdpSocket, backend_->udpSocketControl(),
                              &IDutControlSeams::udpSocketControl);

        for (const auto &l : loaded_) {
            if (l.ext->capabilities() != l.provided) {
                throw DutControlExtensionError(
                    std::string("extension '") + std::string(l.ext->name()) +
                    "' reports capabilities 0x" + hex(l.ext->capabilities()) +
                    " but its seams are 0x" + hex(l.provided) +
                    ": a claim must cover exactly what it answers");
            }
        }
    }

    // The backend's own handle is what the lifecycle, the control port and the
    // identity are; an extension changes none of them.
    bool probe() override { return backend_->probe(); }
    bool startTest() override { return backend_->startTest(); }
    bool endTest() override { return backend_->endTest(); }
    const char *backendName() const override { return backend_->backendName(); }
    std::uint16_t controlPort() const override { return backend_->controlPort(); }
    bool faultCapsResolved() const override { return backend_->faultCapsResolved(); }

    DutCapabilities capabilities() const override {
        return backend_->capabilities() | extensionCapabilities();
    }
    DutCapabilities staticCapabilities() const override {
        return backend_->staticCapabilities() | extensionCapabilities();
    }

    std::string seamProvenance() const override { return provenance_; }

    ITcpControl *tcpControl() override { return tcp_; }
    IUdpControl *udpControl() override { return udp_; }
    ITcpStateQuery *tcpStateQuery() override { return state_query_; }
    ITcpInfoProbe *tcpInfoProbe() override { return info_probe_; }
    ITcpRecvOob *tcpRecvOob() override { return recv_oob_; }
    IDhcpClientControl *dhcpClientControl() override { return dhcp_; }
    ILinkLocalControl *linkLocalControl() override { return link_local_; }
    IUdpReceiveControl *udpReceiveControl() override { return udp_receive_; }
    IArpControl *arpControl() override { return arp_; }
    IServicePrimitiveControl *servicePrimitiveControl() override { return primitive_; }
    ISocketConfigControl *socketConfigControl() override { return socket_config_; }
    IIcmpControl *icmpControl() override { return icmp_; }
    IUdpSocketControl *udpSocketControl() override { return udp_socket_; }

private:
    static std::string hex(DutCapabilities caps) {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%x", static_cast<unsigned>(caps));
        return buf;
    }

    DutCapabilities extensionCapabilities() const {
        DutCapabilities caps = 0;
        for (const auto &l : loaded_) {
            caps |= l.ext->capabilities();
        }
        return caps;
    }

    // The provider of one seam: the backend's, or the single extension that offers
    // it. Records the extension's bit and the provenance line, and refuses the two
    // claims that cannot both stand.
    template <typename T>
    T *resolve(const char *seam, DutCapabilities bit, T *from_backend,
               T *(IDutControlSeams::*get)()) {
        T *chosen = from_backend;
        const compose_detail::Loaded *owner = nullptr;
        for (auto &l : loaded_) {
            T *offered = ((*l.ext).*get)();
            if (offered == nullptr) {
                continue;
            }
            const std::string ext_name(l.ext->name());
            if (from_backend != nullptr) {
                throw DutControlExtensionError(
                    "extension '" + ext_name + "' offers " + seam + ", which the '" +
                    backend_->backendName() +
                    "' backend already provides; an extension adds a seam, it does not replace one");
            }
            if (owner != nullptr) {
                throw DutControlExtensionError(
                    "extensions '" + std::string(owner->ext->name()) + "' and '" + ext_name +
                    "' both offer " + seam + "; only one can provide it");
            }
            l.provided |= bit;
            owner = &l;
            chosen = offered;
            provenance_ += std::string(seam) + ": extension '" + ext_name + "'\n";
        }
        return chosen;
    }

    // Declared first, so it is destroyed last: the extensions hold the backend's
    // service-primitive call.
    std::unique_ptr<IDutControl> backend_;
    std::vector<compose_detail::Loaded> loaded_;
    std::string provenance_;

    ITcpControl *tcp_ = nullptr;
    IUdpControl *udp_ = nullptr;
    ITcpStateQuery *state_query_ = nullptr;
    ITcpInfoProbe *info_probe_ = nullptr;
    ITcpRecvOob *recv_oob_ = nullptr;
    IDhcpClientControl *dhcp_ = nullptr;
    ILinkLocalControl *link_local_ = nullptr;
    IUdpReceiveControl *udp_receive_ = nullptr;
    IArpControl *arp_ = nullptr;
    IServicePrimitiveControl *primitive_ = nullptr;
    ISocketConfigControl *socket_config_ = nullptr;
    IIcmpControl *icmp_ = nullptr;
    IUdpSocketControl *udp_socket_ = nullptr;
};

// The backend as it will be handed out: composed with the extensions registered for
// `kind`, or unchanged when there are none, so a run without extensions is the
// backend and nothing else.
inline std::unique_ptr<IDutControl>
composeDutControlExtensions(std::unique_ptr<IDutControl> backend, DutControlBackend kind,
                            const std::vector<DutControlExtensionRegistration> &registrations) {
    std::vector<DutControlExtensionFactory> factories;
    for (const auto &r : registrations) {
        if (r.backend == kind) {
            factories.push_back(r.make);
        }
    }
    if (factories.empty()) {
        return backend;
    }
    return std::make_unique<ExtendedDutControl>(std::move(backend), factories);
}

}  // namespace tc8::sce
