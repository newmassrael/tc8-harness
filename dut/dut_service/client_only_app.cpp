#include "client_only_app.h"

#include <cstdio>

#include <CommonAPI/CommonAPI.hpp>  // DEFAULT_CONNECTION_ID — the vsomeip app-map key SSOT

namespace tc8::dut {

ClientOnlyApplication::ClientOnlyApplication() = default;

ClientOnlyApplication::~ClientOnlyApplication() { stop(); }

bool ClientOnlyApplication::start() {
    if (app_) {
        return true;
    }
    auto runtime = vsomeip::runtime::get();
    // Enforce the sole-creator invariant (see header) at the earliest point: if the
    // default-connection application already exists, something created it first, and
    // creating it again would MANGLE to a "_N" second routing client (vsomeip's
    // create_application never reuses). Fail loud instead of splitting silently. This
    // catches an ordering regression; a CommonAPI proxy/stub built LATER on the
    // default connection is a contract violation this cannot observe from here.
    if (runtime->get_application(CommonAPI::DEFAULT_CONNECTION_ID)) {
        std::fprintf(stderr,
                     "client_only_app: default-connection application already exists; "
                     "ClientOnlyApplication must be its sole creator\n");
        return false;
    }
    // Create under the SAME key acquireCommonApiApplication retrieves by. Referencing
    // CommonAPI::DEFAULT_CONNECTION_ID (not a bare "") keeps the creator in step with
    // the retriever if CommonAPI ever changes its default connection id — the same
    // discipline as ets_vsomeip_app.h. create_application keys vsomeip's map by this
    // name; the display/config name is resolved from VSOMEIP_APPLICATION_NAME in
    // init() when the name is empty, exactly as when CommonAPI creates the app.
    app_ = runtime->create_application(CommonAPI::DEFAULT_CONNECTION_ID);
    if (!app_ || !app_->init()) {
        std::fprintf(stderr, "client_only_app: create_application/init failed\n");
        app_.reset();
        return false;
    }
    // application::start runs the event loop and BLOCKS, so it owns a dedicated
    // thread. The thread captures a STRONG copy of the application: vsomeip's runtime
    // holds only a weak reference, so this copy plus app_ are the sole owners (a
    // by-reference capture would be a use-after-free). No offer_service /
    // request_service is issued here, so the started application emits no
    // service-discovery traffic; init() has already created the routing layer, so any
    // offer/request the seams issue next is accepted and queued (no wait for
    // registration — CommonAPI's own connect() returns without blocking either).
    thread_ = std::thread([app = app_]() { app->start(); });
    std::printf("tc8-dut: client-only vsomeip application created directly "
                "(no proxy, no offer, no find)\n");
    return true;
}

void ClientOnlyApplication::stop() {
    if (app_) {
        app_->stop();
    }
    if (thread_.joinable()) {
        thread_.join();
    }
    app_.reset();
}

}  // namespace tc8::dut
