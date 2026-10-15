#include "stimulus/tx_observer.h"

namespace tc8::stimulus {
namespace {

// Not atomic, for the reason site_target.cpp gives: written once by the runner before
// any stimulus runs, read afterwards. A responder thread is started after it is set,
// and starting a thread orders the write before the thread's reads.
ITxObserver *g_observer = nullptr;

// The outermost active scope's name on this thread, or nullptr. Per thread because a
// scope names the emitter running on THAT thread; a responder thread sending while the
// capture thread is inside an emitter is not that emitter's send.
thread_local const char *t_emitter = nullptr;

}  // namespace

void setTxObserver(ITxObserver *observer) {
    g_observer = observer;
}

void reportTx(const char *transport, std::string_view iface, std::uint32_t dst_ip_be,
              std::uint16_t dst_port, std::size_t bytes) {
    if (g_observer == nullptr) {
        return;
    }
    TxEvent ev;
    ev.emitter = t_emitter != nullptr ? std::string_view{t_emitter} : std::string_view{};
    ev.transport = transport;
    ev.iface = iface;
    ev.dst_ip_be = dst_ip_be;
    ev.dst_port = dst_port;
    ev.bytes = bytes;
    g_observer->onTx(ev);
}

TxScope::TxScope(const char *emitter) : owns_(t_emitter == nullptr) {
    if (owns_) {
        t_emitter = emitter;
    }
}

TxScope::~TxScope() {
    if (owns_) {
        t_emitter = nullptr;
    }
}

}  // namespace tc8::stimulus
