#include "ets_factory.h"

#include "ets_impl.h"

namespace tc8::dut {

// Default factory. Selected at configure time via TC8_ETS_FACTORY_SRC; an OEM
// builds its own source in this slot to return its EtsImpl subclass — see header.
std::shared_ptr<EtsImpl> createEtsStub() {
    return std::make_shared<EtsImpl>();
}

}  // namespace tc8::dut
