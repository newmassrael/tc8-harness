#include "cli/declaration_register.h"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "sce_integration/case_applicability.h"  // applicabilitySkipReason (one spelling of a reason)
#include "sce_integration/declaration_enum.h"

namespace tc8::cli {
namespace {

// A declaration group's members live in one TestConfig field each.
#define TC8_DECLARATION_FIELD_tcp tcp_declared
#define TC8_DECLARATION_FIELD_network network
#define TC8_DECLARATION_FIELD(group) TC8_DECLARATION_FIELD_##group

template <typename T>
struct is_optional : std::false_type {};
template <typename T>
struct is_optional<std::optional<T>> : std::true_type {};

// The spellings an enumerated item takes; empty for any other kind of value.
template <typename Member>
std::vector<std::string_view> spellingsOf() {
    static_assert(is_optional<Member>::value, "a declaration is a std::optional member: it has no default");
    using V = typename Member::value_type;
    std::vector<std::string_view> out;
    if constexpr (std::is_enum_v<V>) {
        for (const auto &[name, value] : ::tc8::DeclarationEnum<V>::kValues) {
            (void)value;
            out.push_back(name);
        }
    }
    return out;
}

// A declared value in the spelling `--expect` takes.
template <typename V>
std::optional<std::string> render(const std::optional<V> &v) {
    if (!v) {
        return std::nullopt;
    }
    if constexpr (std::is_enum_v<V>) {
        return std::string(::tc8::declarationEnumName(*v));
    } else if constexpr (std::is_same_v<V, std::string>) {
        return *v;
    } else {
        static_assert(std::is_integral_v<V>, "a declaration is an enum, a name or a number");
        return std::to_string(*v);
    }
}

std::vector<DeclarationItem> buildRegister() {
    std::vector<DeclarationItem> items;
#define TC8_EK_tcp(kind, name)
#define TC8_EK_network(kind, name)
#define TC8_ED_tcp(kind, name, cls, standard) \
    items.push_back({"tcp." #name, DeclarationClass::cls, standard, \
                     spellingsOf<decltype(::tc8::TestConfig{}.TC8_DECLARATION_FIELD(tcp).name)>()});
#define TC8_ED_network(kind, name, cls, standard) \
    items.push_back({"network." #name, DeclarationClass::cls, standard, \
                     spellingsOf<decltype(::tc8::TestConfig{}.TC8_DECLARATION_FIELD(network).name)>()});
#include "tc8_expect_keys.def"
#undef TC8_EK_tcp
#undef TC8_EK_network
#undef TC8_ED_tcp
#undef TC8_ED_network
    return items;
}

}  // namespace

const std::vector<DeclarationItem> &declarationRegister() {
    static const std::vector<DeclarationItem> items = buildRegister();
    return items;
}

const DeclarationItem *findDeclaration(std::string_view id) {
    for (const DeclarationItem &item : declarationRegister()) {
        if (item.id == id) {
            return &item;
        }
    }
    return nullptr;
}

std::string_view declarationClassName(DeclarationClass cls) {
    switch (cls) {
        case DeclarationClass::PICS:
            return "PICS";
        case DeclarationClass::PIXIT:
            return "PIXIT";
    }
    return {};
}

std::optional<std::string> declaredValue(const ::tc8::TestConfig &cfg, std::string_view id) {
#define TC8_EK_tcp(kind, name)
#define TC8_EK_network(kind, name)
#define TC8_ED_tcp(kind, name, cls, standard) \
    if (id == "tcp." #name) return render(cfg.TC8_DECLARATION_FIELD(tcp).name);
#define TC8_ED_network(kind, name, cls, standard) \
    if (id == "network." #name) return render(cfg.TC8_DECLARATION_FIELD(network).name);
#include "tc8_expect_keys.def"
#undef TC8_EK_tcp
#undef TC8_EK_network
#undef TC8_ED_tcp
#undef TC8_ED_network
    return std::nullopt;
}

std::optional<std::string> malformedRequirement(const ::tc8::sce::DeclarationRequirement &req) {
    const DeclarationItem *item = findDeclaration(req.item);
    if (item == nullptr) {
        return "the requirement names '" + std::string(req.item) + "', which is no declaration";
    }
    if (!req.value.empty() && !item->values.empty()) {
        for (const std::string_view v : item->values) {
            if (v == req.value) {
                return std::nullopt;
            }
        }
        return "the requirement asks '" + std::string(req.item) + "' to be '" + std::string(req.value) +
               "', which it cannot be declared as";
    }
    return std::nullopt;
}

std::optional<std::string> unmetRequirement(const ::tc8::sce::DeclarationRequirement *reqs,
                                            std::size_t count, const ::tc8::TestConfig &cfg) {
    for (std::size_t i = 0; i < count; ++i) {
        const ::tc8::sce::DeclarationRequirement &req = reqs[i];
        const std::optional<std::string> declared = declaredValue(cfg, req.item);
        if (!declared) {
            return ::tc8::sce::applicabilitySkipReason("undeclared_" + std::string(req.item));
        }
        if (!req.value.empty() && *declared != req.value) {
            return ::tc8::sce::applicabilitySkipReason("declared_" + std::string(req.item) + "_" + *declared);
        }
    }
    return std::nullopt;
}

std::size_t declarationGroupKeyCount() {
    std::size_t n = 0;
#define TC8_EK_tcp(kind, name) ++n;
#define TC8_EK_network(kind, name) ++n;
#include "tc8_expect_keys.def"
#undef TC8_EK_tcp
#undef TC8_EK_network
    return n;
}

}  // namespace tc8::cli
