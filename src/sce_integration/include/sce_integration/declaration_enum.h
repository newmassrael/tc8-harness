#pragma once

#include <optional>
#include <string_view>
#include <utility>

namespace tc8 {

// The spelling of an enumerated operator declaration, written once beside its enum.
//
// A declaration such as "the DUT ignores a RST in TIME-WAIT" takes one of a closed set
// of values. A free-text field would accept a misspelt value and leave every reader to
// compare strings; an enum with this table is parsed once (`--expect`, expect_parser),
// refused when it names no value, and printed back with the same spelling. Specialise
// it next to the enum:
//
//   template <> struct DeclarationEnum<MyEnum> {
//       static constexpr std::pair<std::string_view, MyEnum> kValues[] = {...};
//   };
template <class E>
struct DeclarationEnum;  // no primary definition: an enum without a table does not parse

// The value `text` names, or nullopt when it names none.
template <class E>
std::optional<E> parseDeclarationEnum(std::string_view text) {
    for (const auto &[name, value] : DeclarationEnum<E>::kValues) {
        if (name == text) {
            return value;
        }
    }
    return std::nullopt;
}

// The spelling of `value`, the one `parseDeclarationEnum` accepts for it.
template <class E>
std::string_view declarationEnumName(E value) {
    for (const auto &[name, v] : DeclarationEnum<E>::kValues) {
        if (v == value) {
            return name;
        }
    }
    return {};
}

}  // namespace tc8
