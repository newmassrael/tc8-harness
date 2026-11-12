#include "vsomeip_sd_group.h"

#include "tc8/dut_config.h"  // kSdMcastGroup — the fallback when nothing names a group

#include <arpa/inet.h>
#include <netinet/in.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <vector>

// The JSON parser of Boost releases before 1.76 calls boost::bind with the global
// placeholder `_1` itself, and <boost/bind.hpp> then announces that global placeholders
// are deprecated. Declaring them is what that parser needs, so this file asks for them
// as vsomeip's configuration reader does; no code here uses a placeholder.
#define BOOST_BIND_GLOBAL_PLACEHOLDERS
#include <boost/property_tree/json_parser.hpp>
#include <boost/property_tree/ptree.hpp>

namespace tc8::dut {
namespace {

// `text` as an IPv4 multicast group (224.0.0.0/4) in network byte order.
std::optional<std::uint32_t> multicastGroupBe(const std::string &text) {
    in_addr a{};
    if (::inet_pton(AF_INET, text.c_str(), &a) != 1) {
        return std::nullopt;
    }
    if ((ntohl(a.s_addr) >> 28) != 0xE) {
        return std::nullopt;
    }
    return a.s_addr;
}

std::optional<VsomeipSdGroup> sdGroupFromFile(const std::string &file) {
    boost::property_tree::ptree tree;
    try {
        boost::property_tree::read_json(file, tree);
    } catch (const std::exception &e) {
        std::fprintf(stderr, "tc8-dut: cannot read vsomeip configuration %s: %s\n", file.c_str(),
                     e.what());
        return std::nullopt;
    }
    const auto value = tree.get_optional<std::string>("service-discovery.multicast");
    if (!value) {
        return std::nullopt;
    }
    const auto group = multicastGroupBe(*value);
    if (!group) {
        std::fprintf(stderr,
                     "tc8-dut: %s names service-discovery.multicast '%s', which is not an IPv4 "
                     "multicast group\n",
                     file.c_str(), value->c_str());
        return std::nullopt;
    }
    return VsomeipSdGroup{*group, *value, file};
}

}  // namespace

std::optional<VsomeipSdGroup> sdGroupFromVsomeipConfig(const std::string &path) {
    namespace fs = std::filesystem;
    std::error_code ec;
    if (fs::is_regular_file(path, ec)) {
        return sdGroupFromFile(path);
    }
    if (!fs::is_directory(path, ec)) {
        return std::nullopt;
    }
    std::vector<std::string> files;
    for (const auto &entry : fs::directory_iterator(path, ec)) {
        if (entry.is_regular_file(ec) && entry.path().extension() == ".json") {
            files.push_back(entry.path().string());
        }
    }
    std::sort(files.begin(), files.end());
    for (const auto &file : files) {
        if (auto group = sdGroupFromFile(file)) {
            return group;
        }
    }
    return std::nullopt;
}

VsomeipSdGroup vsomeipSdGroup() {
    if (const char *path = std::getenv("VSOMEIP_CONFIGURATION"); path != nullptr && *path != '\0') {
        if (auto group = sdGroupFromVsomeipConfig(path)) {
            return *group;
        }
    }
    in_addr fallback{};
    ::inet_pton(AF_INET, kSdMcastGroup, &fallback);
    return VsomeipSdGroup{fallback.s_addr, kSdMcastGroup, "compiled default"};
}

}  // namespace tc8::dut
