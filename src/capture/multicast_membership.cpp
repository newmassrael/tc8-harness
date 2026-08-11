#include "capture/multicast_membership.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <utility>

namespace tc8::capture {
namespace {

std::string reasonFor(const std::string &group, const char *what) {
    return group + ": " + what;
}

std::string reasonForErrno(const std::string &group, const char *what, int err) {
    return group + ": " + what + ": " + std::strerror(err);
}

}  // namespace

MulticastMembership MulticastMembership::join(std::string_view iface,
                                              const std::vector<std::string> &groups) {
    MulticastMembership m;
    m.requested_.assign(groups.begin(), groups.end());
    if (groups.empty()) {
        return m;
    }

    // Resolved once: if the interface cannot be named there is no per-group
    // difference to report, and re-querying per group would spread one cause
    // across N identical messages.
    const std::string iface_s(iface);
    const unsigned ifindex = ::if_nametoindex(iface_s.c_str());
    if (ifindex == 0) {
        const int err = errno;
        for (const std::string &g : groups) {
            m.failed_.push_back(reasonForErrno(g, ("if_nametoindex(" + iface_s + ")").c_str(), err));
        }
        return m;
    }

    for (const std::string &g : groups) {
        ::in_addr group_addr{};
        if (::inet_pton(AF_INET, g.c_str(), &group_addr) != 1) {
            m.failed_.push_back(reasonFor(g, "not a dotted-quad IPv4 group"));
            continue;
        }

        const int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            m.failed_.push_back(reasonForErrno(g, "socket(AF_INET, SOCK_DGRAM)", errno));
            continue;
        }

        // Left unbound on purpose. The membership is what makes the snooping
        // bridge forward the group; the frames themselves are read by pcap, not
        // here. An unbound socket has no port for the stack to deliver to, so it
        // accumulates no datagrams and needs no draining thread — this object
        // costs one descriptor per group and nothing else.
        //
        // ip_mreqn carries the interface by INDEX, so the join is pinned to the
        // capture NIC without having to first resolve that NIC's address. On a
        // tester whose capture interface is not the default route, selecting by
        // address would be the subtle way to join the wrong link.
        ::ip_mreqn mreq{};
        mreq.imr_multiaddr = group_addr;
        mreq.imr_address.s_addr = htonl(INADDR_ANY);
        mreq.imr_ifindex = static_cast<int>(ifindex);

        if (::setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) != 0) {
            m.failed_.push_back(reasonForErrno(g, "setsockopt(IP_ADD_MEMBERSHIP)", errno));
            ::close(fd);
            continue;
        }
        m.sockets_.push_back(fd);
    }
    return m;
}

MulticastMembership MulticastMembership::declined(const std::vector<std::string> &groups) {
    MulticastMembership m;
    m.requested_.assign(groups.begin(), groups.end());
    for (const std::string &g : groups) {
        m.failed_.push_back(reasonFor(g, "declined by --no-multicast-membership"));
    }
    return m;
}

void MulticastMembership::release() {
    // Closing the socket is what drops the membership; there is no separate
    // IP_DROP_MEMBERSHIP to get wrong, and no window where the descriptor is
    // gone but the group is still held.
    for (const int fd : sockets_) {
        ::close(fd);
    }
    sockets_.clear();
}

MulticastMembership::~MulticastMembership() {
    release();
}

MulticastMembership::MulticastMembership(MulticastMembership &&other) noexcept
    : sockets_(std::move(other.sockets_)),
      requested_(std::move(other.requested_)),
      failed_(std::move(other.failed_)) {
    other.sockets_.clear();
}

MulticastMembership &MulticastMembership::operator=(MulticastMembership &&other) noexcept {
    if (this != &other) {
        release();
        sockets_ = std::move(other.sockets_);
        requested_ = std::move(other.requested_);
        failed_ = std::move(other.failed_);
        other.sockets_.clear();
    }
    return *this;
}

}  // namespace tc8::capture
