// Hermetic functional test for the netlink walk helpers in tc8/net/rtnetlink.h
// (nlmsgOk/nlmsgNext/rtaOk/rtaNext/nlmsgData/rtaData). The only other exercise of
// these on real entries is the privileged netns neighbor fixture, which self-skips
// without CAP_NET_ADMIN AND walks an empty `lo` table (no rtattrs) — so rtaOk /
// rtaNext / rtaData never actually run in the hosted CI lane. This builds a
// synthetic RTM_NEWNEIGH dump in memory and walks it, with no privilege, pinning
// the helpers byte-for-byte against the glibc NLMSG_*/RTA_* layout they mirror.

#include "tc8/net/rtnetlink.h"

#include <sys/socket.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include <gtest/gtest.h>

namespace tc8::net::rtnl {
namespace {

// Append one RTM_NEWNEIGH message at buf+*off: an ndmsg (ifindex/state) followed
// by an NDA_DST rtattr carrying dst_be. Advances *off past the aligned message.
void putNeigh(char *buf, std::size_t *off, int ifindex, std::uint16_t state,
              std::uint32_t dst_be) {
    auto *nlh = reinterpret_cast<::nlmsghdr *>(buf + *off);
    std::memset(nlh, 0, NLMSG_LENGTH(sizeof(::ndmsg)));
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(::ndmsg));
    nlh->nlmsg_type = RTM_NEWNEIGH;
    auto *nd = nlmsgData<::ndmsg>(nlh);
    nd->ndm_family = AF_INET;
    nd->ndm_ifindex = ifindex;
    nd->ndm_state = state;
    std::size_t attr_off = NLMSG_ALIGN(nlh->nlmsg_len);
    appendAttr(buf + *off, &attr_off, NDA_DST, &dst_be, sizeof(dst_be));
    nlh->nlmsg_len = static_cast<std::uint32_t>(attr_off);
    *off += NLMSG_ALIGN(nlh->nlmsg_len);
}

TEST(RtnlWalk, WalksMultiMessageDumpAndExtractsNdaDst) {
    char buf[512] = {};
    std::size_t off = 0;
    putNeigh(buf, &off, 7, NUD_REACHABLE, 0x0100007f);
    putNeigh(buf, &off, 9, NUD_STALE, 0x0a00000a);

    std::vector<int> ifaces;
    std::vector<std::uint32_t> dsts;
    int len = static_cast<int>(off);
    for (::nlmsghdr *nh = reinterpret_cast<::nlmsghdr *>(buf); nlmsgOk(nh, len);
         nh = nlmsgNext(nh, &len)) {
        ASSERT_EQ(nh->nlmsg_type, RTM_NEWNEIGH);
        const auto *nd = nlmsgData<::ndmsg>(nh);
        ifaces.push_back(nd->ndm_ifindex);
        const auto *rta = reinterpret_cast<const ::rtattr *>(
            reinterpret_cast<const char *>(nd) + NLMSG_ALIGN(sizeof(*nd)));
        int rtlen = static_cast<int>(nh->nlmsg_len - NLMSG_LENGTH(sizeof(*nd)));
        for (; rtaOk(rta, rtlen); rta = rtaNext(rta, &rtlen)) {
            if (rta->rta_type == NDA_DST) {
                dsts.push_back(*rtaData<std::uint32_t>(rta));
            }
        }
    }
    EXPECT_EQ(ifaces, (std::vector<int>{7, 9}));
    EXPECT_EQ(dsts, (std::vector<std::uint32_t>{0x0100007fu, 0x0a00000au}));
}

TEST(RtnlWalk, RtaOkRejectsTruncatedAttr) {
    char buf[64] = {};
    auto *rta = reinterpret_cast<::rtattr *>(buf);
    rta->rta_type = NDA_DST;
    rta->rta_len = static_cast<unsigned short>(RTA_LENGTH(4));
    EXPECT_FALSE(rtaOk(rta, 3));  // fewer bytes left than even the rtattr header
    EXPECT_TRUE(rtaOk(rta, static_cast<int>(RTA_LENGTH(4))));
}

TEST(RtnlWalk, NlmsgNextAdvancesAlignedAndTracksLen) {
    char buf[256] = {};
    std::size_t off = 0;
    putNeigh(buf, &off, 1, NUD_PERMANENT, 0x01020304);
    auto *nh = reinterpret_cast<::nlmsghdr *>(buf);
    const int aligned = static_cast<int>(NLMSG_ALIGN(nh->nlmsg_len));
    int len = static_cast<int>(off);
    auto *next = nlmsgNext(nh, &len);
    EXPECT_EQ(reinterpret_cast<char *>(next), buf + aligned);  // advance == glibc NLMSG_ALIGN
    EXPECT_EQ(len, static_cast<int>(off) - aligned);
    EXPECT_FALSE(nlmsgOk(next, len));  // single message → walk terminates
}

}  // namespace
}  // namespace tc8::net::rtnl
