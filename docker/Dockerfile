# A runnable TC8 tester, packaged.
#
# WHAT THIS SOLVES
# ----------------
# The DUT half of a two-machine run needs no toolchain — staged binaries and a
# vsomeip runtime are enough. The TESTER half does not have that luxury: it is
# ~18 shared libraries deep (libpcap pulls in libnl / libibverbs / libsystemd /
# libdbus) and every distribution spells them differently. That asymmetry, not
# the topology layer, is what makes "run the harness from the other machine" a
# chore.
#
# This image removes the distribution from the equation: the harness and every
# library it needs travel together. Any Linux host with a container runtime can
# be the tester, and it needs nothing installed but that runtime.
#
# WHAT IS DELIBERATELY ABSENT, AND WHY THAT IS LOAD-BEARING
# ---------------------------------------------------------
# There is NO SOME/IP middleware stack in this image — no Boost, no vsomeip, no
# CommonAPI runtimes, no CommonAPI code generators, no JRE. Earlier revisions
# source-built all of them, because the tester NAMED vsomeip3/CommonAPI on its
# link line. It never used them: the produced binary carried no DT_NEEDED for any
# of the three, and no source under src/ includes their headers. The tester writes
# and reads SOME/IP bytes on the wire; it does not drive an implementation of the
# protocol. That link entry has been removed and the find_package set now gates on
# TC8_BUILD_MOCK_DUT alone (root CMakeLists.txt).
#
# Their absence here is not just a size win — it is the ENFORCEMENT of that split,
# and the reason to keep it that way. A comment claiming "the tester needs no
# SOME/IP stack" has exactly the same standing as the wrong comment it replaced;
# nothing about it fails if someone re-adds a find_package. An image that cannot
# supply the stack does fail, visibly, in the CI job that builds it. So: do not
# add a SOME/IP stack back here to fix a build error. The error is the signal, and
# the fix belongs in whatever re-coupled the tester to the middleware.
#
# A DERIVED image that also carries a DUT (a self-test fixture) is a different
# artifact and must add these layers itself — which is the correct place for them,
# since a DUT stack may be a vendor-patched one under NDA and the tester is the
# artifact that has to stand in front of third-party hardware.
#
# WHAT IT DELIBERATELY DOES NOT DO
# --------------------------------
# It does not isolate. A conformance tester exists to put crafted frames on a
# real wire and observe what comes back, so it needs the host's NIC at the raw
# frame level — the opposite of what a container normally provides. Run it with
# host networking and the two capabilities below; treat this as PACKAGING, not a
# sandbox:
#
#   docker run --rm --network host \
#       --cap-add=NET_RAW --cap-add=NET_ADMIN \
#       -v "$PWD/site.toml:/site.toml:ro" \
#       tc8-tester \
#       --topology ssh-remote --workers 1 --topology-conf /site.toml SOMEIPSRV_FORMAT_01
#
# Those flags are the `ssh-remote` shape — the topology this image is built for.
# `single-pc` is a DIFFERENT shape, and the difference is not obvious enough to
# leave a reader to rediscover:
#
#   docker run --rm \
#       --cap-add=NET_ADMIN --cap-add=NET_RAW --cap-add=SYS_ADMIN \
#       --security-opt apparmor=unconfined \
#       tc8-tester --topology single-pc ...
#
# `run-isolated.sh` wraps the single-pc orchestrator in a private net + mount
# namespace, so it needs SYS_ADMIN for `unshare --net --mount` and its tmpfs.
# The capability alone is not enough: Ubuntu's `docker-default` AppArmor profile
# denies the propagation change outright, and the run dies at "unshare: cannot
# change root filesystem propagation: Permission denied" — a failure the two
# capabilities named above give no hint about. Dropping SYS_ADMIN instead fails
# earlier, at "unshare: unshare failed: Operation not permitted"; those two
# negative controls are what make this set measured rather than guessed.
# `--privileged` is NOT required, nor is `seccomp=unconfined`, nor is
# `--network host` — every frame single-pc handles lives in namespaces
# run-isolated.sh creates, so it needs no host stack.
#
# One precondition: this image is built with -DTC8_BUILD_MOCK_DUT=OFF and so
# carries no tc8-dut. Mount one in and name it, rather than baking a DUT into the
# tester — which is the whole point of keeping the two products apart:
#
#   -v /path/to/dut:/mnt/dut:ro -v "$PWD/site.toml:/site.toml:ro"
#   --topology single-pc --topology-conf /site.toml
#
# with the site conf naming it (see "Choosing how single-pc launches its DUT" in
# the README):
#
#   [dut]
#   bin = "/mnt/dut/tc8-dut"
#
# A DUT that is not an executable at all — a sibling container, a rig behind a
# script — uses the `start`/`stop` form of the same section.
#
# The site descriptor is MOUNTED, never baked: it carries the operator's own
# addresses, account names and interface names (an `enx…` name literally encodes
# a MAC), none of which belong in a shared image any more than in git.
#
# SSH: the orchestrator spawns the remote DUT over ssh, so mount a key too —
#   -v "$HOME/.ssh/id_ed25519:/root/.ssh/id_ed25519:ro"
# and point `ssh_opts` in the site conf at that path.
#
# Base pinned to 22.04 to match build-test.yml exactly, so the image rides the
# environment CI already verifies end to end on every push. A consequence worth
# naming: the image's libtins is 22.04's, not the host's, which is the whole
# point of packaging it.
#
# (The original reason for the pin was that 24.04's GCC refuses to build
# CommonAPI 3.2.0 under its -Werror. That no longer applies here — nothing in
# this image builds CommonAPI — but it still applies to any DERIVED image that
# adds a DUT, so the constraint is recorded rather than dropped.)
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# --- Layer 1: distribution packages -----------------------------------------
# Ordered first and separately so the expensive source builds below survive a
# source-code change in the repo.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        clang-format-15 \
        cmake \
        curl \
        git \
        libclang-dev \
        libpcap-dev \
        libtins-dev \
        libxml2-dev \
        ninja-build \
        pkg-config \
        python3 \
        iproute2 \
        iputils-ping \
        openssh-client \
        tcpdump \
    && ln -sf /usr/bin/clang-format-15 /usr/bin/clang-format \
    && rm -rf /var/lib/apt/lists/*

# libxml2-dev and libclang-dev are NOT in build-test.yml's apt list: the GitHub
# runner image ships both, so CI never had to name them. sce-codegen needs the
# first through its `libxml` crate's pkg-config probe and the second through
# bindgen, which dlopens libclang.so. On a clean base each is a hard failure.
# Undocumented host dependencies like these are exactly what a packaged image
# surfaces — CI proves the build works on ONE machine, the image proves it can
# be reproduced on any.

# Rust: the orchestrator is a cargo crate, and sce-codegen is built from the
# upstream SCE engine at the SHA pinned in third_party/sce/VERSION.
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
ENV PATH=/root/.cargo/bin:$PATH

# --- Layer 2: the pinned sources the dependency build needs ------------------
# Only the part the sce pin reads (third_party/sce/VERSION), copied BEFORE the
# rest of the tree so an ordinary source edit leaves the expensive layer below
# cached.
#
# Boost, vsomeip and CommonAPI were built here until the tester stopped naming a
# SOME/IP stack it never called into. Nothing in this image needs them now, and
# their absence is what keeps that true (see the header). `patches/` and `.git`
# went with them: both existed only for the vsomeip quilt series and its pristine
# git reset, and nothing in this build embeds a commit SHA.
WORKDIR /src
COPY third_party /src/third_party

# --- Layer 3: sce-codegen at the pinned SHA. Built here rather than fetched so
# the image carries no unpinned binary.
RUN set -eux; \
    rev="$(tr -d '[:space:]' < third_party/sce/VERSION)"; \
    git clone https://github.com/newmassrael/scxml-core-engine.git /tmp/sce-src; \
    git -C /tmp/sce-src checkout "${rev}"; \
    cargo build --release --manifest-path /tmp/sce-src/sce-build/Cargo.toml \
        --bin sce-codegen --features cli; \
    install /tmp/sce-src/target/release/sce-codegen /usr/local/bin/; \
    rm -rf /tmp/sce-src /root/.cargo/registry

# --- Layer 4: the harness + orchestrator ------------------------------------
# The rest of the tree, now that every dependency layer above is settled.
COPY . /src

# TC8_BUILD_MOCK_DUT=OFF is what makes this a TESTER image: it is the option that
# owns the SOME/IP middleware dependency, so declining it means no find_package
# for vsomeip/CommonAPI runs at all. If this configure ever fails looking for one
# of them, something has re-coupled the tester to the middleware — fix that, do
# not install a stack here (see the header).
RUN cmake -S . -B build \
        -DCMAKE_BUILD_TYPE=Release \
        -DTC8_SCE_FIND_PACKAGE=OFF \
        -DTC8_BUILD_MOCK_DUT=OFF \
    && cmake --build build -j"$(nproc)"

RUN cd dut/env/orchestrator && cargo build --release

# The orchestrator shells out to the harness by path and resolves the repo root
# from the working directory, so both stay where the build put them.
ENV PATH=/src/build:$PATH
WORKDIR /src
ENTRYPOINT ["/src/dut/env/orchestrator/target/release/tc8-orchestrator"]
