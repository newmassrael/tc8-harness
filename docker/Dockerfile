# A runnable TC8 tester, packaged.
#
# WHAT THIS SOLVES
# ----------------
# The DUT half of a two-machine run needs no toolchain — staged binaries and a
# vsomeip runtime are enough. The TESTER half does not have that luxury: it is
# ~18 shared libraries deep (libpcap pulls in libnl / libibverbs / libsystemd /
# libdbus) plus a source-built SOME/IP stack, and every distribution spells
# those differently. That asymmetry, not the topology layer, is what makes
# "run the harness from the other machine" a chore.
#
# This image removes the distribution from the equation: the harness and every
# library it needs travel together. Any Linux host with a container runtime can
# be the tester, and it needs nothing installed but that runtime.
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
# One precondition: single-pc exec's a local tc8-dut, and this image is built
# with -DTC8_BUILD_MOCK_DUT=OFF and therefore carries none. Running single-pc
# from the stock image needs a DUT put there by a derived image — which is a
# packaging consequence of the topology's launch path, tracked in
# claudedocs/dut-role-separation-request.md, not something the flags above fix.
#
# The site descriptor is MOUNTED, never baked: it carries the operator's own
# addresses, account names and interface names (an `enx…` name literally encodes
# a MAC), none of which belong in a shared image any more than in git.
#
# SSH: the orchestrator spawns the remote DUT over ssh, so mount a key too —
#   -v "$HOME/.ssh/id_ed25519:/root/.ssh/id_ed25519:ro"
# and point `ssh_opts` in the site conf at that path.
#
# Base pinned to 22.04 to match build-test.yml exactly.
#
# 24.04 was tried first (it is what the reference two-PC setup runs) and its
# GCC refuses to build CommonAPI 3.2.0: upstream compiles with -Werror, and the
# newer toolchain both deprecates std::ptr_fun and stops pulling <string> in
# transitively, so capicxx-core-runtime fails on its own sources. Carrying a
# patch for a third-party dependency to satisfy a base-image preference is debt
# for nothing — CI proves 22.04 end to end on every push, so the image rides the
# environment that is already continuously verified. A consequence worth naming:
# the image's libtins is 22.04's, not the host's, which is the whole point of
# packaging it.
FROM ubuntu:22.04

# Single source for the Boost pin: the fetch, the checksum and the comment all
# derive from these, mirroring build-test.yml so the image and CI cannot drift
# to different SOME/IP stacks. vsomeip 3.7.3 needs Boost >= 1.75.
ARG BOOST_VERSION=1.75.0
ARG BOOST_SHA256=aeb26f80e80945e82ee93e5939baebdca47b9dee80a07d3144be1e1a6a66dd6a
ARG COMMONAPI_TAG=3.2.0
# Everything lands in one prefix so CMAKE_PREFIX_PATH stays single-rooted, and
# so vsomeip's $ORIGIN rpath resolves its dlopen'd plugin modules from a sibling
# lib/ — the failure mode that otherwise surfaces as the misleading
# "Configuration module could not be loaded!" with the dlerror swallowed.
ENV SOMEIP_PREFIX=/opt/someip-stack
ENV CMAKE_PREFIX_PATH=/opt/someip-stack
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
        quilt \
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

# --- Layer 2: Boost (source) -------------------------------------------------
# Only `filesystem` is needed (libvsomeip3-cfg links it). The tarball is
# checksum-verified before it is compiled and installed into the runtime stack:
# an unverified download here would be a supply-chain hole, not a convenience.
RUN set -eux; \
    boost_uscore="$(echo "${BOOST_VERSION}" | tr . _)"; \
    curl -fsSL -o /tmp/boost.tar.gz \
        "https://archives.boost.io/release/${BOOST_VERSION}/source/boost_${boost_uscore}.tar.gz"; \
    echo "${BOOST_SHA256}  /tmp/boost.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/boost.tar.gz -C /tmp; \
    cd "/tmp/boost_${boost_uscore}"; \
    ./bootstrap.sh --prefix="${SOMEIP_PREFIX}" --with-libraries=filesystem; \
    ./b2 -j"$(nproc)" variant=release link=shared threading=multi install; \
    rm -rf /tmp/boost*

# --- Layer 3: the pinned sources the dependency builds need ------------------
# Only the parts setup-vsomeip.sh and the sce pin read, copied BEFORE the rest of
# the tree: an ordinary source edit then leaves these expensive layers cached.
# .git comes along because the pristine reset below is a git operation and
# third_party/vsomeip/.git is a pointer into .git/modules (see .dockerignore).
WORKDIR /src
COPY .git /src/.git
COPY scripts /src/scripts
COPY patches /src/patches
COPY third_party /src/third_party

# vsomeip: patched in place by the repo's own quilt series. Using the script
# rather than open-coding cmake keeps the image on the SAME patch stack the
# harness is tested against — the series is what RPC_07/_08 depend on.
RUN ./scripts/setup-vsomeip.sh "${SOMEIP_PREFIX}"

# --- Layer 4: CommonAPI (source) --------------------------------------------
# AFTER vsomeip: capicxx-someip-runtime links it, which is why build-test.yml
# orders them this way. Upstream and unpatched, so they only rebuild when the
# tag or the prefix changes.
RUN set -eux; \
    mkdir -p /tmp/capi && cd /tmp/capi; \
    git clone --depth=1 --branch "${COMMONAPI_TAG}" https://github.com/COVESA/capicxx-core-runtime.git; \
    cmake -S capicxx-core-runtime -B capicxx-core-runtime/build \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="${SOMEIP_PREFIX}"; \
    cmake --build capicxx-core-runtime/build -j"$(nproc)"; \
    cmake --install capicxx-core-runtime/build; \
    git clone --depth=1 --branch "${COMMONAPI_TAG}" https://github.com/COVESA/capicxx-someip-runtime.git; \
    cmake -S capicxx-someip-runtime -B capicxx-someip-runtime/build \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="${SOMEIP_PREFIX}" \
        -DCMAKE_PREFIX_PATH="${SOMEIP_PREFIX}"; \
    cmake --build capicxx-someip-runtime/build -j"$(nproc)"; \
    cmake --install capicxx-someip-runtime/build; \
    rm -rf /tmp/capi


# --- Layer 5: sce-codegen at the pinned SHA. Built here rather than fetched so
# the image carries no unpinned binary.
RUN set -eux; \
    rev="$(tr -d '[:space:]' < third_party/sce/VERSION)"; \
    git clone https://github.com/newmassrael/scxml-core-engine.git /tmp/sce-src; \
    git -C /tmp/sce-src checkout "${rev}"; \
    cargo build --release --manifest-path /tmp/sce-src/sce-build/Cargo.toml \
        --bin sce-codegen --features cli; \
    install /tmp/sce-src/target/release/sce-codegen /usr/local/bin/; \
    rm -rf /tmp/sce-src /root/.cargo/registry

# --- Layer 6: the harness + orchestrator ------------------------------------
# The rest of the tree, now that every dependency layer above is settled.
COPY . /src

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
