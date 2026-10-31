# pqc-bench: one image with every pinned tool for the benchmark and interop tests.
# Versions and checksums are documented in docker/VERSIONS.md. Change them only with team approval.

# debian:trixie, resolved on 2026-10-22. Trixie ships OpenSSL 3.5, which Sequoia PQC needs.
ARG DEBIAN_IMAGE=debian:trixie@sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308

# ---------------------------------------------------------------------------
# Stage 1: GnuPG 2.5.22 and its libraries, built from source.
# The official GnuPG apt repo for trixie no longer carries 2.5.22.
# Library versions match what the GnuPG project ships in that repo.
# Signatures were verified on 2026-10-22 against the GnuPG release keys
# 6DAA6E64A76D2840571B4902528897B826403ADA (Werner Koch) and
# AC8E115BF73E2D8D47FA9908E98E9B2D19C6C8BD (Niibe Yutaka); the build pins the SHA-256.
# ---------------------------------------------------------------------------
FROM ${DEBIAN_IMAGE} AS gnupg-build

ARG LIBGPG_ERROR_VERSION=1.61
ARG LIBGPG_ERROR_SHA256=7a85413f2bc354f4f8aa832b718af122e48965e9e0eb9012ee659c13c6385c93
ARG LIBGCRYPT_VERSION=1.12.2
ARG LIBGCRYPT_SHA256=7ce33c2492221a0436f96a8500215e9f3e3dcb5fd26a757cd415e7a843babd5e
ARG LIBASSUAN_VERSION=3.0.2
ARG LIBASSUAN_SHA256=d2931cdad266e633510f9970e1a2f346055e351bb19f9b78912475b8074c36f6
ARG LIBKSBA_VERSION=1.8.0
ARG LIBKSBA_SHA256=296b9db9095749f2aa104202d7ab7fd09ad10710e00780a709c9754b1a1d9292
ARG NPTH_VERSION=1.8
ARG NPTH_SHA256=8bd24b4f23a3065d6e5b26e98aba9ce783ea4fd781069c1b35d149694e90ca3e
ARG GNUPG_VERSION=2.5.22
ARG GNUPG_SHA256=96e27b020ad26510388e06f5f07f3f70a4ed8916ee995f1b72b7a024e6d9d87e

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential bzip2 ca-certificates curl \
      libbz2-dev libgnutls28-dev libsqlite3-dev zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*

ENV PREFIX=/opt/gnupg
ENV PATH=/opt/gnupg/bin:$PATH \
    PKG_CONFIG_PATH=/opt/gnupg/lib/pkgconfig \
    LD_LIBRARY_PATH=/opt/gnupg/lib

WORKDIR /build

# fetch <package> <version> <sha256>: download a tarball and refuse it if the hash differs.
RUN printf '%s\n' \
      '#!/bin/sh' \
      'set -eu' \
      'curl -fsSL "https://gnupg.org/ftp/gcrypt/$1/$1-$2.tar.bz2" -o "$1-$2.tar.bz2"' \
      'echo "$3  $1-$2.tar.bz2" | sha256sum -c -' \
      'tar xjf "$1-$2.tar.bz2"' \
      > /usr/local/bin/fetch \
 && chmod +x /usr/local/bin/fetch

RUN fetch libgpg-error "$LIBGPG_ERROR_VERSION" "$LIBGPG_ERROR_SHA256" \
 && cd "libgpg-error-$LIBGPG_ERROR_VERSION" \
 && ./configure --prefix="$PREFIX" --disable-doc --disable-tests \
 && make -j"$(nproc)" && make install

RUN fetch libgcrypt "$LIBGCRYPT_VERSION" "$LIBGCRYPT_SHA256" \
 && cd "libgcrypt-$LIBGCRYPT_VERSION" \
 && ./configure --prefix="$PREFIX" --with-libgpg-error-prefix="$PREFIX" --disable-doc \
 && make -j"$(nproc)" && make install

RUN fetch libassuan "$LIBASSUAN_VERSION" "$LIBASSUAN_SHA256" \
 && cd "libassuan-$LIBASSUAN_VERSION" \
 && ./configure --prefix="$PREFIX" --with-libgpg-error-prefix="$PREFIX" --disable-doc \
 && make -j"$(nproc)" && make install

RUN fetch libksba "$LIBKSBA_VERSION" "$LIBKSBA_SHA256" \
 && cd "libksba-$LIBKSBA_VERSION" \
 && ./configure --prefix="$PREFIX" --with-libgpg-error-prefix="$PREFIX" --disable-doc \
 && make -j"$(nproc)" && make install

RUN fetch npth "$NPTH_VERSION" "$NPTH_SHA256" \
 && cd "npth-$NPTH_VERSION" \
 && ./configure --prefix="$PREFIX" \
 && make -j"$(nproc)" && make install

# Pinentry is not built: every gpg call uses --pinentry-mode loopback with passphrase-less test keys.
RUN fetch gnupg "$GNUPG_VERSION" "$GNUPG_SHA256" \
 && cd "gnupg-$GNUPG_VERSION" \
 && ./configure --prefix="$PREFIX" \
      --with-libgpg-error-prefix="$PREFIX" \
      --with-libgcrypt-prefix="$PREFIX" \
      --with-libassuan-prefix="$PREFIX" \
      --with-ksba-prefix="$PREFIX" \
      --with-npth-prefix="$PREFIX" \
      --disable-doc --disable-ldap \
 && make -j"$(nproc)" && make install

# ---------------------------------------------------------------------------
# Stage 2: age 1.3.1 release binaries, checksum pinned per architecture.
# ---------------------------------------------------------------------------
FROM ${DEBIAN_IMAGE} AS age-fetch

ARG TARGETARCH=amd64
ARG AGE_VERSION=1.3.1
ARG AGE_SHA256_AMD64=bdc69c09cbdd6cf8b1f333d372a1f58247b3a33146406333e30c0f26e8f51377
ARG AGE_SHA256_ARM64=c6878a324421b69e3e20b00ba17c04bc5c6dab0030cfe55bf8f68fa8d9e9093a

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) sha="$AGE_SHA256_AMD64" ;; \
      arm64) sha="$AGE_SHA256_ARM64" ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    tarball="age-v${AGE_VERSION}-linux-${TARGETARCH}.tar.gz"; \
    curl -fsSL "https://github.com/FiloSottile/age/releases/download/v${AGE_VERSION}/${tarball}" -o "$tarball"; \
    echo "$sha  $tarball" | sha256sum -c -; \
    tar xzf "$tarball"; \
    install -m 0755 age/age age/age-keygen age/age-inspect /usr/local/bin/

# ---------------------------------------------------------------------------
# Stage 3: Sequoia sq 1.4.0-pqc.1 with the OpenSSL backend (RFC 9980 PQC).
# Trixie's OpenSSL 3.5 provides ML-KEM and ML-DSA; trixie's Rust 1.85 meets the
# crate's minimum. --locked uses the crate's own Cargo.lock.
# ---------------------------------------------------------------------------
FROM ${DEBIAN_IMAGE} AS sq-build

ARG SQ_VERSION=1.4.0-pqc.1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates cargo rustc pkg-config \
      capnproto clang libclang-dev libssl-dev libsqlite3-dev \
 && rm -rf /var/lib/apt/lists/*

RUN cargo install sequoia-sq --version "$SQ_VERSION" --locked \
      --no-default-features --features crypto-openssl \
      --root /opt/sq

# ---------------------------------------------------------------------------
# Stage 4: GopenPGP v3.4.1-proton through our CLI wrapper (interop/gopenpgp-cli).
# The module version is pinned in go.mod and go.sum.
# ---------------------------------------------------------------------------
FROM ${DEBIAN_IMAGE} AS gopenpgp-build

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates golang-go git \
 && rm -rf /var/lib/apt/lists/*

ENV GOTOOLCHAIN=local CGO_ENABLED=0
WORKDIR /src
COPY interop/gopenpgp-cli/go.mod interop/gopenpgp-cli/go.sum ./
RUN go mod download
COPY interop/gopenpgp-cli/*.go ./
RUN go build -trimpath -o /opt/gopenpgp-cli .

# ---------------------------------------------------------------------------
# Final image
# ---------------------------------------------------------------------------
FROM ${DEBIAN_IMAGE}

# hyperfine: timing. time: GNU time for max_rss_bytes (RQ3). python3: runners.
# The runtime libraries are what the GnuPG build links against.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates hyperfine time python3 \
      libbz2-1.0 libgnutls30t64 libsqlite3-0 libssl3t64 zlib1g \
 && rm -rf /var/lib/apt/lists/*

# GnuPG stays at its build prefix, because gpg finds gpg-agent through compiled-in paths.
COPY --from=gnupg-build /opt/gnupg /opt/gnupg
COPY --from=age-fetch /usr/local/bin/age /usr/local/bin/age-keygen /usr/local/bin/age-inspect /usr/local/bin/
COPY --from=sq-build /opt/sq/bin/sq /usr/local/bin/sq
COPY --from=gopenpgp-build /opt/gopenpgp-cli /usr/local/bin/gopenpgp-cli
RUN echo /opt/gnupg/lib > /etc/ld.so.conf.d/gnupg.conf && ldconfig
ENV PATH=/opt/gnupg/bin:$PATH

# gpg-agent puts its sockets here instead of into GNUPGHOME under the bind-mounted keys/.
# A container's agent is killed on exit without removing its sockets, and stale sockets
# in keys/ stop the next fresh container's agent from starting.
RUN mkdir -p -m 700 /run/user/0

WORKDIR /work
