# Pinned versions

Every tool in the `pqc-bench` image, with its source and checksum. The values here must match the `ARG`s in `docker/Dockerfile`. Changing any of them changes the experiment and invalidates comparison with the committed results.

Resolved and verified on 2026-10-22 (UTC).

## Base image

| Component | Version | Pin |
|---|---|---|
| Debian | `debian:trixie` | `sha256:4c25275446ca371766b8b093c696782eabce06263fccacb8d5d813b3dc44b308` (multi-arch index digest) |

Trixie ships OpenSSL 3.5, which Sequoia PQC needs.

## GnuPG and libraries (built from source)

The official GnuPG apt repo for trixie (`repos.gnupg.org/deb/gnupg/trixie`) carries 2.5.21 and 2.5.24 but not 2.5.22, so GnuPG 2.5.22 is built from source to keep the pinned version. The library versions match the ones the GnuPG project ships in that repo (npth: latest release, since the repo uses Debian's).

| Component | Version | SHA-256 of `.tar.bz2` |
|---|---|---|
| libgpg-error | 1.61 | `7a85413f2bc354f4f8aa832b718af122e48965e9e0eb9012ee659c13c6385c93` |
| libgcrypt | 1.12.2 | `7ce33c2492221a0436f96a8500215e9f3e3dcb5fd26a757cd415e7a843babd5e` |
| libassuan | 3.0.2 | `d2931cdad266e633510f9970e1a2f346055e351bb19f9b78912475b8074c36f6` |
| libksba | 1.8.0 | `296b9db9095749f2aa104202d7ab7fd09ad10710e00780a709c9754b1a1d9292` |
| npth | 1.8 | `8bd24b4f23a3065d6e5b26e98aba9ce783ea4fd781069c1b35d149694e90ca3e` |
| GnuPG | 2.5.22 | `96e27b020ad26510388e06f5f07f3f70a4ed8916ee995f1b72b7a024e6d9d87e` |

Source: `https://gnupg.org/ftp/gcrypt/<package>/`. Each tarball's detached signature was verified against the GnuPG release keys from `https://gnupg.org/signature_key.asc`. All six carry good signatures from both:

- `6DAA6E64A76D2840571B4902528897B826403ADA` Werner Koch (dist signing 2020)
- `AC8E115BF73E2D8D47FA9908E98E9B2D19C6C8BD` Niibe Yutaka (GnuPG Release Key)

The Docker build then refuses any tarball whose SHA-256 differs from the table. Configure flags: `--disable-doc --disable-ldap` for GnuPG; no pinentry, since every call uses `--pinentry-mode loopback`.

## age

| Component | Version | SHA-256 |
|---|---|---|
| age, age-keygen, age-inspect (linux/amd64) | 1.3.1 | `bdc69c09cbdd6cf8b1f333d372a1f58247b3a33146406333e30c0f26e8f51377` |
| age, age-keygen, age-inspect (linux/arm64) | 1.3.1 | `c6878a324421b69e3e20b00ba17c04bc5c6dab0030cfe55bf8f68fa8d9e9093a` |

Source: official release assets at `https://github.com/FiloSottile/age/releases/tag/v1.3.1`; checksums from the release's published asset digests.

## From Debian trixie (apt)

| Component | Version | Notes |
|---|---|---|
| hyperfine | 1.19.0-1+b3 | timing |
| GNU time (`time`) | 1.9-0.2 | `max_rss_bytes` |
| Python (`python3.13`) | 3.13.5-2+deb13u5 | runners |

These come from the pinned base image's apt sources at build time. Rebuilding later may pull newer Debian point releases; `results/env.json` records the versions actually used.

## Sequoia `sq` (built from crates.io)

| Component | Version | Notes |
|---|---|---|
| sequoia-sq | 1.4.0-pqc.1 (published 2025-11-13) | `cargo install sequoia-sq --version 1.4.0-pqc.1 --locked --no-default-features --features crypto-openssl` |
| sequoia-openpgp | 2.2.0-pqc.1 | from the crate's `Cargo.lock` (`--locked`) |
| Crypto backend | OpenSSL 3.5.7 (Debian trixie `libssl-dev` / `libssl3t64`) | provides ML-KEM and ML-DSA |
| Rust toolchain | rustc 1.85.1+dfsg1-1+deb13u1 (Debian trixie) | crate needs ≥ 1.85 |

Newer releases exist (1.4.0, 1.4.1, 1.5.0); the pin stays at 1.4.0-pqc.1, the version used in the reference interop report.

Key profiles used: classical `--profile rfc4880 --cipher-suite cv25519` (v4 key, positive control); PQC `--profile rfc9580 --cipher-suite mldsa65-ed25519` (v6 key, ML-KEM-768+X25519 encryption subkey).

## GopenPGP (Go module)

| Component | Version | Notes |
|---|---|---|
| github.com/ProtonMail/gopenpgp/v3 | v3.4.1-proton | pinned in `interop/gopenpgp-cli/go.mod` and `go.sum` |
| github.com/ProtonMail/go-crypto | v1.4.1-proton | indirect, pinned in `go.sum` |
| Go toolchain | go1.24.4 (Debian trixie `golang-go`) | `GOTOOLCHAIN=local`, `CGO_ENABLED=0` |

Driven through our wrapper `interop/gopenpgp-cli` (adapted from detrin/pqc, MIT). Classical keys use the library default profile (v4: EdDSA primary, ECDH cv25519 subkey), so the classical row is a valid positive control. PQC keys use `profile.PQC()` (v6: ML-DSA-65+Ed25519 primary, ML-KEM-768+X25519 subkey). Verified with `sq packet dump` on 2026-10-22.
