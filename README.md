# Quantum-Safe File Encryption in Practice

A reproducible benchmark and interoperability test suite comparing **classical** and **hybrid post-quantum** (ML-KEM-768 + X25519) file encryption in [age](https://github.com/FiloSottile/age) and [GnuPG](https://gnupg.org).

Seminar project for the Information Security course (Siguria e Informacionit), FIEK Master, 2026/27.
Team: Ora Osmani, Erëza Ismajli, Nehar Jashari.

> **Status (Oct 22, 2026):** the Docker image builds with all four tools (age, GnuPG, Sequoia `sq`, GopenPGP), and the smoke test passes a classical and a post-quantum round trip for each. The benchmark, interop, and analysis scripts are in progress. Sections marked *(planned)* describe targets that are not implemented yet.

---

## What we measure

Encrypted files can be copied today and decrypted later, once a quantum computer can break X25519 ("harvest now, decrypt later"). Both age and GnuPG now offer hybrid post-quantum modes. This project measures what those modes cost and whether they interoperate:

| | Question | Measured as |
|---|---|---|
| **RQ1** | How much larger are post-quantum keys and encrypted files, and how does that grow with the number of recipients? | public key size, ciphertext overhead per recipient |
| **RQ2** | How do encryption and decryption times compare, from 1 KB to 1 GB? | wall time (hyperfine), median and IQR, PQ/classical ratio |
| **RQ3** | How much do CPU time and peak memory increase, and does it depend on the number of recipients? | cgroup v2 `cpu.stat` and `memory.peak`, GNU time max RSS |
| **RQ4** | Can GnuPG's post-quantum messages be decrypted by Sequoia-PGP and GopenPGP (RFC 9980), and the other way round? If not, where does it fail? | pass/fail and failure stage (import, encrypt, decrypt) per tool pair |

### Experiment design

| | Values |
|---|---|
| Modes | `age-x25519`, `age-pq`, `gpg-cv25519`, `gpg-pqc` |
| File sizes | 1 KB, 100 KB, 10 MB, 1 GB of random bytes |
| Recipients | 1, 10, 50 |
| Repetitions | 10 per condition (3 for 1 GB), after 2 warm-up runs |
| Held constant | machine, tool versions, test keys; no signing, no compression, binary (non-armored) output |

Each post-quantum mode is compared with the classical mode **of the same tool**, so the difference comes from key establishment and not from the file format. Every decryption is checked against the input's SHA-256.

### Key types

| Mode | Command | Key |
|---|---|---|
| `age-x25519` | `age-keygen` | X25519 |
| `age-pq` | `age-keygen -pq` | ML-KEM-768 + X25519 |
| `gpg-cv25519` | `gpg --quick-gen-key <uid> future-default default never` | Ed25519 primary, cv25519 encryption subkey |
| `gpg-pqc` | `gpg --quick-gen-key <uid> ed25519 default never`, then `gpg --quick-add-key <fpr> ky768_cv25519 encr never` | Ed25519 primary, ML-KEM-768 + X25519 (`ky768_cv25519`) encryption subkey |

We do not use GnuPG's `pqc` shortcut for `gpg-pqc`. In GnuPG 2.5.22 it creates a brainpoolP384r1 primary key with an ML-KEM-768 + brainpool P-256 subkey. That would change the classical curve as well as adding ML-KEM, and it would differ from the X25519 hybrid used by age and RFC 9980. With the commands above, the two gpg modes differ only in the encryption subkey.

---

## Requirements

- **Docker.** Everything runs in the `pqc-bench` image.
- **For measurements (RQ3): a Linux host with cgroup v2 and kernel ≥ 5.19**, where `memory.peak` exists. Check with:

  ```bash
  stat -fc %T /sys/fs/cgroup
  ```

  It must print `cgroup2fs`. Docker Desktop on Windows or macOS is fine for development, but final measurements are taken on one dedicated Linux machine.
- **GNU Make**, for the shortcuts below. On Windows, use WSL2.

## Quick start

```bash
make image
```

Builds the `pqc-bench` image. The first build compiles GnuPG and Sequoia from source and takes a while.

```bash
make smoke
```

Prints every tool's version and does one encrypt/decrypt round trip per mode and tool, with a hash check. It must pass before any measurement.

Without Make:

```bash
docker build -t pqc-bench -f docker/Dockerfile .
```

```bash
docker run --rm -v "$PWD:/work" -w /work pqc-bench sh docker/smoke_test.sh
```

## Reproducing the results *(planned)*

The full pipeline will be:

```bash
make inputs
```

Generates the random input files in `data/` (1 KB, 100 KB, 10 MB, 1 GB) and their hashes in `results/inputs.sha256`. Once the hash file exists, `make inputs` only checks the inputs against it. The committed hashes belong to our original random inputs, so in a fresh clone run `sh measure/make_inputs.sh --force` inside the image to generate new inputs and new hashes.

```bash
make env
```

Writes `results/env.json`: CPU, RAM, OS, kernel, Docker and image digest, the git commit, and the full version output of every tool. Runs on the host and starts the containers itself. The full runs refuse to start without it.

```bash
docker run --rm -v "$PWD:/work" -w /work pqc-bench python3 bench/run_all.py --phase full
```

Key generation, sizes (RQ1), and timing (RQ2). `--phase pilot` runs only the small files.

```bash
python3 bench/run_resources.py --phase full
```

CPU and memory (RQ3). Runs on the **host**, because it starts one fresh container per measured run.

```bash
docker run --rm -v "$PWD:/work" -w /work pqc-bench python3 interop/run_matrix.py --repeats 3
```

Interop matrix (RQ4).

```bash
make figures
```

Regenerates every figure and table from `results/`. It runs on the host and needs the pinned analysis packages first:

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

Then run `make figures PYTHON=.venv/bin/python`. It starts with `analysis/sanity.py`, which stops everything if a condition or run is missing, an exit code is not 0, or a SHA-256 check failed, and which lists noisy conditions (IQR above 20% of the median). Then `analysis/figures.py` writes `figures/*.pdf`, and `analysis/tables.py` writes `tables/*.tex`: medians with IQR, PQ/classical ratios with 95% bootstrap confidence intervals, and a cost decomposition `a + b·recipients + c·bytes` per mode.

Full runs take hours and are done once, on the measurement machine, with nothing else running. All scripts are resumable and skip conditions whose output already exists.

---

## Tools and versions

All versions are pinned. Exact versions, checksums, and signing keys are in [`docker/VERSIONS.md`](docker/VERSIONS.md).

| Tool | Version | Source |
|---|---|---|
| Base image | `debian:trixie` (digest pinned) | ships OpenSSL 3.5, needed by Sequoia PQC |
| age | 1.3.1 | official release binaries, SHA-256 checked |
| GnuPG | 2.5.22 | built from signature-verified source (the official apt repo no longer carries 2.5.22) |
| Sequoia `sq` | 1.4.0-pqc.1 | `cargo install --locked --no-default-features --features crypto-openssl` |
| GopenPGP | v3.4.1-proton | through our CLI wrapper, [`interop/gopenpgp-cli`](interop/gopenpgp-cli) |
| hyperfine, GNU time, Python | from Debian trixie | timing, max RSS, runners |

## Repository layout

```text
docker/          Dockerfile, VERSIONS.md, smoke_test.sh
bench/           key generation, sizes, timing, resource runs
measure/         cgroup measurement, environment capture, input generation
interop/         tool adapters, interop matrix, packet diagnosis, GopenPGP CLI wrapper (Go)
analysis/        statistics, figures, tables, sanity checks
results/         raw CSVs, hyperfine JSONs, env.json (committed)
figures/         generated figures (committed)
tables/          generated LaTeX tables (committed)
data/            generated input files (not committed)
keys/            generated test keys (not committed)
```

## Safety

- Only synthetic random files and freshly generated test keys are used. No real personal keys or data.
- `keys/` and `data/` are never committed. Delete them and regenerate to reset.
- Everything runs locally in throwaway containers. Nothing scans or connects to other systems.
- Any security bug found in a tool is reported to its developers before anything is published about it.

## Acknowledgements

The GopenPGP CLI wrapper is adapted from the `pqcrypt` tool in [detrin/pqc](https://github.com/detrin/pqc) (MIT License, Daniel Herman), which also documents the Sequoia and GopenPGP interop that RQ4 builds on.
