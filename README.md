# Quantum-Safe File Encryption in Practice

A reproducible benchmark and interoperability test suite comparing **classical** and **hybrid post-quantum** (ML-KEM-768 + X25519) file encryption in [age](https://github.com/FiloSottile/age) and [GnuPG](https://gnupg.org).

Seminar project for the Information Security course (Siguria e Informacionit), FIEK Master, 2026/27.
Team: Ora Osmani, Erëza Ismajli, Nehar Jashari.

> **Status (Oct 30, 2026):** all measurements are done and committed: key and ciphertext sizes (RQ1), timing (RQ2), CPU and memory (RQ3), and the interop matrix (RQ4). Every figure and table in `figures/` and `tables/` is generated from the raw data in `results/`. See [Results](#results) for where each file is.

---

## What we measure

Encrypted files can be copied today and decrypted later, once a quantum computer can break X25519 ("harvest now, decrypt later"). Both age and GnuPG now offer hybrid post-quantum modes. This project measures what those modes cost and whether they interoperate:

| | Question | Measured as |
|---|---|---|
| **RQ1** | How much larger are post-quantum keys and encrypted files, and how does that grow with the number of recipients? | public key size, ciphertext overhead per recipient |
| **RQ2** | How do encryption and decryption times compare, from 1 KB to 1 GB? | wall time (hyperfine), median and IQR, PQ/classical ratio |
| **RQ3** | How much do CPU time and peak memory increase, and does it depend on the number of recipients? | cgroup v2 `cpu.stat` and `memory.peak`, GNU time max RSS |
| **RQ4** | Can GnuPG's post-quantum messages be decrypted by Sequoia-PGP and GopenPGP (RFC 9980), and the other way round? If not, where does it fail? | pass/fail and failure stage (import, encrypt, decrypt) per tool pair |

### Interoperability (RQ4)

The RQ4 runner checks every directed pair of GnuPG, Sequoia `sq`, and GopenPGP, including each tool against itself, with classical and PQC keys. Each repeat creates fresh keys and a fresh 100 KiB random input. The runner stops at the first failed stage, records complete stderr and tool versions, and checks decrypted output with SHA-256. Classical results are the positive control.

Run the three full repetitions in the pinned Docker image with `make interop`. This writes `results/interop/matrix.csv`, packet dumps under `results/interop/dumps/`, `results/interop/packets.csv`, and the two generated tables `tables/interop_matrix.tex` and `tables/interop_packets.tex`. Packet tables should be interpreted together with the raw dumps: a blank packet field means the installed dumper did not expose a matching field in its output, not that the packet property is absent.

When `gpg --list-packets` reads a v6 message it cannot parse, only its first two packets are meaningful. After them, gpg reads the encrypted bytes as packets, so the rest of that dump is noise and its length varies between repeats.

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

### How the benchmark measures (`bench/`)

**Conditions.** Each mode is measured at every file size, with 1, 10, and 50 recipients. Encryption is one condition. Decryption with one recipient is one condition. With 10 or 50 recipients, decryption is measured twice: with the key of the **first** recipient (r01) and with the key of the **last** one (r10 or r50). age tries the recipient stanzas in order, so the position matters. That gives 8 measured conditions per mode and size, 128 in total, plus 48 ciphertext-size conditions. [`bench/conditions.py`](bench/conditions.py) defines them and builds the exact tool calls, so the timing runs and the resource runs execute the same commands:

```text
age  encrypt:  age -R <recipients file> -o <out> <in>
age  decrypt:  age -d -i <identity> -o <out> <in>
gpg  encrypt:  gpg --batch --yes --pinentry-mode loopback --trust-model always --compress-algo none -r <fpr> ... -o <out> -e <in>
gpg  decrypt:  gpg --batch --yes --pinentry-mode loopback --trust-model always -o <out> -d <in>
```

**Keys** ([`bench/gen_keys.py`](bench/gen_keys.py)): 50 test recipients `r01` … `r50` per mode, in `keys/`. Every gpg recipient has its own `GNUPGHOME` with only its own key. The sender's keyring holds the 50 public certificates and no secret keys. `keys/MANIFEST.csv` lists every key.

**Sizes, RQ1** ([`bench/sizes.py`](bench/sizes.py)): public key sizes go to `key_sizes.csv`. Ciphertext sizes go to `sizes.csv`, measured once per condition, because they are deterministic. Overhead is ciphertext size minus input size. Each ciphertext is decrypted as r01 and checked against the input's SHA-256. `results/bench/inspect/` holds `age-inspect` or `gpg --list-packets` of the 1 KB ciphertexts, which show where the bytes go.

**Timing, RQ2** ([`bench/run_timing.py`](bench/run_timing.py)): `hyperfine --shell=none` with 2 warm-up runs, then 10 measured runs (3 for 1 GB). The output file is removed before every run. Conditions run in a shuffled order, and the seed is saved in `results/bench/seed_timing.txt`, so drift over time does not line up with one mode. For gpg, `gpg-agent` is started before the timing and stopped after it. The last run's output is checked against the input's SHA-256. Each measured run becomes one row in `timing.csv`, and the full hyperfine JSON is kept in `results/bench/raw/`.

**Phases.** `--phase pilot` runs 1 KB and 100 KB with 2 runs per condition, for checking the setup. `--phase full` runs everything. [`bench/run_all.py`](bench/run_all.py) runs keys, sizes, and timing in order and logs to `results/bench/run.log`.

**Resumable.** Every script skips conditions that already have results. `--force` measures again and replaces the old rows. `run_timing.py` and `run_resources.py` also take `--only <condition_id>` to run only some conditions. A failed tool call or hash check is written to the CSV, and then the run stops so it can be investigated.

CPU and memory (RQ3) are measured by [`bench/run_resources.py`](bench/run_resources.py) with the same commands, one fresh container per run. See [Reproducing the results](#reproducing-the-results).

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

## Reproducing the results

The full pipeline, in order:

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

CPU and memory (RQ3). Runs on the **host**, because it starts one fresh container per measured run: [`measure/run_measured.sh`](measure/run_measured.sh) reads the container cgroup's `cpu.stat` around the tool call and its `memory.peak`, and GNU time gives the tool's own max RSS. gpg-agent runs in the same cgroup, so its CPU and memory are included. `--phase pilot` runs only the small files. Before it, the measurement can be checked with:

```bash
python3 measure/validate_measured.py
```

It measures the baseline (`true`), confirms that gpg-agent is in the measured cgroup, and compares the two memory numbers.

```bash
make interop
```

Interop matrix (RQ4). Runs `interop/run_matrix.py --repeat 3`, then `interop/diagnose.py` (packet dumps of every PQC cert and ciphertext), then `interop/make_table.py`, all inside the image. It takes under a minute. Each run replaces `results/interop/matrix.csv` as a whole.

```bash
make figures
```

Regenerates every figure and table from `results/`. It runs on the host and needs the pinned analysis packages first. On Debian and Ubuntu, `venv` needs the `python3-venv` package (for example `python3.12-venv`):

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

Then run `make figures PYTHON=.venv/bin/python`. It starts with `analysis/sanity.py`, which stops everything if a condition or run is missing, an exit code is not 0, or a SHA-256 check failed, and which lists noisy conditions (IQR above 20% of the median). Then `analysis/figures.py` writes `figures/*.pdf`, and `analysis/tables.py` writes `tables/*.tex`: medians with IQR, PQ/classical ratios with 95% bootstrap confidence intervals, and a cost decomposition `a + b·recipients + c·bytes` per mode.

Full runs take hours and are done once, on the measurement machine, with nothing else running. All scripts are resumable and skip conditions whose output already exists.

The containers run as root, so the files they write into the mounted repo (`results/`, `figures/`, `tables/`, `keys/`, `tmp/`) belong to root on the host. Before `git add` or `git pull`, give them back to your user without `sudo`:

```bash
docker run --rm -v "$PWD:/work" -w /work pqc-bench chown -R "$(id -u):$(id -g)" results figures tables keys tmp
```

---

## Results

All raw data is in `results/`. Everything in `figures/` and `tables/` is generated from it by `make figures` and is never edited by hand.

| | Raw data | Figures and tables |
|---|---|---|
| **RQ1** sizes | `results/bench/key_sizes.csv` (200 keys), `results/bench/sizes.csv` (48 ciphertexts), `results/bench/inspect/` (`age-inspect` and `gpg --list-packets` output) | `tables/key_sizes.tex`, `figures/overhead_vs_recipients.pdf` |
| **RQ2** timing | `results/bench/timing.csv` (1,184 rows, pilot and full), `results/bench/raw/*.json` (hyperfine, every run) | `figures/time_vs_size.pdf`, `figures/time_ratio.pdf`, `figures/decrypt_position.pdf`, `tables/ratio_time.tex`, `tables/decompose_time.tex` |
| **RQ3** CPU and memory | `results/bench/resources.csv` (1,184 rows, pilot and full), `results/bench/resources_baseline.csv` (container baseline) | `figures/resources_vs_recipients.pdf`, `tables/ratio_cpu.tex`, `tables/decompose_cpu.tex` |
| **RQ4** interop | `results/interop/matrix.csv` (54 rows: 3 repeats × 9 pairs × 2 key types, with full stderr), `results/interop/packets.csv`, `results/interop/dumps/` | `tables/interop_matrix.tex`, `tables/interop_packets.tex` |

Run order and seeds: `results/bench/seed_timing.txt`, `results/bench/seed_resources.txt`, `results/bench/run.log`. Input hashes: `results/inputs.sha256`.

### Measurement environment

All measurements ran on one machine: AMD Ryzen 7 PRO 7840HS (16 logical CPUs), Ubuntu 24.04 on WSL2 (kernel 6.18.54.1, cgroup v2) under Windows 11, Docker Engine 29.8.2, on AC power. `results/env.json` and `tables/environment.tex` describe the timing run (captured 2026-10-26T23:08:13Z). The resource run's `env.json` is in git history at commit `64d0e1d` (captured 2026-10-26T21:43:38Z). Both runs used the same image build. The interop run (2026-10-30) used a rebuild of the image that differs only in the GopenPGP CLI wrapper.

### Interop at a glance

Identical in all 3 repeats:

| Encryptor → decryptor | Classical | PQC |
|---|---|---|
| each tool → itself | pass | pass |
| `sq` ↔ GopenPGP | pass | pass |
| gpg → `sq`, gpg → GopenPGP | pass | fails at import: GnuPG 2.5.22 does not read v6 certs (`packet(6) with unknown version 6`) |
| `sq` → gpg, GopenPGP → gpg | pass | fails at encrypt: neither finds a usable encryption subkey in GnuPG's `ky768_cv25519` cert |

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
