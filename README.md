# Quantum-Safe File Encryption in Practice

A reproducible benchmark and interop test suite comparing **classical** and **hybrid post-quantum** (ML-KEM-768 + X25519) file encryption in [age](https://github.com/FiloSottile/age) and [GnuPG](https://gnupg.org).

Seminar project, Information Security (Siguria e Informacionit), FIEK Master, 2026/27.
Team: Ora Osmani, Erëza Ismajli, Nehar Jashari.

## Research questions

| | Question | Measured as |
|---|---|---|
| **RQ1** | How much larger are PQ keys and ciphertexts? | key size, ciphertext overhead per recipient |
| **RQ2** | How do encryption and decryption times compare? | hyperfine wall time, median and IQR |
| **RQ3** | How much do CPU and peak memory grow? | cgroup v2 `cpu.stat`, `memory.peak`, GNU time max RSS |
| **RQ4** | Do GnuPG PQ messages interoperate with Sequoia and GopenPGP (RFC 9980)? | pass/fail and failing stage per tool pair |

## Experiment design

| | Values |
|---|---|
| Modes | `age-x25519`, `age-pq`, `gpg-cv25519`, `gpg-pqc` |
| File sizes | 1 KB, 100 KB, 10 MB, 1 GB (random bytes) |
| Recipients | 1, 10, 50 |
| Runs | 10 per condition (3 for 1 GB), after 2 warm-ups |
| Fixed | machine, tool versions, keys; no signing, no compression, binary output |

- Each PQ mode is compared with the classical mode of the same tool.
- With 10 or 50 recipients, decryption is measured as the first and the last recipient, because age tries stanzas in order.
- Run order is shuffled with a saved seed. Every decryption is checked against the input's SHA-256.
- `gpg-pqc` uses an Ed25519 primary key plus a `ky768_cv25519` encryption subkey, so the two gpg modes differ only in the encryption subkey. GnuPG's `pqc` shortcut is not used, because it switches to brainpool curves.
- RQ3 runs one fresh container per measured run, since `memory.peak` never decreases within a cgroup.

All commands are defined in [`bench/conditions.py`](bench/conditions.py), so timing and resource runs execute the same tool calls.

## Requirements

- Docker. Everything runs in the `pqc-bench` image.
- For RQ3: Linux with cgroup v2 and kernel ≥ 5.19 (`stat -fc %T /sys/fs/cgroup` prints `cgroup2fs`).
- GNU Make (WSL2 on Windows).

## Reproduce

```bash
make image        # build the image (compiles GnuPG and Sequoia, slow the first time)
make smoke        # versions + one round trip per tool; must pass first
make inputs       # input files in data/ and hashes in results/inputs.sha256
make env          # results/env.json; full runs refuse to start without it
```

In a fresh clone, the committed hashes do not match new random inputs. Regenerate both inside the image with `sh measure/make_inputs.sh --force`.

```bash
# RQ1 + RQ2: keys, sizes, timing
docker run --rm -v "$PWD:/work" -w /work pqc-bench python3 bench/run_all.py --phase full

# RQ3: CPU and memory (on the host; starts one container per run)
python3 measure/validate_measured.py
python3 bench/run_resources.py --phase full

# RQ4: interop matrix, 3 repeats, packet dumps, tables
make interop

# Figures and tables (host, pinned packages)
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
make figures PYTHON=.venv/bin/python
```

- Use `--phase pilot` to check the setup on the small files first. Full runs take hours.
- All scripts are resumable and skip finished conditions. `--force` re-measures; `--only <condition_id>` runs a subset.
- `make figures` runs `analysis/sanity.py` first and stops on any missing run, non-zero exit code, or failed hash check.
- Containers run as root. Before `git add`, fix ownership:

  ```bash
  docker run --rm -v "$PWD:/work" -w /work pqc-bench chown -R "$(id -u):$(id -g)" results figures tables keys tmp
  ```

## Results

Figures and tables are generated from `results/` by `make figures` and never edited by hand.

| | Raw data | Output |
|---|---|---|
| **RQ1** | `results/bench/key_sizes.csv`, `sizes.csv`, `inspect/` | `tables/key_sizes.tex`, `figures/overhead_vs_recipients.pdf` |
| **RQ2** | `results/bench/timing.csv`, `raw/*.json` | `figures/time_vs_size.pdf`, `time_ratio.pdf`, `decrypt_position.pdf`, `tables/ratio_time.tex`, `decompose_time.tex` |
| **RQ3** | `results/bench/resources.csv`, `resources_baseline.csv` | `figures/resources_vs_recipients.pdf`, `tables/ratio_cpu.tex`, `decompose_cpu.tex` |
| **RQ4** | `results/interop/matrix.csv`, `packets.csv`, `dumps/` | `tables/interop_matrix.tex`, `interop_packets.tex` |

Seeds and logs: `results/bench/seed_timing.txt`, `seed_resources.txt`, `run.log`.

**Machine:** AMD Ryzen 7 PRO 7840HS, Ubuntu 24.04 on WSL2 (kernel 6.18.54.1, cgroup v2), Docker Engine 29.8.2, on AC power. Details in `results/env.json` (timing run) and commit `64d0e1d` (resource run).

### Interop (identical in all 3 repeats)

| Encryptor → decryptor | Classical | PQC |
|---|---|---|
| each tool → itself | pass | pass |
| `sq` ↔ GopenPGP | pass | pass |
| gpg → `sq` / GopenPGP | pass | fails at import: GnuPG 2.5.22 cannot read v6 certs |
| `sq` / GopenPGP → gpg | pass | fails at encrypt: no usable subkey in GnuPG's `ky768_cv25519` cert |

In a gpg packet dump of an unparseable v6 message, only the first two packets are meaningful.

## Tools

Pinned versions, checksums, and signing keys: [`docker/VERSIONS.md`](docker/VERSIONS.md).

| Tool | Version |
|---|---|
| Base image | `debian:trixie` (digest pinned, OpenSSL 3.5) |
| age | 1.3.1 |
| GnuPG | 2.5.22 (built from verified source) |
| Sequoia `sq` | 1.4.0-pqc.1 (`crypto-openssl`) |
| GopenPGP | v3.4.1-proton, via [`interop/gopenpgp-cli`](interop/gopenpgp-cli) |
| hyperfine, GNU time, Python | Debian trixie |

## Layout

```text
docker/     Dockerfile, VERSIONS.md, smoke test
bench/      keys, sizes, timing, resource runs
measure/    cgroup measurement, env capture, input generation
interop/    tool adapters, matrix, packet diagnosis, GopenPGP wrapper
analysis/   statistics, figures, tables, sanity checks
results/    raw data (committed)
figures/    generated figures (committed)
tables/     generated LaTeX tables (committed)
data/ keys/ generated inputs and test keys (not committed)
```

## Safety

Only random test files and freshly generated test keys are used. Everything runs locally in throwaway containers and connects to nothing. Security bugs found in a tool are reported to its developers before publication.

## Acknowledgements

The GopenPGP CLI wrapper is adapted from `pqcrypt` in [detrin/pqc](https://github.com/detrin/pqc) (MIT License, Daniel Herman).
