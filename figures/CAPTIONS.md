# Figure and table captions

Captions for every file in `figures/` and `tables/`, ready to paste into the paper. Below each caption are notes for the text: the values the figure shows, read from `results/` (full phase). Values are medians. "IQR" is the interquartile range over the runs of a condition.

All figures are made by `analysis/figures.py`, the RQ1–RQ3 tables by `analysis/tables.py`, and the interop tables by `interop/make_table.py`. Run `make figures` to regenerate them all.

---

## Figures

### `overhead_vs_recipients.pdf` (RQ1)

**Caption.** Ciphertext overhead (ciphertext size minus input size) against the number of recipients, for a 1 KB input. Both axes are logarithmic. Post-quantum modes are solid lines, classical modes dashed.

**Notes.**
- Overhead in bytes, at 1 / 10 / 50 recipients:

  | mode | 1 | 10 | 50 | per extra recipient |
  |---|---:|---:|---:|---:|
  | `age-x25519` | 200 | 1,082 | 5,002 | 98 |
  | `age-pq` | 1,659 | 15,672 | 77,952 | 1,557 |
  | `gpg-cv25519` | 169 | 1,033 | 4,873 | 96 |
  | `gpg-pqc` | 1,254 | 11,883 | 59,123 | 1,181 |

  "Per extra recipient" is (overhead at 50 − overhead at 1) / 49.
- Overhead grows linearly with the number of recipients in all four modes. Each post-quantum recipient adds about 16× (age) or 12× (gpg) the bytes of a classical one.
- The 1 KB file is used because it isolates the per-recipient cost. Overhead also changes slightly with file size, through the per-chunk framing of the encrypted stream. `results/bench/sizes.csv` has every size.

### `time_vs_size.pdf` (RQ2)

**Caption.** Encryption (top) and decryption (bottom) wall time against file size for one recipient, age (left) and GnuPG (right). Medians, with the IQR as error bars. Both axes are logarithmic. 10 runs per point (3 at 1 GB) after 2 warm-up runs.

**Notes.**
- Encryption, 1 recipient, in ms:

  | mode | 1 KB | 100 KB | 10 MB | 1 GB |
  |---|---:|---:|---:|---:|
  | `age-x25519` | 2.70 | 3.18 | 13.75 | 1,205.5 |
  | `age-pq` | 2.67 | 2.93 | 13.51 | 1,223.9 |
  | `gpg-cv25519` | 2.33 | 2.32 | 19.97 | 1,538.1 |
  | `gpg-pqc` | 11.89 | 13.64 | 28.75 | 1,443.6 |

- For age, the two modes cannot be told apart at any size.
- For GnuPG, PQC encryption has a fixed cost of about 10 ms that classical encryption does not have. It dominates small files and is lost in the I/O time at 1 GB.
- At 1 GB the times are mostly I/O, and the 1 GB decryption times are among the noisy conditions (IQR above 20% of the median).

### `time_ratio.pdf` (RQ2)

**Caption.** Wall-time ratio of the post-quantum mode to the classical mode of the same tool (age-pq / age-x25519, left; gpg-pqc / gpg-cv25519, right), for every matched condition: file size, number of recipients n, and operation. For decryption with several recipients, "first" and "last" mean the key of the first or the last recipient. Points are the ratio of medians. Bars are 95% percentile bootstrap confidence intervals (10,000 resamples of each mode's runs, fixed seed). The x axes are logarithmic, with different ranges.

**Notes.**
- **GnuPG encryption** is the only clear cost: 5.1× (1 KB, n=1) up to 10.9× (1 KB, n=50), 5.9× to 10.0× at 100 KB, and 1.4× to 6.2× at 10 MB. At 1 GB it falls to 0.94× to 1.08×.
- **GnuPG decryption:** 0.75× to 1.27×. Only one condition is slower with a CI above 1, and only slightly: 1.05× (1.01 to 1.07) at 10 MB, n=50, last recipient. The 1.27× at 1 GB, n=1 has a CI of 0.75 to 1.37. Several small-file conditions are slightly faster (CI below 1, for example 0.78× at 100 KB, n=1).
- **age:** 0.76× to 1.41×. PQC costs at most about 40%, at 100 KB with n=50 (encryption 1.41×, decryption as last recipient 1.40×). The 1 GB intervals are wide (3 runs).

### `decrypt_position.pdf` (RQ2)

**Caption.** Decryption wall time with 50 recipients, using the key of the first recipient (r01, solid) or the last recipient (r50, hatched), per file size. Medians, with the IQR as error bars.

**Notes.**
- age tries the recipient stanzas in order, so the last recipient pays for 49 failed attempts first. At 1 KB: `age-x25519` 2.51 → 6.60 ms, `age-pq` 3.00 → 9.05 ms. At 100 KB: 3.00 → 6.31 ms and 3.15 → 8.85 ms. The extra cost per skipped stanza is larger for ML-KEM.
- GnuPG shows no consistent position effect (1 KB: `gpg-cv25519` 6.35 / 6.71 ms, `gpg-pqc` 6.52 / 5.06 ms). This fits the format: each PKESK packet names its recipient's key ID, so gpg does not need to try the other recipients' packets.
- At 1 GB the position effect is lost in the I/O time and the run-to-run noise.

### `resources_vs_recipients.pdf` (RQ3)

**Caption.** CPU time (top), the tool process's maximum resident set size (middle), and the container cgroup's peak memory (bottom) for encryption, against the number of recipients, per file size. Each run uses a fresh container. CPU time is user + system from the cgroup's `cpu.stat` and includes gpg-agent. Max RSS is from GNU time. Cgroup peak is `memory.peak`. Medians, with the IQR as error bars. The dotted line is the baseline, a container that runs only `true`.

**Notes.**
- Baseline: 9.1 ms CPU, 1.2 MiB max RSS, 5.2 MiB cgroup peak.
- **CPU:** `gpg-pqc` is the only mode with a clear per-recipient cost: at 1 KB, 31.3 → 50.4 → 185.2 ms for 1 / 10 / 50 recipients, against 8.6 → 10.7 → 22.7 ms for `gpg-cv25519`. Both age modes stay close to each other (1 KB, n=50: 24.3 and 21.7 ms). The 1 GB CPU times are noisy and not monotonic in n. That is the I/O effect noted in RQ2.
- **Max RSS:** all modes use 4.5 to 5.2 MiB, except `age-pq` with 50 recipients, which reaches 7.0 to 7.2 MiB at every file size.
- **Cgroup peak:** about the same for all modes at a given file size: 5.2 to 7.2 MiB up to 100 KB (the highest is `age-pq` with 50 recipients), 14.6 to 16.9 MiB at 10 MB, and 1,057.8 to 1,060.6 MiB at 1 GB. It follows the file size, not the mode, so file data counted against the cgroup, not the tool's own memory, is the most likely cause. For small files it is dominated by the container baseline. The tool's own memory is better read from max RSS.

---

## Tables

### `key_sizes.tex` (RQ1)

**Caption.** Public key size per mode: for age, the recipient string; for GnuPG, the exported binary certificate. The last column is the size of the encryption-subkey packet alone.

Values: `age-x25519` 62 B, `age-pq` 1,959 B, `gpg-cv25519` 464 B (subkey packet 58 B), `gpg-pqc` 1,646 B (subkey packet 1,240 B).

### `ratio_time.tex` (RQ2) and `ratio_cpu.tex` (RQ3)

**Caption.** Post-quantum / classical ratio of median wall time (`ratio_time`) and median CPU time (`ratio_cpu`) per matched condition, with 95% percentile bootstrap confidence intervals (10,000 resamples, fixed seed).

### `decompose_time.tex` (RQ2) and `decompose_cpu.tex` (RQ3)

**Caption.** Least-squares fit of wall time (`decompose_time`) and CPU time (`decompose_cpu`) per mode and operation: a + b · recipients + c · bytes, over all runs. Decryption is fitted separately for the first and the last recipient, and n=1 counts for both.

### `environment.tex`

**Caption.** Measurement environment and tool versions, from `results/env.json`. The file describes the timing run (captured 2026-10-26T23:08:13Z). The resource run used the same machine and the same image build. The interop run used a rebuild that differs only in the GopenPGP CLI wrapper.

The "python" row is the image's Python, which drives the tools. The analysis ran on the host with the versions pinned in `requirements.txt`.

### `interop_matrix.tex` (RQ4)

**Caption.** Directed interoperability between GnuPG 2.5.22, Sequoia `sq` 1.4.0-pqc.1, and GopenPGP v3.4.1-proton, with classical keys (top) and post-quantum keys (bottom). Rows encrypt, columns decrypt. ✓ means decryption succeeded with a matching SHA-256. ✗ names the stage that failed. All three repeats agree, with fresh keys in each.

### `interop_packets.tex` (RQ4)

**Caption.** Packet formats each tool produces in post-quantum mode: version of the encryption key packet, public-key algorithm ID, PKESK version, and the encrypted-data packet. Read from `gpg --list-packets` and `sq packet dump` (`results/interop/dumps/`).

See `results/interop/SUMMARY.md` for the interpretation.
