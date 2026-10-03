# Control-plane measurements (C12)

Status: one run on one machine, recorded with its method. **These are descriptions, not thresholds.** No test
asserts a speed, nothing gates on a number, and nothing here is a capacity claim for a deployment (none exists).
This repository is maintained by the Redact Secret project; the numbers are project-maintained, not independent
validation.

## What is and is not measured

Measured, each separately: request latency, queue and submission limits, database contention, and ledger batch
export growth, all for the **custodian control plane** (operator CLI commands, SQLite store, in-memory ledger
backend, audit export, whole-ledger verification).

Not measured, and not to be inferred from these tables: scanner or kernel performance, engine time, sandbox
startup, worker staging of a real corpus, a Git-backed ledger or any network round trip, a real signer process,
disk behavior on the production volume, or behavior under hostile load. The "engine" in these runs is an
in-process scripted double; the operations timed are the control plane's own.

Never traded for speed: isolation is not touched (no worker runs in these timings), every command runs its full
path including the startup check against the whole ledger, every audit event is written and exported, and
budgets are never reset between measurements (each section builds a fresh world with synthetic data).

## Method

`crates/custodian-cli/examples/c12_measure.rs`, run as

```
cargo run --release -p custodian-cli --example c12_measure          # N = 40
C12_MEASURE_N=200 cargo run --release -p custodian-cli --example c12_measure
```

The example prints markdown. Under `cargo test` only a tiny-size consistency test of the same code runs
(`measurements_run_and_stay_consistent_at_a_tiny_size`); it asserts counts, never time.

- World: synthetic population of 4 entries, run-unit limit 1,000,000 so budgets never bind, a fresh temporary
  SQLite file (WAL, `synchronous = FULL`), the in-memory ledger backend, test-generated keys.
- Timer: `std::time::Instant` around one library call (`Control::execute`) per sample; wall clock, one process.
- Percentiles: nearest-rank over the samples of a batch. Small samples (n = 40) make p95 and max noisy.
- Machine: Apple M4, macOS (Darwin 25.5.0) arm64, rustc 1.98.1, release profile, local SSD, 2026-10-03.
  Other tasks were running on the machine; treat differences under about 2x as noise.

## Results (single run, N = 40)

### Request latency, by ledger size

Each batch of 40 requests is submitted, approved and queried; the batch is then exported before the next one, so
the startup check that every state-changing command runs walks a larger ledger.

| operation (ledger records before the batch) | n | p50 ms | p95 ms | max ms |
| --- | --- | --- | --- | --- |
| submit (0 records) | 40 | 0.87 | 2.71 | 2.92 |
| approve (0 records) | 40 | 1.47 | 2.98 | 6.86 |
| status (0 records) | 40 | 0.15 | 0.33 | 0.39 |
| export of the batch / `verify all` after it | 1 | 58.59 / 35.70 | | |
| submit (124 records) | 40 | 28.64 | 67.91 | 99.09 |
| approve (124 records) | 40 | 26.43 | 68.62 | 126.73 |
| status (124 records) | 40 | 0.26 | 0.84 | 5.24 |
| export of the batch / `verify all` after it | 1 | 73.75 / 44.97 | | |
| submit (245 records) | 40 | 29.51 | 45.12 | 73.43 |
| approve (245 records) | 40 | 29.44 | 41.46 | 48.62 |
| status (245 records) | 40 | 0.21 | 0.65 | 0.86 |
| export of the batch / `verify all` after it | 1 | 53.86 / 43.18 | | |

Reading: reads (`status`) do not touch the ledger and stay under a millisecond. Every state-changing command
runs the startup check, which walks and verifies the entire ledger (`walk_ledger`), so its latency moves from
about a millisecond with an empty ledger to about 30 ms with a few hundred records. This is the same walk
`verify all` performs (next table: roughly 0.11 to 0.12 ms per record). The cost is therefore proportional to
ledger size, and nothing in the control plane caches a verified prefix. Register entry R-7; extrapolating the
slope to tens of thousands of records (not measured) would put one command in the seconds, before any Git
backend cost. The in-memory backend hides the cost of `git fetch` on the real backend.

### Database contention

Approvals of distinct, pre-submitted requests, each thread on its own connection to the same file.

| threads | approvals | approved | refused | wall ms | approvals/s |
| --- | --- | --- | --- | --- | --- |
| 1 | 20 | 20 | none | 34 | 594 |
| 2 | 40 | 40 | none | 85 | 470 |
| 4 | 80 | 80 | none | 133 | 600 |
| 8 | 160 | 160 | none | 241 | 665 |

Reading: no `Busy` refusals at 8 writers (the default busy timeout is 5 s), every approval was recorded exactly
once, and throughput did not scale with threads, as expected for a single serialized writer plus a shared
in-memory ledger lock. Correctness under contention (exactly the limit reserved, one winner for the same
request, one execution for a duplicate dispatch) is asserted by `c12_concurrency.rs`, not by these numbers.

### Queue and submission limits

| measure | value |
| --- | --- |
| intake queue capacity (`MAX_PENDING_QUEUE`) | 4096 |
| pending submissions capacity (`MAX_PENDING_SUBMISSIONS`) | 1024 |
| claim and enqueue latency over 400 deliveries, p50 / p95 / max ms | 0.25 / 0.50 / 1.58 |
| 40 submissions | all `submitted`, 30 ms total |

Both limits refuse and never evict (`a_full_queue_refuses_and_never_evicts`, and the submission-limit test in
`crates/custodian-store/tests/intake.rs`). Filling to capacity was not timed in this run. Retention of done
queue rows and cancelled submissions is not implemented (register HG-4).

### Ledger batch export growth

| reservations exported | audit events | ledger files | ledger bytes | export ms | ms per event | `verify all` ms |
| --- | --- | --- | --- | --- | --- | --- |
| 20 | 62 | 64 | 63,832 | 21.8 | 0.352 | 7.7 |
| 40 | 122 | 124 | 125,076 | 37.3 | 0.306 | 16.9 |
| 80 | 242 | 244 | 247,636 | 69.6 | 0.288 | 32.8 |
| 160 | 482 | 484 | 492,756 | 110.5 | 0.229 | 56.0 |

Reading: about 1 KiB of ledger per audit event (one canonical signed file per event, two files of overhead per
batch for the checkpoint records) and roughly three events per approved request. Export cost is roughly
linear in events (0.23 to 0.35 ms per event, including signing and the self-check verification); whole-ledger
verification is roughly linear in files. A Git ledger adds a commit and a push per write (`GitBackend` is
compare-and-swap on the remote), so its growth is different and was not measured.

## What would change these numbers

A real Git remote (network, fetch per write), a signer in another process (an IPC round trip per record),
`synchronous = FULL` on a slower volume, a larger ledger, a busy host, or a debug build (not measured here, and much slower for hashing and
signing; the test suite runs in debug). Repeat the measurements on the production host
class before any capacity statement, and keep the method.
