# Performance & memory profiling

The recovery engines are I/O-bound, but careless per-file allocation can dominate
runtime and memory. This project ships a **heap-profiling harness** (the Rust
analogue of a dotMemory snapshot) so allocation regressions are easy to catch.

## Running the profiler

The [`dhat`](https://docs.rs/dhat) heap profiler is wired in behind the optional
`dhat-heap` feature and driven by the `heap_profile` example:

```sh
cargo run --profile profiling --features dhat-heap --example heap_profile
```

It runs a representative workload (carving a ~12 MiB image of many small JPEGs,
then an ext4 undelete pass) and on exit prints allocation totals/peaks to stderr
and writes `dhat-heap.json`. Open that file in the
[dhat viewer](https://nnethercote.github.io/dh_view/dh_view.html) to drill into
the allocation call sites — peak/total bytes, block counts, and where each came
from, just like a memory-profiler snapshot.

Without the feature the example simply runs the workload (and prints carving
throughput), which is handy as a quick timing check:

```sh
cargo run --release --example heap_profile
```

## What profiling found (and fixed)

The first run flagged enormous transient allocation: the carver allocated a fixed
**4 MiB** copy buffer for every recovered file and a **1 MiB** buffer for every
footer search. On the small-file workload that meant ~1 GB of churn to process
~12 MiB.

The fix was to size those buffers to the actual file and **reuse** them across
the whole carving run instead of allocating per file.

| Metric (same workload)     | Before    | After    | Change       |
|----------------------------|-----------|----------|--------------|
| Total bytes allocated      | 1.12 GB   | 72 MB    | **~15× less** |
| Allocation blocks          | 2,937     | 2,537    | fewer        |
| Carving throughput         | 69 MiB/s  | 103 MiB/s| ~1.5× faster |
| Peak heap                  | 25.7 MB   | 22.6 MB  | lower        |

Peak memory is now dominated by the single 8 MiB sequential scan buffer, which is
intentional and independent of how many files are recovered.

### Recovery backends

A second pass profiled the `undelete` path. The NTFS backend read **every MFT
record** through a helper that allocated a fresh 1 MiB temp buffer per call, so
scanning the MFT churned ~1 MiB per record. The fix reads each record straight
into its output buffer, and the FAT/exFAT/NTFS per-file copy buffers are now
sized to the file (capped at 1 MiB).

Workload: carve (as above) **plus** an NTFS volume with 90 deleted files.

| Metric                | Before  | After  | Change        |
|-----------------------|---------|--------|---------------|
| Total bytes allocated | 200 MB  | 72 MB  | **~2.8× less** |
| NTFS undelete time    | 15.7 ms | 6.5 ms | ~2.4× faster  |

The ~128 MB difference is exactly the per-record temp buffers that no longer
exist.

### ext4 read path

A third pass profiled the ext4 backend. Reconstructing a recovered file walked
its block map and allocated a **fresh `Vec` per block** (`read_block`), copying
each block into the output — so a 2 MiB file churned ~2,000 short-lived
allocations. The fix reads each block straight into the output buffer (sparse
holes stay zero-filled), and the jbd2 journal scan now reuses a single block
buffer instead of allocating one per journal block.

Workload: carve (as above) plus an ext4 volume with a 2 MiB deleted file.

| Metric                | Before  | After  | Change        |
|-----------------------|---------|--------|---------------|
| Total bytes allocated | 78.7 MB | 76.6 MB| ~2 MB less    |
| Allocation blocks     | 6,883   | 4,834  | ~2,000 fewer  |
| ext undelete time     | 11.2 ms | 3.2 ms | ~3.5× faster  |

The byte saving is one avoided copy of the file; the bigger win is eliminating
the per-block allocation traffic, which is what drives the ~3.5× speedup.

## Tips

- Profile in the `profiling` profile (release optimizations + line info) so the
  call sites in `dhat-heap.json` are meaningful.
- The harness is deterministic, so before/after comparisons are stable.
