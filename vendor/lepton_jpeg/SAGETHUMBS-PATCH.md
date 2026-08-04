# SageThumbs 2K patch to `lepton_jpeg` 0.5.8

This directory is the crates.io `lepton_jpeg` 0.5.8 package
(`microsoft/lepton_jpeg_rust` at tag `0.5.8`) plus the upstream `LICENSE.txt`
and `NOTICE.txt` (Apache-2.0), with nineteen hardening fixes (crash-safety,
DoS/memory-budget, and test-infrastructure; numbered below; each changed hunk
carries a `SAGETHUMBS PATCH (0.5.8)` marker comment).

## The bug

`src/structs/lepton_header.rs`, `LeptonHeader::read_compressed_lepton_header`
(the `early_eof_encountered` branch):

```rust
let mut max_last_segment_size = self.jpeg_file_size
    - u32::try_from(self.rinfo.garbage_data.len())?
    - u32::try_from(self.raw_jpeg_header_read_index)?
    - u32::try_from(SOI.len())?;
...
max_last_segment_size -= self.thread_handoff[i].segment_size;
```

For files whose declared `jpeg_file_size` is smaller than
`garbage_data + raw_jpeg_header + 2` (legacy C++ truncation files), the first
expression underflows and **panics** in any build with overflow checks
(debug/dev; tests). Under `panic = "abort"` — SageThumbs' release profile, and
the mode the shell extension runs in inside explorer/dllhost — that panic
becomes a process abort of the thumbnail host.

The same applies to the per-segment `-=` loop: a file whose declared size
doesn't cover the sum of its own segment sizes underflows there instead.

## The fix

All fixes are in `src/`; each is marked with a `SAGETHUMBS PATCH (0.5.8)`
comment. Together they enforce the invariant that a corrupt or malicious
`.lep` can produce a `LeptonError` — never a panic/abort inside the shell
host (see the repo's `src/safety.rs` and the `panic = "abort"` rationale in
the repo's `src/lib.rs`).

1. **`structs/lepton_header.rs` — early_eof size arithmetic** (`saturating_sub`
   on `jpeg_file_size - garbage - header - SOI` and the per-segment loop).
   Debug/overflow-checked builds panicked on legacy C++ truncation files
   whose declared size doesn't cover header + garbage (reproduced with a
   crafted EEE+GRB file; note that dropbox's `gold-legacy.lep` itself has NO
   EEE marker — the crash it actually triggered upstream is fix 2's
   `num_threads - 1` with an empty HH list). Release silently wrapped.
   Clamping to 0 preserves the "shorten the last segment" intent and fails
   cleanly.
2. **`structs/lepton_header.rs` — zero thread-handoff guard.** `num_threads - 1`
   underflowed (usize) on legacy C++ files with an empty HH list; now a clean
   `BadLeptonFile`.
3. **`structs/lepton_header.rs` — first `parse()` must reach a scan.**
   `JpegHeader::parse` returns `Ok(false)` when the raw JPEG header ends at
   EOI before any SOS; the boolean was ignored. A tiny hostile file
   (bare `FF D9` header + an HH marker) then indexed an empty `trunc_info`
   (`get_block_height(0)`) — a Vec OOB panic in ALL builds, release
   included. Requiring a real scan header also blocks the sibling
   huffman-index panic (huff tables stay at their 0xff defaults without an
   SOS, indexing `h_codes[0][255]` during recode).
4. **`structs/lepton_header.rs` — thread-range validation.** After the
   existing clamps, ranges must be non-inverted, contiguous
   (`start[i] == end[i-1]`), and start at row 0; otherwise
   `BlockBasedImage::merge`'s contiguity assert (a panic in ALL builds on
   the main thread for progressive files) is reachable with hostile HH
   values. Legit encoders always write such ranges (the format requires it
   for merge), so this rejects only corrupt/hostile headers.
5. **`structs/lepton_header.rs` — capped header length fields.** The HDR,
   FRS, and GRB length fields are hostile-controlled u32s; upstream
   `Vec::resize`d with no bound, so a ~40-byte file declaring ~4 GiB
   lengths OOM-aborted the process. All are now capped at
   `max_jpeg_file_size` (`BadLeptonFile` beyond). The same cap covers the
   CRS marker's `rst_count` loop bound (fix 10) — a deflate bomb (a few MiB
   of compressed input, itself bounded only by `compressed_header_size`)
   could otherwise decompress to GiB of restart-count entries and OOM.
6. **`jpeg/jpeg_write.rs` — bounded `rst_cnt` index.** The CRS marker's
   restart-count list can hold fewer entries than the file has scans;
   indexing it with the unbounded scan counter panicked in ALL builds. A
   missing entry now means "no injected restarts for this scan".
7. **`jpeg/block_based_image.rs` — saturating `luma_y_end - luma_y_start`.**
   Inverted ranges underflowed u32 (debug panic; release wrapped into a
   graceful OOM). Defense in depth behind fix 4.
8. **`structs/lepton_file_reader.rs` — saturating `jpeg_file_size_left`.**
   Declared file size smaller than the garbage blob underflowed u64 (debug
   panic on gold-legacy-style files).
9. **`structs/simple_threadpool.rs` — per-call pools must not leak threads.**
   Three coordinated changes:
   - Workers hold a **Weak** reference to the idle list instead of a strong
     Arc. Upstream's strong clone kept `Mutex<Vec<Sender>>` alive as long as
     a worker lived, so a per-call pool's channels never closed on drop and
     every decode leaked 1–2 permanently parked threads in dllhost.
   - Parked workers wait with `recv_timeout(250 ms)` and re-check pool
     liveness on timeout (their own captured Sender keeps the channel open,
     so plain `recv` never observes Disconnected once the pool is gone);
     they exit ≤250 ms after the pool drop. The liveness probe never
     re-pushes the Sender (each wake-up would duplicate the idle-list entry,
     and a worker later evicted by the NUM_CPUS cap would leave a stale
     Sender behind → `send` → `SendError` panic on the next submit).
   - `send` to a stale Sender (evicted worker) no longer unwraps; the task
     is re-queued onto a fresh worker.
   The process-global `DEFAULT_THREAD_POOL` is unaffected (never dropped;
   its Weak never expires, workers are reused). Regression tests in the
   vendored crate: `pool_drop_releases_idle_list` (drop releases the idle
   list) and `per_call_pool_workers_exit_on_drop` (workers actually
   terminate ≤ 250 ms after the drop — asserted via a cfg(test)-only
   liveness counter), plus the SageThumbs `decode::lepton` suite.
10. **`structs/lepton_header.rs` — capped CRS `rst_count` loop.** (See the
    note under fix 5.) `rst_count` is a hostile u32 loop bound; the loop
    reads 4 bytes per entry from the zlib stream, so an unbounded count is
    an OOM entry point even though `compressed_header_size` itself is
    capped. Legit files carry one small entry per scan.
11. **`jpeg/truncate_components.rs` — saturating `max_d_pos[i] + 1`.**
    The EEE marker's `max_dpos[0..3]` fields are hostile-controlled u32s read
    with no validation (only `max_sah` gets a `u8::try_from`); a file
    declaring `0xFFFFFFFF` overflowed the `+ 1` in `set_truncation_bounds`
    (header-parse main thread, no catch_unwind) and panicked in
    overflow-checked builds (dev/tests; reproduced with "attempt to add with
    overflow" at truncate_components.rs:69). Release wrapped to 0 and failed
    cleanly (no shell-host abort), but the invariant "hostile .lep → error,
    never a panic" was violated in every overflow-checked build. Saturating:
    `u32::MAX` now means "no truncation", which is what the value represents
    (real encoders write actual sizes; a wrapped zero would silently empty
    the image).
12. **`jpeg/jpeg_write.rs` — u8 eob-scan underflow in `encode_ac_prg_sa`.`**
    The scan walks `bpos: u8` DOWN from `to` while `bpos >= from`. With a
    hostile SOS declaring Ss=0/Se≥1 (the decode-side header accepts from==0;
    only the encode side rejects it) and a block with no ±1 coefficient (an
    all-zero block is a valid hostile decode), the upstream `bpos -= 1`
    underflowed: overflow panic in debug, and in RELEASE a wrap to 255 that
    indexed `block[255]` of a `[i16; 64]` — an index-OOB abort in ALL builds
    on the main thread (process_progressive → jpeg_write_entire_scan, no
    catch_unwind). The C++ reference uses a signed int and exits at -1;
    stopping at 0 is the equivalent scan. Regression:
    `encode_ac_prg_sa_from_zero_all_zero_block_does_not_underflow`
    (unit-tests the private fn directly — the only deterministic trigger,
    since a decode-level repro needs a valid progressive bitstream whose SOS
    was rewritten).
13. **`jpeg/jpeg_header.rs` — decode-side 4-color (CMYK) gate.** The shared
    `JpegHeader::parse` accepted up to 4 components (`cmpc > 4`) while the
    C++ reference rejects 4-color JPEGs at header-parse time
    (`custom_exit(UNSUPPORTED_4_COLORS)`) and the Rust port only kept that
    rejection on the ENCODE side (jpeg_read.rs). A hostile 4-component .lep
    reached `RowSpec::get_row_spec_from_index`'s
    `image_data.len() <= COLOR_CHANNEL_NUM_BLOCK_TYPES` assert on a decode
    worker — a panic in ALL builds (release: process abort in the shell
    host; progressive files hit it on the MAIN thread via
    jpeg_write_entire_scan with no catch_unwind). The shared parse gate now
    rejects `cmpc > COLOR_CHANNEL_NUM_BLOCK_TYPES` (3) as `UnsupportedJpeg`;
    the encode-side check stays as defense in depth. Regression:
    `tests/hostile_decode.rs::four_component_sof_rejected`.
14. **`structs/lepton_header.rs` — MCU-row grid alignment for thread ranges**
    (completes fix 4). Fix 4 validated inversion/contiguity/start-at-0 but
    not MCU alignment. `RowSpec::get_row_spec_from_index` emits luma_y
    values that are multiples of `component_multiple[0] = bcv[0]/mcuv`, and
    each decode thread consumes WHOLE MCU rows; a boundary between two grid
    points makes the thread's BlockBasedImage capacity (computed from
    `(end-start)/bcv[0]`) smaller than the blocks the MCU row emits,
    tripping `append_block`'s capacity assert on a worker — a panic in ALL
    builds. Legit encoders always split on MCU rows (C++
    `crystallize_thread_handoff` uses `mcu/mcuh` grid rows). Off-grid
    boundaries are now `BadLeptonFile`. Regression:
    `tests/hostile_decode.rs::off_grid_thread_range_rejected`.
15. **`structs/thread_handoff.rs` — validate `num_overhang_bits`.** The HH
    marker carries it raw; C++ encoders write 0..=7 (64 - cbit2 with cbit2 in
    (56, 64]) and 0xff is the C++ legacy-mode marker (unreachable here —
    legacy files carry no HH marker and are rejected by fix 2 before
    deserialize). A value > 8 flowed into
    `BitWriter::reset_from_overhang_byte_and_num_bits`, where `64 - num_bits`
    underflows (debug panic; release wraps and trips the `has_no_remainder`
    assert on the decode worker) — an abort in the shell host. deserialize
    now rejects it as `BadLeptonFile` (its return type is the crate error,
    not io, so the clean codes work). Regression:
    `structs::thread_handoff::tests::overhang_bits_validated`.
16. **`structs/lepton_header.rs` — bound the whole decompressed header**
    (completes fix 5/10). Three coordinated changes:
    - The ZlibDecoder is wrapped in `.take(max_jpeg_file_size)` so the TOTAL
      decompressed stream — every marker's payload together, not just one
      length field — is bounded. Without this, a deflate bomb (stored blocks
      expand ~13107x) could grow the recovery-marker section to GiB across
      many markers, an OOM abort. take() exhaustion surfaces as
      UnexpectedEof (which the marker loop treats as stream end), so the
      limit() check after the loop turns "budget hit" into a clean error
      instead of silently accepting a truncated header.
    - The CRS `rst_count` cap (fix 10) is now the byte-consistent
      `max_jpeg_file_size / 4` (it counts u32 ENTRIES; the old per-marker
      cap alone still allowed a 512 MiB Vec).
    - The trailing `assert!(remaining == 0)` — reachable on 1-2 trailing
      bytes after the last marker (the 3-byte prefix read breaks on
      UnexpectedEof first) — is a clean `BadLeptonFile`, never a panic.
    Regressions: `tests/hostile_decode.rs::crs_entry_count_capped`,
    `trailing_bytes_after_markers_clean_error`.
17. **`jpeg/block_based_image.rs` — merge contiguity assert → clean error.**
    The upstream `assert!(dpos_offset == contents.len())` in `merge` is a
    PANIC in ALL builds, reachable on the MAIN thread for progressive files
    (process_progressive, no catch_unwind) from a hostile EEE truncation:
    `max_dpos` cutting through a middle thread partition stops that
    partition short (the decode gate), so the next partition's dpos_offset
    no longer matches the accumulated contents. The C++ reference has no
    such assert (its reads clamp dpos to trunc_bc-1), but the Rust JPEG
    writers index the merged image by the full-height layout, so a short
    partition cannot be tolerated without a fill pass — a clean error is the
    safe middle ground. Regression:
    `jpeg::block_based_image::tests::merge_with_gate_truncated_partition_is_clean_error`
    (deterministic; an end-to-end trigger is impractical: baseline files
    never merge, empty tail partitions are dropped by the multiplexer, and
    the alignment math makes a truncated-but-nonempty partition pair
    unreachable through hostile EEE values alone).
18. **`jpeg/block_based_image.rs` — global coefficient-block budget.** The
    upstream Rust port dropped the C++ reference's memory budget
    (`jpgcoder.cc:734-752`: `mem_limit = 1280 MiB - 128 MiB * (MAX_NUM_THREADS
    - 1) = 384 MiB` with `MAX_NUM_THREADS = 8`, then
    `max_number_of_blocks = (mem_limit/4) * 3 / 128 = 2,359,296`). A
    16384^2 4:4:4 image needs ~1.5 GiB of coefficient buffers plus another
    full copy for progressive merge — a transient ~3 GiB peak inside
    dllhost/explorer, far beyond the nominal per-decode budget. Unlike C++
    (which clamps allocations to the budget and lets decoding proceed), the
    Rust capacity asserts cannot tolerate a clamped buffer, so components
    whose whole-image block count exceeds their share of the budget are
    rejected up front with a clean `OutOfMemory` error. Regression:
    `jpeg::block_based_image::tests::new_rejects_component_over_global_block_budget`
    (+ positive control `..._within_global_block_budget`).
19. **`src/helpers.rs` — fixture path resolution.** `read_file` used the
    compile-time `WORKSPACE_ROOT` env (the upstream checkout root); it now
    resolves via `CARGO_MANIFEST_DIR` so the crate builds without any
    external environment variable. The upstream images/ corpus is NOT
    vendored (it would add ~63 MiB to the repo); CI runs the fixture-free
    subset — the full lib suite with the 22 image-file tests skipped by
    exact name plus `tests/hostile_decode.rs` (previously CI only ran
    `simple_threadpool` and the hostile tests were orphaned outside every
    job). A full local run needs the upstream `images/` directory copied to
    `vendor/lepton_jpeg/images/`.

## Verification

- `cargo test` (debug): `decode::lepton::tests::*` plus the C++-interop
  samples (dropbox `gold-legacy.lep`, `iphone16.lep`, `narrowrst.lep`) must
  not panic; legacy-format files decode or return `Err`, never abort.
  Observed: `iphone16.lep` decodes to the full 3264×2448 JPEG (pixel-exact
  to `iphone.jpg` — see
  `decode::lepton::tests::cpp_encoded_iphone16_decodes_pixel_exact_to_source_jpeg`;
  the assertion covers decoded pixels, not the reconstructed JPEG bytes);
  `gold-legacy.lep` returns `BadLeptonFile` (empty thread handoffs);
  `narrowrst.lep`'s version byte is unverified in this corpus — the upstream
  0.5.8 sample is version 1, and no C++ build here can produce a v4 file —
  the corpus test accepts Ok or Err either way.
- `cargo test --release`: same suite, release overflow-checking off — the
  regression this patch prevents would previously have been silent in
  release; the debug-mode panic is the reproducible symptom.
- `cargo test --manifest-path vendor/lepton_jpeg/Cargo.toml --lib -- --skip <22 image-file tests>`
  plus `--test hostile_decode`: the fixture-free CI set (skip list in
  `.github/workflows/ci.yml`). No `WORKSPACE_ROOT` environment variable is
  required. With the upstream `images/` directory copied to
  `vendor/lepton_jpeg/images/`, the skip list can be dropped for a full run.
- `tests/hostile_decode.rs` (6 tests): the patch 13/14/16 discriminators plus
  three added in the audit follow-up — `zero_thread_handoffs_is_clean_error`
  (patch 2, previously only corpus-covered), `early_eof_segment_loop_is_bounded`
  (patch 1's per-segment `-=` loop, previously unreachable: the single-threaded
  early_eof tests never iterate `0..num_threads-1`; debug-only discriminator —
  release wraps rather than panics), and
  `decompressed_header_over_budget_is_clean_error` (patch 16's take-budget
  `limit()==0` branch, previously untested — a zlib stream that genuinely
  expands to the 128 MiB cap).
- `decode::lepton::tests::lepton_mutations_never_panic`: 400 deterministic
  bit-flip/truncation mutations + an oversized-declared-size file must never
  panic, only Ok/Err.

- `decode::lepton::tests::lepton_eee_maxdpos_saturates`, `..._early_eof_size_arithmetic_is_bounded`,
  `..._garbage_size_underflow_is_bounded`, `..._thread_ranges_are_validated`,
  `..._header_lengths_are_capped`: deterministic hostile-header constructions
  (a real raw JPEG header + crafted EEE/GRB/HH markers, lengths and declared
  sizes chosen per patch) that panic on the unpatched code paths above and
  must now return a clean error — or, for `max_dpos = u32::MAX`, decode
  normally.
- Patch 6 (bounded `rst_cnt`) has no deterministic in-repo trigger: reaching
  the recode-time index needs a restart-carrying (DRI) v1 file whose scan
  data still decodes AND whose CRS table is shorter than its scan count —
  no corpus sample has the short-table shape (the corpus's restart-carrying
  JPEGs — iphone/iphoneprogressive/androidprogressive — all roundtrip
  cleanly, and narrowrst's odd-restart shape is unencodable here). The
  mutation fuzz patrols the surrounding space; revisit when a short-CRS
  sample lands in the corpus.

Remove this override after upstream ships the fixes (upstream `main` still
carries the unchecked arithmetic, the ignored parse boolean, the unbounded
header resizes, the unvalidated thread ranges, the unbounded `rst_cnt` index,
the uncapped CRS loop, the unguarded `max_d_pos + 1`, the thread-pool Arc
leak, the send-unwrap, the u8 eob-scan underflow, the missing 4-color gate,
the missing MCU-grid alignment check, the unvalidated overhang bits, the
unbounded decompressed header, and the merge-contiguity assert — and the
LepViewer/LepThumb project vendors the same unfixed 0.5.8).
