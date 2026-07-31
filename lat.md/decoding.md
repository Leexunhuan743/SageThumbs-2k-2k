# Decoding

How thumbnails, previews, and first pages are produced for the 327 supported formats, and which engine backs each tier: pure-Rust codecs, OS codecs, or the isolated ImageMagick child process.

## Decoder Tiers

The ladder, in order: JPEG XL → Lepton (.lep) → `image` crate → raw-preview (camera-RAW baked JPEG) → WIC (HEIC/HEIF, AVIF, camera RAW, JPEG 2000) → TGA → ImageMagick subprocess → raw-preview (full-fidelity) → lenient embedded-JPEG last resort.

JPEG XL and Lepton are signature-gated pure-Rust tiers before the `image` crate — a Lepton file decodes to a bit-exact JPEG the image tier consumes ([[decoding#Lepton]]). The first raw-preview tier runs only on the thumbnail/menu-preview path; the magick tier and the second raw-preview tier run only when `external` — the in-shell classic menu skips both. TGA has no magic bytes, so a header sanity check decodes it with an explicit format BEFORE magick — a real TGA skips a doomed (20 s-capped) subprocess. ImageMagick itself is an isolated child process: `-limit` resource caps, a hardened app-local policy.xml, a named-semaphore concurrency gate, and an external kill timeout (20 s, 3 s for metafiles). The lenient last resort (`largest_embedded_jpeg`) surfaces any decodable embedded JPEG — a RAW's EXIF thumbnail — rather than a blank tile. Video, PDF, SVG, ebooks/comics, and audio cover art take dedicated paths that bypass the ladder; [[architecture#Decode Pipeline]] is the pipeline overview.

## Video Frames

A representative frame (~30% into the file) is grabbed through Windows Media Foundation codecs streamed from disk via an `IMFByteStream` — no codec bytes ship with the app.

`src/video.rs` exposes the decode entry points and `src/vstream.rs` implements the byte stream; the MF imports are delay-loaded and gated behind a `media_foundation_available()` check before use.

## PDF Rendering

First-page thumbnails and previews use the in-box WinRT `Windows.Data.Pdf` rasterizer in `src/pdf.rs`.

The async plumbing (`IAsyncOperation`) comes from `windows-future` — zero bundled PDF engine.

## Quick Preview

The Space-bar viewer (EXE-only) renders Markdown via pulldown-cmark, syntax-highlighted code, archive listings, and OCR text from the WinRT path.

Archive listing comes from [[src/container/mod.rs#list_archive]] and OCR from the WinRT path behind [[src/lib.rs#ocr_probe]]. Local HTML preview is optional behind the `html-preview` feature (WebView2, scripts off) and default-off Settings toggles.

## Lepton

Dropbox's lossless JPEG recompression (.lep, 0xCF 0x84 magic) decodes through the pure-Rust `lepton_jpeg` crate (Apache-2.0, `#![forbid(unsafe_code)]`) to a bit-exact JPEG, which the `image` tier then decodes.

Caps come from `EnabledFeatures` (MAX_DIM per edge, 128 MiB JPEG stream, 2 worker threads on a per-call pool that exits with the decode — no threads linger in dllhost). The crate is **vendored + patched** (`vendor/lepton_jpeg/`, see SAGETHUMBS-PATCH.md): eleven crash-safety fixes found by independent audits — legacy-C++ overflow panics, an ignored parse boolean (a tiny file → Vec OOB in all builds), unbounded header resizes (~4 GiB OOM), an uncapped CRS restart-count loop (deflate-bomb OOM), a thread leak and SendError race in per-call pools, bounds/continuity validation for hostile thread-split headers, and a saturating early-eof truncation bound (EEE `max_dpos + 1` overflow in overflow-checked builds). Decode-only: no .lep encode or Convert target.
