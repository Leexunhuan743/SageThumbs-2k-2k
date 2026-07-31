# Architecture

How the workspace is split into crates, what COM surface the shell DLL exposes, and the design rules that keep hostile input away from Explorer's address space.

## Workspace Layout

Three shipped artifacts (the shell-extension DLL, the Options/Convert EXE, the CLI) are built from one rlib core plus a thin cdylib wrapper.

The core crate `sagethumbs2k_core` (`src/`) is rlib-only; the `dll/` crate is the `sagethumbs2k` cdylib that shims the `Dll*` entry points; the bins are `src/bin/app/main.rs` (`SageThumbs2K.exe`, the Options/Convert dialog) and `src/bin/cli.rs` (`st2k.exe`, console CLI + MCP server). Workspace `default-members` is `[".", "dll"]` so a bare `cargo build` emits all three; version 1.4.1 is shared through `[workspace.package]`, and the vendored `vendor/exr` carries a documented patch for the DWA table bloat.

## Decode Pipeline

Cheapest successful path wins, tier by tier: JPEG XL → Lepton (.lep) → `image` crate → raw-preview → WIC (HEIC/HEIF, AVIF, camera RAW, JPEG 2000) → TGA → ImageMagick child → raw-preview (full-fidelity) → lenient embedded-JPEG last resort.

The ladder is `decode_any_with_wic_target` in [[src/decode.rs]]: JPEG XL and Lepton are signature-gated pure-Rust tiers that run before the `image` crate (Lepton decodes to a bit-exact JPEG the image tier consumes); the camera-RAW baked-JPEG preview runs before WIC on the thumbnail/menu path and again after magick as the full-fidelity fallback; TGA (header-sanity-detected — it has no magic bytes) decodes with an explicit format BEFORE magick so a real TGA skips a doomed (20 s-capped) subprocess; the lenient embedded-JPEG scan (`largest_embedded_jpeg`) is the strict last resort, so a RAW's EXIF thumbnail still shows rather than a blank tile. ImageMagick runs as an isolated child process — no OS sandbox (no Job object / restricted token / SIL): `-limit` resource caps, a hardened app-local policy.xml, a named-semaphore concurrency gate, and an external kill timeout (20 s, 3 s for metafiles). SVG routes up front to resvg.

[[decoding#Decoder Tiers]] has the full ladder, and [[src/lib.rs#magick_available]] gates the magick-only Convert targets on compact installs.

## COM Surface

One in-proc COM server exposes five coclasses plus per-verb quick CLSIDs, all constructed by a single [[src/factory.rs#ClassFactory]] keyed on the requested CLSID.

The five are ThumbnailProvider (`IThumbnailProvider` + `IInitializeWithStream`), ExplorerCommand (modern menu), ContextMenu (classic owner-drawn menu), PreviewHandler, and PropertyStore. The entry points [[src/lib.rs#dll_get_class_object]], [[src/lib.rs#dll_register_server]], [[src/lib.rs#dll_unregister_server]], and [[src/lib.rs#dll_can_unload_now]] are plain functions in the rlib that the cdylib wraps in `#[no_mangle]` shims. A RAII [[src/lib.rs#ModuleRef]] tracks live objects for the unload count.

## Crash Isolation

The shell surface runs under `panic = "abort"` with `clippy::unwrap_used`/`expect_used` at warn — escalated to deny in the verify gate — and every COM entry point is wrapped in a panic guard — a malformed file cannot abort Explorer.

Hostile decode runs out-of-process in Explorer's dllhost surrogate, ImageMagick runs as an isolated child process with resource limits and kill timeouts, and decompression-bomb guards bound archive and pixel memory.

## Settings and Localization

Settings live in `HKCU\Software\SageThumbs2K`, read through `src/settings.rs`.

UI strings are baked in at build time: `build.rs` parses `locales/*.toml` into a static table (36 languages, no runtime TOML parser), and the `dll-i18n-subset` feature ships only the `menu_*` keys in the slim DLL that loads into Explorer.
