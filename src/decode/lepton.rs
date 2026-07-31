//! Lepton (.lep) — Dropbox's lossless JPEG recompression. Pure-Rust tier: the
//! `lepton_jpeg` crate (Apache-2.0, `#![forbid(unsafe_code)]`, fuzzed upstream)
//! decodes the container back to a bit-exact JPEG byte stream, which the `image`
//! tier then decodes. Bomb-guarded by the crate's own width/height/file-size caps
//! below plus the `image` tier's MAX_DIM / MAX_ALLOC limits.

use super::*;
// Alias avoids colliding with this module's own `decode_lepton` (the tier fn).
use lepton_jpeg::decode_lepton as lepton_decode;
use lepton_jpeg::{EnabledFeatures, LeptonThreadPriority, SimpleThreadPool};

/// Lepton signature: the tau symbol `0xCF 0x84` (LEPTON_FILE_HEADER). The version
/// byte at [2] and the 'Z'/'X' JPEG-type byte at [3] are validated by the decoder
/// itself. The 0xCE 0xB6 zlib-outer variant and UJG ("UJ") are NOT supported by
/// `lepton_jpeg` — deliberately not matched here; such files fall through to the
/// other tiers and fail harmlessly (stock icon).
pub(super) fn looks_like_lepton(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0xCF, 0x84])
}

/// Decode a Lepton file: lepton → bit-exact JPEG bytes → the `image` tier.
///
/// Caps: JPEG dims ≤ [`limits::MAX_DIM`], decoded-JPEG byte stream ≤ 128 MiB (the
/// crate's own compat default; bounds the intermediate buffer), input already
/// bounded by the shared MAX_INPUT_BYTES read path. Errors → E_FAIL, logged as a
/// tier breadcrumb like every other tier.
pub(super) fn decode_lepton(bytes: &[u8]) -> Result<DynamicImage> {
    // Caps aligned with the centralized budgets (decode.rs `limits`). The
    // accept/reject flags follow the crate's `compat_lepton_vector_read` so
    // real-world C++-encoded files decode; the header's own flag bits may flip the
    // 16-bit estimate flags (the crate mutates the features itself during parse).
    let features = EnabledFeatures {
        progressive: true,
        reject_dqts_with_zeros: false,
        max_jpeg_width: limits::MAX_DIM,
        max_jpeg_height: limits::MAX_DIM,
        use_16bit_dc_estimate: true,
        use_16bit_adv_predict: true,
        accept_invalid_dht: true,
        max_partitions: 8,
        // Bounds decode parallelism; the pool below is per-call anyway.
        max_processor_threads: 2,
        // Declared original-JPEG size cap (128 MiB — the crate's compat default).
        max_jpeg_file_size: 128 * 1024 * 1024,
        stop_reading_at_eoi: false,
    };
    // Per-call pool, NOT the crate's global DEFAULT_THREAD_POOL: a per-call pool is
    // dropped when decode returns and its workers exit with it (the vendored crate
    // uses a Weak reference to the idle list — see vendor/lepton_jpeg/SAGETHUMBS-PATCH.md),
    // so no threads linger inside dllhost/explorer (the project's
    // no-global-pool-in-the-shell rule — the same reason rayon is kept out of the DLL).
    let pool = SimpleThreadPool::new(LeptonThreadPriority::Normal);
    let mut jpeg = Vec::new();
    lepton_decode(&mut std::io::Cursor::new(bytes), &mut jpeg, &features, &pool).map_err(|e| {
        crate::safety::log_debug(&format!("lepton decode error: {e:?}"));
        Error::from(E_FAIL)
    })?;
    // The same entry the jxl / raw-preview tiers end at: image crate + MAX_DIM /
    // MAX_ALLOC limits + CMYK handling + ICC→sRGB. `jpeg` is ≤ 128 MiB by the cap
    // above, so the allocation is bounded before this call.
    super::decode_with_image(&jpeg)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic noisy JPEG (reuses the pattern of `decode::tests::noisy_jpeg_bytes`,
    /// which is not accessible from this child module).
    fn test_jpeg(w: u32, h: u32) -> Vec<u8> {
        let mut img = image::RgbImage::new(w, h);
        for y in 0..h {
            for x in 0..w {
                img.put_pixel(
                    x,
                    y,
                    image::Rgb([
                        (x * 37 + y * 11) as u8,
                        (x * 13 + y * 53) as u8,
                        (x * 97 + y * 3) as u8,
                    ]),
                );
            }
        }
        let mut bytes = Vec::new();
        image::DynamicImage::ImageRgb8(img)
            .write_to(
                &mut std::io::Cursor::new(&mut bytes),
                image::ImageFormat::Jpeg,
            )
            .unwrap();
        bytes
    }

    /// In-memory .lep producer: `encode_lepton_verify` returns `(lep_bytes, metrics)`
    /// and self-verifies the round-trip. Test-only — the encode side is LTO
    /// dead-stripped from the release DLL but compiles in dev/test builds from the
    /// same dependency.
    fn lepton_bytes(jpeg: &[u8]) -> Vec<u8> {
        try_lepton_bytes(jpeg).expect("synthetic jpeg must encode")
    }

    /// Fallible variant of [`lepton_bytes`]: corpus jpgs the encoder rejects
    /// (broken/truncated files, or dimensions beyond the 4096 helper cap) yield
    /// `None` and the caller skips them.
    fn try_lepton_bytes(jpeg: &[u8]) -> Option<Vec<u8>> {
        use lepton_jpeg::DEFAULT_THREAD_POOL;
        let feats = EnabledFeatures {
            progressive: true,
            reject_dqts_with_zeros: false,
            max_jpeg_width: 4096,
            max_jpeg_height: 4096,
            use_16bit_dc_estimate: true,
            use_16bit_adv_predict: true,
            accept_invalid_dht: true,
            max_partitions: 8,
            max_processor_threads: 2,
            max_jpeg_file_size: 64 * 1024 * 1024,
            stop_reading_at_eoi: false,
        };
        lepton_jpeg::encode_lepton_verify(jpeg, &feats, &DEFAULT_THREAD_POOL)
            .ok()
            .map(|(lep, _)| lep)
    }

    /// Root of the C++-encoded interop corpus: `{TEMP}/lepton-cpp/images` (kept
    /// outside the repo). `None` when absent so corpus tests skip on CI.
    fn cpp_corpus_dir() -> Option<std::path::PathBuf> {
        let temp = std::env::var("TEMP").ok()?;
        let dir = std::path::Path::new(&temp).join("lepton-cpp/images");
        dir.is_dir().then_some(dir)
    }

    #[test]
    fn lepton_roundtrip_decodes_to_original_pixels() {
        let jpeg = test_jpeg(96, 64);
        let lep = lepton_bytes(&jpeg);
        assert!(looks_like_lepton(&lep));
        let img = decode_lepton(&lep).expect("valid lepton must decode");
        assert_eq!((img.width(), img.height()), (96, 64));
        // Bit-exact container ⇒ pixels identical to decoding the original JPEG.
        let reference = super::super::decode_with_image(&jpeg).unwrap();
        assert_eq!(
            img.to_rgb8().into_raw(),
            reference.to_rgb8().into_raw()
        );
    }

    #[test]
    fn lepton_tier_rejects_garbage_without_panicking() {
        // Truncated real file.
        let lep = lepton_bytes(&test_jpeg(96, 64));
        assert!(decode_lepton(&lep[..lep.len() / 2]).is_err());
        // Random noise that happens to start with the magic.
        let mut junk = vec![0xCF, 0x84, 0x01, b'Z'];
        junk.extend(vec![0x41; 4096]);
        assert!(decode_lepton(&junk).is_err());
        // Gate: not a lepton.
        assert!(!looks_like_lepton(&test_jpeg(32, 32)));
        assert!(!looks_like_lepton(&[0xCE, 0xB6, 1, 2, 3]));
    }

    /// Build a hostile .lep whose zlib-compressed header is `header_payload`
    /// (must start with the "HDR" marker + u32 length as the format requires).
    /// The fixed 28-byte prefix declares a modest jpeg_file_size and the exact
    /// compressed header length, so the decoder reaches the header parser.
    fn hostile_lep(header_payload: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(header_payload).unwrap();
        let compressed = enc.finish().unwrap();

        let mut lep = Vec::new();
        lep.extend_from_slice(&[0xCF, 0x84, 0x01, b'Z', 0, 0, 0, 0]);
        lep.extend_from_slice(&[0; 12]); // git-revision / flags area
        lep.extend_from_slice(&64u32.to_le_bytes()); // jpeg_file_size
        lep.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        lep.extend_from_slice(&compressed);
        // The decoder also wants a CMP marker + trailing 4-byte EOF size before
        // it considers the input complete; give it junk — these cases must fail
        // in the HEADER, long before the body is read.
        lep.extend_from_slice(b"CMP");
        lep.extend_from_slice(&(lep.len() as u32 + 4).to_le_bytes());
        lep
    }

    /// P0 regression: a JPEG header that ends at EOI before any SOF/SOS (e.g. a
    /// bare `FF D9`) used to slip past `JpegHeader::parse` (its Ok(false) was
    /// ignored) and panic with a trunc_info index-out-of-bounds / huffman-table
    /// index-out-of-bounds in ALL builds — a ~30-byte file crashing the shell
    /// host. Must now be a clean Err.
    #[test]
    fn lepton_header_without_scan_is_rejected() {
        // "HDR" marker + declared raw header length 2 + raw header `FF D9` (EOI).
        let mut hdr = b"HDR".to_vec();
        hdr.extend_from_slice(&2u32.to_le_bytes());
        hdr.extend_from_slice(&[0xFF, 0xD9]);
        assert!(decode_lepton(&hostile_lep(&hdr)).is_err());

        // Same with a real SOF0 (so cmpc >= 1) but NO SOS: the old code reached
        // the huffman recode with huff_dc/huff_ac still 0xff and indexed
        // h_codes[0][255].
        let mut hdr2 = b"HDR".to_vec();
        hdr2.extend_from_slice(&18u32.to_le_bytes());
        hdr2.extend_from_slice(&[
            0xFF, 0xD8, // SOI
            0xFF, 0xC0, 0x00, 0x11, 0x08, // SOF0, len 17, precision 8
            0x00, 0x40, 0x00, 0x40, // 64x64
            0x01, 0x01, 0x11, 0x00, // 1 component, 1x1 sampling, qt 0
            0xFF, 0xD9, // EOI without any SOS
        ]);
        assert!(decode_lepton(&hostile_lep(&hdr2)).is_err());

        // The nastiest variant: bare EOI header PLUS a one-thread HH (luma-split)
        // marker, so num_threads == 1 and the old code passed the zero-handoff
        // guard, then indexed trunc_info[0] with cmpc == 0 (Vec OOB panic in ALL
        // builds). HH lives OUTSIDE the declared raw-header length (the marker
        // loop reads it from the stream after hdr_data). Payload: start u16,
        // segment_size u32, overhang u8, num_bits u8, 3x last_dc i16, 1x padding
        // u16.
        let mut hdr3 = b"HDR".to_vec();
        hdr3.extend_from_slice(&2u32.to_le_bytes()); // raw header = just FF D9
        hdr3.extend_from_slice(&[0xFF, 0xD9]); // EOI, no SOF
        hdr3.extend_from_slice(b"HH");
        hdr3.push(1); // one thread
        hdr3.extend_from_slice(&0u16.to_le_bytes()); // luma_y_start
        hdr3.extend_from_slice(&0u32.to_le_bytes()); // segment_size
        hdr3.push(0); // overhang_byte
        hdr3.push(0); // num_overhang_bits
        for _ in 0..3 {
            hdr3.extend_from_slice(&0i16.to_le_bytes()); // last_dc
        }
        hdr3.extend_from_slice(&0u16.to_le_bytes()); // padding
        assert!(decode_lepton(&hostile_lep(&hdr3)).is_err());
    }

    /// Lightweight mutation fuzz: the vendored decode path must never panic on
    /// any corrupted input (bit flips + truncations of a real file), only return
    /// Ok/Err. Guards every current and future panic site in the crate.
    #[test]
    fn lepton_mutations_never_panic() {
        let lep = lepton_bytes(&test_jpeg(96, 64));
        // Deterministic PRNG (no external dep): xorshift64*.
        let mut state: u64 = 0x9E3779B97F4A7C15;
        let mut next = move || {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545F4914F6CDD1D)
        };
        // 200 single-byte flips.
        for _ in 0..200 {
            let mut m = lep.clone();
            let pos = (next() as usize) % m.len();
            m[pos] ^= 1 << (next() % 8);
            let _ = decode_lepton(&m); // must not panic
        }
        // 200 truncations at every size class.
        for _ in 0..200 {
            let cut = (next() as usize) % lep.len();
            let _ = decode_lepton(&lep[..cut]); // must not panic
        }
        // Oversized declared lengths (the P0 OOM caps): a tiny file declaring a
        // 4 GiB garbage blob / header must Err fast, not abort.
        let mut big = lep.clone();
        if big.len() > 28 {
            // patch jpeg_file_size (bytes 20..24) to u32::MAX
            big[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        }
        assert!(decode_lepton(&big).is_err());
    }

    /// Regenerates tests/fixtures/lepton.lep. Run manually when the committed
    /// fixture needs refreshing (the fixture is what the CLI/preview smoke tests
    /// use): `cargo test decode::lepton::tests::regenerate_fixture -- --ignored`.
    #[test]
    #[ignore = "manual fixture regeneration"]
    fn regenerate_fixture() {
        let lep = lepton_bytes(&test_jpeg(640, 480));
        std::fs::write(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/lepton.lep"
            ),
            &lep,
        )
        .unwrap();
    }

    /// C++-encoded .lep files (dropbox/lepton, incl. legacy) must decode or fail
    /// cleanly — never panic. gold-legacy.lep is v1 legacy C++ (panicked before the
    /// vendored decode fix), iphone16.lep is v3, narrowrst.lep is v4 (unsupported by
    /// `lepton_jpeg` ⇒ must Err).
    #[test]
    fn cpp_corpus_decodes_or_errors_cleanly() {
        let Some(dir) = cpp_corpus_dir() else { return };
        let mut files = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "lep"))
            .collect::<Vec<_>>();
        files.sort();
        assert!(
            !files.is_empty(),
            "corpus dir exists but has no .lep files: {}",
            dir.display()
        );
        for path in files {
            let data = std::fs::read(&path).unwrap();
            match decode_lepton(&data) {
                Ok(img) => {
                    assert!(
                        img.width() > 0 && img.height() > 0,
                        "{}: decoded dims must be > 0, got {}x{}",
                        path.display(),
                        img.width(),
                        img.height()
                    );
                    println!("{}: OK {}x{}", path.file_name().unwrap().to_string_lossy(), img.width(), img.height());
                }
                Err(_) => println!("{}: clean error (unsupported)", path.file_name().unwrap().to_string_lossy()),
            }
        }
    }

    /// Every encodable corpus jpg round-trips bit-exactly through lepton: decoding
    /// its .lep yields the same dims and pixels as the app's reference decode of the
    /// original jpg (the identical tail pipeline `decode_lepton` ends at). Files the
    /// encoder rejects (broken/truncated, or beyond the helper's 4096px cap) are
    /// skipped — they exist in the corpus precisely as decode-robustness samples.
    #[test]
    fn cpp_jpeg_roundtrip_matches_source_pixels() {
        let Some(dir) = cpp_corpus_dir() else { return };
        let mut files = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "jpg"))
            .collect::<Vec<_>>();
        files.sort();
        assert!(
            !files.is_empty(),
            "corpus dir exists but has no .jpg files: {}",
            dir.display()
        );
        let mut checked = 0;
        let mut skipped = Vec::new();
        for path in files {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let jpg = std::fs::read(&path).unwrap();
            let Some(lep) = try_lepton_bytes(&jpg) else {
                skipped.push(format!("{name}: encode rejected"));
                continue;
            };
            let img = decode_lepton(&lep).unwrap_or_else(|e| {
                panic!("{name}: lep verified by encoder but tier decode failed: {e:?}")
            });
            // Same pipeline the app uses (CMYK handling, ICC→sRGB) — the reference
            // decode of the original jpg. Truncated originals that the reference
            // cannot decode are skipped (nothing to compare against).
            let Ok(reference) = super::super::decode_with_image(&jpg) else {
                skipped.push(format!("{name}: reference decode of original failed"));
                continue;
            };
            assert_eq!(
                (img.width(), img.height()),
                (reference.width(), reference.height()),
                "{name}: dims mismatch"
            );
            assert_eq!(
                img.to_rgb8().into_raw(),
                reference.to_rgb8().into_raw(),
                "{name}: pixels mismatch"
            );
            if let Ok(plain) = image::load_from_memory(&jpg) {
                assert_eq!(
                    (img.width(), img.height()),
                    (plain.width(), plain.height()),
                    "{name}: dims differ from plain image-crate load of the source"
                );
            }
            checked += 1;
        }
        assert!(checked > 0, "no corpus jpg could be encoded — corpus empty?");
        println!(
            "roundtripped {checked} corpus jpgs; skipped {}: {skipped:?}",
            skipped.len()
        );
    }

    /// A progressive JPEG must round-trip identically through lepton. The image
    /// crate's encoder is baseline-only, so the progressive source comes from the
    /// C++ corpus (iphoneprogressive.jpg is genuine SOF2; the similarly-named
    /// iphoneprogressive2/androidprogressive are baseline, so probe for a real one).
    #[test]
    fn progressive_roundtrip() {
        let Some(dir) = cpp_corpus_dir() else { return };
        let mut tested = 0;
        for name in ["iphoneprogressive", "iphoneprogressive2", "androidprogressive"] {
            let path = dir.join(format!("{name}.jpg"));
            let Ok(jpg) = std::fs::read(&path) else { continue };
            // Genuine progressive marker SOF2 = FF C2 (candidate names lie).
            if !jpg.windows(2).any(|w| w == [0xFF, 0xC2]) {
                continue;
            }
            let lep = lepton_bytes(&jpg);
            let img = decode_lepton(&lep).unwrap_or_else(|e| {
                panic!("{name}: progressive roundtrip decode failed: {e:?}")
            });
            let reference = super::super::decode_with_image(&jpg).unwrap();
            assert_eq!(
                (img.width(), img.height()),
                (reference.width(), reference.height()),
                "{name}: dims mismatch"
            );
            assert_eq!(
                img.to_rgb8().into_raw(),
                reference.to_rgb8().into_raw(),
                "{name}: pixels mismatch"
            );
            tested += 1;
            println!("{name}.jpg: progressive roundtrip OK {}x{}", img.width(), img.height());
        }
        assert!(tested >= 1, "no genuine progressive jpg found in corpus");
    }
}
