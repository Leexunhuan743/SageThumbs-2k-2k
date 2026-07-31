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
    // Per-call pool, NOT the crate's global DEFAULT_THREAD_POOL: dropping it at the
    // end of decode closes its channels and exits any worker threads, so nothing
    // lingers inside dllhost/explorer (the project's no-global-pool-in-the-shell
    // rule — the same reason rayon is kept out of the DLL).
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
        use lepton_jpeg::{DEFAULT_THREAD_POOL, EnabledFeatures};
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
            .unwrap()
            .0
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
}
