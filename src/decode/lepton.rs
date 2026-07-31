//! Lepton (.lep) — Dropbox's lossless JPEG recompression. Pure-Rust tier: the
//! `lepton_jpeg` crate (Apache-2.0, `#![forbid(unsafe_code)]`, fuzzed upstream)
//! decodes the container back to a bit-exact JPEG byte stream, which the `image`
//! tier then decodes. Bomb-guarded by the crate's own width/height/file-size caps
//! below plus the `image` tier's MAX_DIM / MAX_ALLOC limits.

use super::*;
// Alias avoids colliding with this module's own `decode_lepton` (the tier fn).
use lepton_jpeg::decode_lepton as lepton_decode;
use lepton_jpeg::{EnabledFeatures, LeptonThreadPriority, SimpleThreadPool};

/// Original-JPEG size budget for the lepton container (the crate's own compat
/// default). It bounds the decoded-JPEG buffer in [`decode_lepton`] AND every
/// length field [`probe_dimensions`] trusts — the header probe rejects files
/// that declare more, so "plausible header" means the same thing on both
/// paths.
const MAX_JPEG_FILE_SIZE: u32 = 128 * 1024 * 1024;

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
        max_jpeg_file_size: MAX_JPEG_FILE_SIZE,
        stop_reading_at_eoi: false,
    };
    // Per-call pool, NOT the crate's global DEFAULT_THREAD_POOL: a per-call pool is
    // dropped when decode returns and its workers exit with it (the vendored crate
    // uses a Weak reference to the idle list — see vendor/lepton_jpeg/SAGETHUMBS-PATCH.md),
    // so no threads linger inside dllhost/explorer (the project's
    // no-global-pool-in-the-shell rule — the same reason rayon is kept out of the DLL).
    let pool = SimpleThreadPool::new(LeptonThreadPriority::Normal);
    let mut jpeg = Vec::new();
    lepton_decode(
        &mut std::io::Cursor::new(bytes),
        &mut jpeg,
        &features,
        &pool,
    )
    .map_err(|e| {
        crate::safety::log_debug(&format!("lepton decode error: {e:?}"));
        Error::from(E_FAIL)
    })?;
    // The same guard set as the jxl / raw-preview tiers: image crate + MAX_DIM /
    // MAX_ALLOC limits + CMYK handling + ICC→sRGB (jxl decodes via jxl_oxide
    // with an equivalent limits block, not through this entry). `jpeg` is
    // ≤ 128 MiB by the cap above, so the allocation is bounded before this call.
    super::decode_with_image(&jpeg)
}

/// Probe ONLY the container's compressed header for the embedded JPEG's
/// dimensions — no pixel decode, no thread pool. The property handler's
/// [`read_info_bounded`](crate::strip::read_info_bounded) path uses this so
/// Explorer's Details pane shows .lep dimensions without materializing the
/// JPEG stream (propstore policy forbids full-fidelity conversion in-process);
/// the unbounded [`read_info`](crate::strip::read_info) gets it too, skipping
/// the slow full-decode fallback.
///
/// Returns `(height, width)` — the SOF marker stores height before width — or
/// `None` on any malformation. Hostile files cannot panic: every slice index
/// is bounds-checked, every declared length is capped at
/// [`MAX_JPEG_FILE_SIZE`] (the same budget the decode tier applies), and the
/// zlib stream is read through `Take` limits, so a deflate bomb stops at the
/// declared header size.
pub(crate) fn probe_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    use std::io::Read;

    // Fixed header (28 bytes, offsets mirror vendor/lepton_jpeg's
    // `read_lepton_fixed_header`): 2 magic + 1 version + 1 type byte + 12 bytes
    // revision/flags + u32 jpeg_file_size + u32 compressed_header_size (both
    // little-endian). The zlib-compressed header follows at offset 28.
    const FIXED_HEADER_SIZE: usize = 28;
    const SOI: u8 = 0xD8;
    const SOS: u8 = 0xDA;
    const EOI: u8 = 0xD9;

    let fixed = bytes.get(..FIXED_HEADER_SIZE)?;
    if !fixed.starts_with(&[0xCF, 0x84]) || fixed[2] != 1 || !matches!(fixed[3], b'Z' | b'X') {
        return None;
    }
    let jpeg_file_size = u32::from_le_bytes(fixed[20..24].try_into().ok()?);
    let compressed_header_size = u32::from_le_bytes(fixed[24..28].try_into().ok()?);
    if jpeg_file_size > MAX_JPEG_FILE_SIZE || compressed_header_size > MAX_JPEG_FILE_SIZE {
        return None;
    }
    let end = FIXED_HEADER_SIZE.checked_add(compressed_header_size as usize)?;
    let compressed = bytes.get(FIXED_HEADER_SIZE..end)?;

    // Decompressed layout: "HDR" + u32 LE declared raw-header length, then that
    // many bytes of raw JPEG header (SOI..SOS, SOI excluded). Read the 7-byte
    // prefix FIRST so the decompression budget is the DECLARED header size, not
    // the whole (potentially bomb-shaped) stream.
    let mut dec = flate2::read::ZlibDecoder::new(std::io::Cursor::new(compressed));
    let mut prefix = [0u8; 7];
    dec.read_exact(&mut prefix).ok()?;
    if &prefix[..3] != b"HDR" {
        return None;
    }
    let hdr_len = u32::from_le_bytes([prefix[3], prefix[4], prefix[5], prefix[6]]) as usize;
    if hdr_len > MAX_JPEG_FILE_SIZE as usize {
        return None;
    }
    let mut raw = Vec::new();
    dec.take(hdr_len as u64).read_to_end(&mut raw).ok()?;
    if raw.len() < hdr_len {
        return None; // declared header runs past the end of the zlib stream
    }

    // Walk the JPEG segments to the first SOF0/1/2 (FF C0/C1/C2). Every index
    // is bounds-checked; a segment whose declared length is not fully present
    // (or is absurdly small) ends the probe with None.
    let mut i = 0usize;
    while i + 1 < raw.len() {
        if raw[i] != 0xFF {
            return None; // marker byte expected between segments
        }
        let marker = raw[i + 1];
        match marker {
            // SOI and the standalone markers (TEM, RSTn) carry no length field.
            SOI | 0x01 | 0xD0..=0xD7 => i += 2,
            // SOS / EOI before any SOF: no usable dimensions in this header.
            SOS | EOI => return None,
            _ => {
                let seg_len = u16::from_be_bytes(raw.get(i + 2..i + 4)?.try_into().ok()?) as usize;
                if seg_len < 2 {
                    return None;
                }
                let seg_end = i.checked_add(2)?.checked_add(seg_len)?;
                raw.get(i + 2..seg_end)?; // declared segment must be fully present
                if matches!(marker, 0xC0..=0xC2) {
                    // Payload: precision(1) + height u16 BE + width u16 BE +
                    // component count(1) + components. seg_len >= 8 guarantees
                    // the precision..width bytes below are in range.
                    if seg_len < 8 {
                        return None;
                    }
                    let payload = i + 4;
                    let height = u32::from_be_bytes([0, 0, raw[payload + 1], raw[payload + 2]]);
                    let width = u32::from_be_bytes([0, 0, raw[payload + 3], raw[payload + 4]]);
                    return (height > 0 && width > 0).then_some((height, width));
                }
                i = seg_end;
            }
        }
    }
    None
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
        use lepton_jpeg::{EnabledFeatures, DEFAULT_THREAD_POOL};
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
        assert_eq!(img.to_rgb8().into_raw(), reference.to_rgb8().into_raw());
    }

    #[test]
    fn committed_fixture_decodes_to_reference_pixels() {
        // Provenance: `regenerate_fixture` encodes test_jpeg(640, 480); the lepton
        // container is bit-exact, so the committed fixture must decode to exactly
        // the same pixels as the source JPEG. Keeps tests/fixtures/lepton.lep live
        // and proves it matches the current encoder output.
        let lep = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/lepton.lep"
        ))
        .expect("fixture must be committed");
        assert!(looks_like_lepton(&lep));
        let img = decode_lepton(&lep).expect("committed fixture must decode");
        assert_eq!((img.width(), img.height()), (640, 480));
        let reference = super::super::decode_with_image(&test_jpeg(640, 480)).unwrap();
        assert_eq!(img.to_rgb8().into_raw(), reference.to_rgb8().into_raw());
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
        hostile_lep_full(header_payload, 64)
    }

    /// Like [`hostile_lep`] with a caller-chosen `jpeg_file_size`: the
    /// early-eof / garbage arithmetic only underflows when the declared size is
    /// smaller than header + garbage, so tests targeting those patches choose
    /// the size; header-validation tests keep the modest default.
    fn hostile_lep_full(header_payload: &[u8], jpeg_file_size: u32) -> Vec<u8> {
        use std::io::Write;
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(header_payload).unwrap();
        let compressed = enc.finish().unwrap();

        let mut lep = Vec::new();
        lep.extend_from_slice(&[0xCF, 0x84, 0x01, b'Z', 0, 0, 0, 0]);
        // Mirror the Rust encoder's fixed-header layout (lepton_header.rs:460-477):
        // "MS" magic + u32 legacy header size + flags + encoder_version (NOT 55,
        // or bad_truncation_version() skips the garbage-size arithmetic) + 4-byte
        // git prefix.
        lep.extend_from_slice(b"MS");
        lep.extend_from_slice(&0u32.to_le_bytes()); // legacy uncompressed header size
        lep.push(0x80); // flags
        lep.push(1); // encoder_version — != 55 so the patch-8 path runs
        lep.extend_from_slice(&[0; 4]); // git revision prefix
        lep.extend_from_slice(&jpeg_file_size.to_le_bytes());
        lep.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        lep.extend_from_slice(&compressed);
        // The decoder also wants a CMP marker + trailing 4-byte EOF size before
        // it considers the input complete; give it junk — these cases must fail
        // in the HEADER, long before the body is read.
        lep.extend_from_slice(b"CMP");
        lep.extend_from_slice(&(lep.len() as u32 + 4).to_le_bytes());
        lep
    }

    /// "HDR" marker + u32 raw-header length + `raw` + `markers` — the payload
    /// shape for [`hostile_lep`] / [`hostile_lep_full`]. The markers (HH/EEE/
    /// GRB/…) live OUTSIDE the declared raw-header length, exactly where the
    /// decoder's marker loop reads them.
    fn hdr_payload(raw: &[u8], markers: &[u8]) -> Vec<u8> {
        let mut hdr = b"HDR".to_vec();
        hdr.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        hdr.extend_from_slice(raw);
        hdr.extend_from_slice(markers);
        hdr
    }

    /// The raw JPEG header (SOF..SOS, no SOI — the parser rejects SOI in-stream)
    /// and the trailing recovery markers (HH splits) of a REAL in-memory .lep,
    /// so hostile-header tests pass the scan gate by construction and keep
    /// decode-faithful partitions.
    fn real_header_parts() -> (Vec<u8>, Vec<u8>) {
        use std::io::Read;
        let base = lepton_bytes(&test_jpeg(96, 64));
        let csz = u32::from_le_bytes(base[24..28].try_into().unwrap()) as usize;
        let mut dec = flate2::read::ZlibDecoder::new(&base[28..28 + csz]);
        let mut inflated = Vec::new();
        dec.read_to_end(&mut inflated).unwrap();
        let raw_len = u32::from_le_bytes(inflated[3..7].try_into().unwrap()) as usize;
        let split = 7 + raw_len;
        (inflated[7..split].to_vec(), inflated[split..].to_vec())
    }

    /// A one-thread HH (luma-split) marker: start u16, segment_size u32,
    /// overhang u8, num_bits u8, 3x last_dc i16, 1x padding u16.
    fn hh_marker(luma_y_start: u16, segment_size: u32) -> Vec<u8> {
        let mut hh = b"HH".to_vec();
        hh.push(1); // one thread
        hh.extend_from_slice(&luma_y_start.to_le_bytes());
        hh.extend_from_slice(&segment_size.to_le_bytes());
        hh.push(0); // overhang_byte
        hh.push(0); // num_overhang_bits
        for _ in 0..3 {
            hh.extend_from_slice(&0i16.to_le_bytes()); // last_dc
        }
        hh.extend_from_slice(&0u16.to_le_bytes()); // padding
        hh
    }

    /// EEE (early-eof) marker: max_cmp, max_bpos, max_sah, then max_dpos[0..4].
    /// All fields are hostile-controlled u32s; only max_sah gets a u8 range
    /// check on read.
    fn eee_marker(max_dpos0: u32) -> Vec<u8> {
        let mut eee = b"EEE".to_vec();
        eee.extend_from_slice(&0u32.to_le_bytes()); // max_cmp
        eee.extend_from_slice(&0u32.to_le_bytes()); // max_bpos
        eee.extend_from_slice(&0u32.to_le_bytes()); // max_sah
        eee.extend_from_slice(&max_dpos0.to_le_bytes());
        eee.extend_from_slice(&0u32.to_le_bytes());
        eee.extend_from_slice(&0u32.to_le_bytes());
        eee.extend_from_slice(&0u32.to_le_bytes());
        eee
    }

    /// GRB (garbage) marker: u32 size + that many bytes of junk.
    fn grb_marker(size: u32, junk: u8) -> Vec<u8> {
        let mut grb = b"GRB".to_vec();
        grb.extend_from_slice(&size.to_le_bytes());
        grb.extend(std::iter::repeat_n(junk, size as usize));
        grb
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
        // SOF0 present but NO SOS — the sibling of hdr1: with cmpc >= 1 the old
        // code survived the trunc_info index and reached huffman recode with the
        // tables still at their 0xff defaults (h_codes[0][255] OOB in ALL
        // builds). The lepton raw header has no SOI (the parser rejects it
        // in-stream), so a well-formed SOF0 (len 11 = 1 component) + bare EOI.
        // The declared length must equal the payload or the probe dies in
        // read_exact before the parser ever runs.
        let mut hdr2 = b"HDR".to_vec();
        hdr2.extend_from_slice(&15u32.to_le_bytes());
        hdr2.extend_from_slice(&[
            0xFF, 0xC0, 0x00, 0x0B, 0x08, // SOF0, len 11, precision 8
            0x00, 0x40, 0x00, 0x40, // 64x64
            0x01, 0x01, 0x11, 0x00, // 1 component, 1x1 sampling, qt 0
            0xFF, 0xD9, // EOI without any SOS
        ]);
        hdr2.extend_from_slice(&hh_marker(0, 0)); // one thread — the old huffman path
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
        hdr3.extend_from_slice(&hh_marker(0, 0));
        assert!(decode_lepton(&hostile_lep(&hdr3)).is_err());
    }

    /// P0 regression for patch 10 (EEE `max_dpos + 1` overflow): the EEE
    /// marker's max_dpos fields are hostile u32s with no validation, and
    /// `u32::MAX` used to overflow in `set_truncation_bounds` (reproduced:
    /// "attempt to add with overflow" at truncate_components.rs:69 in
    /// overflow-checked builds). The saturating fix makes `u32::MAX` mean "no
    /// truncation", so a real file carrying the hostile marker must decode
    /// normally. jpeg_file_size must exceed header + garbage + SOI so the
    /// early-eof size arithmetic (patch 1) cannot clamp the image first.
    #[test]
    fn lepton_eee_maxdpos_saturates() {
        let (raw, markers) = real_header_parts();
        let payload = hdr_payload(&raw, &[&eee_marker(u32::MAX)[..], &markers[..]].concat());
        let img = decode_lepton(&hostile_lep_full(&payload, 100_000))
            .expect("EEE max_dpos=u32::MAX must saturate to no-truncation, not panic");
        assert_eq!((img.width(), img.height()), (96, 64));
    }

    /// Regression for patch 1 (early_eof size arithmetic): a declared
    /// jpeg_file_size smaller than garbage + raw header + SOI used to underflow
    /// and panic in overflow-checked builds (legacy C++ files, e.g.
    /// gold-legacy.lep). Saturating clamps to 0, the last segment shortens to
    /// nothing, and the decode fails cleanly.
    #[test]
    fn lepton_early_eof_size_arithmetic_is_bounded() {
        let (raw, markers) = real_header_parts();
        let payload = hdr_payload(&raw, &[&eee_marker(0)[..], &markers[..]].concat());
        // 64 < real header (~110 bytes) + EOI garbage (2) + SOI (2): underflows
        // without the patch; clamps to an empty decode with it.
        assert!(decode_lepton(&hostile_lep_full(&payload, 64)).is_err());
    }

    /// Regression for patch 8 (jpeg_file_size_left): a declared file size
    /// smaller than the GRB garbage blob underflowed u64. Saturating bounds the
    /// output writer to zero bytes, so the reconstructed JPEG is empty and the
    /// tier fails cleanly.
    #[test]
    fn lepton_garbage_size_underflow_is_bounded() {
        let (raw, markers) = real_header_parts();
        // The real encoder's marker section ends with its own GRB (the EOI as
        // garbage, size 2) — the LAST GRB in the stream wins, so the hostile
        // 70-byte GRB must come AFTER the real markers or it is overwritten.
        let payload = hdr_payload(&raw, &[&markers[..], &grb_marker(70, 0xAB)[..]].concat());
        assert!(decode_lepton(&hostile_lep_full(&payload, 64)).is_err());
    }

    /// Regression for patch 4 (thread-range validation): hostile HH markers
    /// with an out-of-range start or an inverted range used to reach
    /// BlockBasedImage::merge's contiguity assert (a panic in ALL builds on the
    /// main thread for progressive files). Both shapes must now be a clean
    /// error before any decode work.
    #[test]
    fn lepton_thread_ranges_are_validated() {
        let (raw, _) = real_header_parts();
        // Start beyond the image height (96): inverted by construction.
        assert!(decode_lepton(&hostile_lep(&hdr_payload(&raw, &hh_marker(200, 0)))).is_err());
        // Contiguous at first, then a third handoff starting BELOW its
        // predecessor's start: inverted ranges.
        let inverted = [
            &hh_marker(0, 0)[..],
            &hh_marker(60, 0)[..],
            &hh_marker(30, 0)[..],
        ]
        .concat();
        assert!(decode_lepton(&hostile_lep(&hdr_payload(&raw, &inverted))).is_err());
    }

    /// Regression for patch 5 (capped header length fields): the HDR, FRS, and
    /// GRB length fields are hostile u32s that used to drive unbounded
    /// Vec::resize (a ~4 GiB OOM abort from a ~40-byte file). All three must
    /// fail fast as BadLeptonFile.
    #[test]
    fn lepton_header_lengths_are_capped() {
        let (raw, _) = real_header_parts();
        // HDR raw-header length = u32::MAX.
        let mut huge_hdr = b"HDR".to_vec();
        huge_hdr.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_lepton(&hostile_lep(&huge_hdr)).is_err());
        // FRS restart-error count = u32::MAX.
        let mut frs = b"FRS".to_vec();
        frs.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_lepton(&hostile_lep(&hdr_payload(&raw, &frs))).is_err());
        // GRB garbage size = u32::MAX.
        assert!(decode_lepton(&hostile_lep(&hdr_payload(&raw, &grb_marker(u32::MAX, 0)))).is_err());
    }

    /// Lightweight mutation fuzz: the vendored decode path must never panic on
    /// any corrupted input (bit flips + truncations of a real file), only return
    /// Ok/Err. Guards every current and future panic site in the crate. Random
    /// flips cannot construct the structured markers (HH/EEE/CRS/GRB + exact
    /// lengths) the per-patch regressions need — those live in the dedicated
    /// tests above; this one patrols everything else.
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
        // Oversized declared jpeg_file_size (bytes 20..24): trips the upstream
        // fixed-header cap before any allocation. The HDR/FRS/GRB length caps
        // (patch 5) are exercised deterministically by
        // `lepton_header_lengths_are_capped`.
        let mut big = lep.clone();
        if big.len() > 28 {
            big[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        }
        assert!(decode_lepton(&big).is_err());
    }

    /// Regenerates tests/fixtures/lepton.lep. Run manually when the committed
    /// fixture needs refreshing (it is exercised by
    /// `committed_fixture_decodes_to_reference_pixels`):
    /// `cargo test decode::lepton::tests::regenerate_fixture -- --ignored`.
    #[test]
    #[ignore = "manual fixture regeneration"]
    fn regenerate_fixture() {
        let lep = lepton_bytes(&test_jpeg(640, 480));
        std::fs::write(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/lepton.lep"),
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
                    println!(
                        "{}: OK {}x{}",
                        path.file_name().unwrap().to_string_lossy(),
                        img.width(),
                        img.height()
                    );
                }
                Err(_) => println!(
                    "{}: clean error (unsupported)",
                    path.file_name().unwrap().to_string_lossy()
                ),
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
        assert!(
            checked > 0,
            "no corpus jpg could be encoded — corpus empty?"
        );
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
        for name in [
            "iphoneprogressive",
            "iphoneprogressive2",
            "androidprogressive",
        ] {
            let path = dir.join(format!("{name}.jpg"));
            let Ok(jpg) = std::fs::read(&path) else {
                continue;
            };
            // Genuine progressive marker SOF2 = FF C2 (candidate names lie).
            if !jpg.windows(2).any(|w| w == [0xFF, 0xC2]) {
                continue;
            }
            let lep = lepton_bytes(&jpg);
            let img = decode_lepton(&lep)
                .unwrap_or_else(|e| panic!("{name}: progressive roundtrip decode failed: {e:?}"));
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
            println!(
                "{name}.jpg: progressive roundtrip OK {}x{}",
                img.width(),
                img.height()
            );
        }
        assert!(tested >= 1, "no genuine progressive jpg found in corpus");
    }

    /// The committed fixture's SOF0 declares 640x480 — the probe must extract
    /// exactly that from the container's compressed header, height FIRST (SOF
    /// stores height before width), without decoding a single pixel.
    #[test]
    fn probe_dimensions_reads_fixture_header() {
        let lep = include_bytes!("../../tests/fixtures/lepton.lep");
        assert!(looks_like_lepton(lep));
        assert_eq!(probe_dimensions(lep), Some((480, 640)));
    }

    /// Segment walking: non-SOF segments (APP0) are skipped by their declared
    /// length and the SOF that follows is still found.
    #[test]
    fn probe_dimensions_skips_preceding_segments() {
        let mut hdr = b"HDR".to_vec();
        hdr.extend_from_slice(&33u32.to_le_bytes());
        hdr.extend_from_slice(&[
            0xFF, 0xE0, 0x00, 0x12, // APP0, len 18 (2 length bytes + 16 payload)
            b'J', b'F', b'I', b'F', 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, // 16-byte APP0 payload
            0xFF, 0xC0, 0x00, 0x0B, // SOF0, len 11
            0x08, // precision 8
            0x01, 0xE0, 0x02, 0x80, // height 480, width 640
            0x01, 0x01, 0x11, 0x00, // 1 component
        ]);
        assert_eq!(probe_dimensions(&hostile_lep(&hdr)), Some((480, 640)));
    }

    /// `probe_dimensions` must never panic and must return None for every
    /// malformed container: truncated fixed header, bogus magic, zeroed sizes,
    /// unsupported version/type, over-budget declared lengths, non-zlib
    /// compressed data, a missing HDR marker, over-budget/truncated raw-header
    /// lengths, and JPEG headers without a usable SOF.
    #[test]
    fn probe_dimensions_rejects_hostile_headers() {
        // Too short for the 28-byte fixed header / wrong magic.
        assert_eq!(probe_dimensions(&[]), None);
        assert_eq!(probe_dimensions(&[0xCF, 0x84]), None);
        assert_eq!(probe_dimensions(&[0xCE, 0xB6, 1, 2, 3]), None);
        // Magic + all-zero fixed header: declares nothing to decompress.
        let mut zeroed = vec![0xCF, 0x84, 0x01, b'Z'];
        zeroed.extend_from_slice(&[0; 24]);
        assert_eq!(probe_dimensions(&zeroed), None);
        // Unsupported version / type bytes.
        let mut bad_ver = vec![0xCF, 0x84, 0x02, b'Z'];
        bad_ver.extend_from_slice(&[0; 24]);
        assert_eq!(probe_dimensions(&bad_ver), None);
        let mut bad_type = vec![0xCF, 0x84, 0x01, b'Q'];
        bad_type.extend_from_slice(&[0; 24]);
        assert_eq!(probe_dimensions(&bad_type), None);
        // jpeg_file_size beyond the 128 MiB budget.
        let mut over = vec![0xCF, 0x84, 0x01, b'Z', 0, 0, 0, 0];
        over.extend_from_slice(&[0; 12]);
        over.extend_from_slice(&u32::MAX.to_le_bytes());
        over.extend_from_slice(&4u32.to_le_bytes());
        over.extend_from_slice(&[0; 4]);
        assert_eq!(probe_dimensions(&over), None);
        // compressed_header_size beyond the 128 MiB budget.
        let mut huge_comp = vec![0xCF, 0x84, 0x01, b'Z', 0, 0, 0, 0];
        huge_comp.extend_from_slice(&[0; 12]);
        huge_comp.extend_from_slice(&64u32.to_le_bytes());
        huge_comp.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(probe_dimensions(&huge_comp), None);
        // Declared compressed header runs past the end of the file.
        let mut truncated = vec![0xCF, 0x84, 0x01, b'Z', 0, 0, 0, 0];
        truncated.extend_from_slice(&[0; 12]);
        truncated.extend_from_slice(&64u32.to_le_bytes());
        truncated.extend_from_slice(&100u32.to_le_bytes());
        assert_eq!(probe_dimensions(&truncated), None);
        // Valid zlib stream that is not a lepton header ("HDR" missing).
        assert_eq!(probe_dimensions(&hostile_lep(b"NOPE")), None);
        // "HDR" declaring u32::MAX raw-header bytes (over budget).
        let mut hdr = b"HDR".to_vec();
        hdr.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(probe_dimensions(&hostile_lep(&hdr)), None);
        // "HDR" declaring more raw bytes than the zlib stream holds.
        let mut hdr = b"HDR".to_vec();
        hdr.extend_from_slice(&100u32.to_le_bytes());
        hdr.extend_from_slice(&[0xFF, 0xC0]); // only 2 of the 100 bytes
        assert_eq!(probe_dimensions(&hostile_lep(&hdr)), None);
        // Raw header that is just an EOI (no SOF, no SOS).
        let mut hdr = b"HDR".to_vec();
        hdr.extend_from_slice(&2u32.to_le_bytes());
        hdr.extend_from_slice(&[0xFF, 0xD9]);
        assert_eq!(probe_dimensions(&hostile_lep(&hdr)), None);
        // SOS before any SOF.
        let mut hdr = b"HDR".to_vec();
        hdr.extend_from_slice(&4u32.to_le_bytes());
        hdr.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08]);
        assert_eq!(probe_dimensions(&hostile_lep(&hdr)), None);
        // SOF declaring zero dimensions.
        let mut hdr = b"HDR".to_vec();
        hdr.extend_from_slice(&13u32.to_le_bytes());
        hdr.extend_from_slice(&[
            0xFF, 0xC0, 0x00, 0x0B, // SOF0, len 11
            0x08, // precision 8
            0x00, 0x00, 0x00, 0x00, // height 0, width 0
            0x01, 0x01, 0x11, 0x00, // 1 component
        ]);
        assert_eq!(probe_dimensions(&hostile_lep(&hdr)), None);
        // SOF whose declared length runs past the end of the raw header.
        let mut hdr = b"HDR".to_vec();
        hdr.extend_from_slice(&6u32.to_le_bytes());
        hdr.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00]);
        assert_eq!(probe_dimensions(&hostile_lep(&hdr)), None);
    }
}
