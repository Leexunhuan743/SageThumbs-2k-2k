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
pub(crate) const MAX_JPEG_FILE_SIZE: u32 = 128 * 1024 * 1024;

/// Lepton signature: the tau symbol `0xCF 0x84` (LEPTON_FILE_HEADER). The version
/// byte at [2] and the 'Z'/'X' JPEG-type byte at [3] are validated by the decoder
/// itself. The 0xCE 0xB6 zlib-outer variant and UJG ("UJ") are NOT supported by
/// `lepton_jpeg` — deliberately not matched here; such files fall through to the
/// other tiers and fail harmlessly (stock icon). C++-producible edge encodings
/// are likewise unmatched by design and fall through: 'Y'-type files
/// (lepton -startbyte=N sliced encodings, which also carry PGR prefix-garbage
/// markers) and PGE (embedded-JPEG garbage) are rejected by the decoder's
/// type byte and marker checks; the pre-2016 PAD marker (replaced by P0D in
/// dropbox commit c6deaa9) is rejected as an unknown marker. All are clean
/// fall-throughs, never a crash.
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
    // The same entry the jxl / raw-preview tiers end at: image crate + MAX_DIM /
    // MAX_ALLOC limits + CMYK handling + ICC→sRGB. `jpeg` is ≤ 128 MiB by the cap
    // above, so the allocation is bounded before this call.
    //
    // EXIF orientation: lepton is bit-exact, so the reconstructed JPEG carries the
    // camera's original orientation tags — apply them here, exactly once. The
    // outer `decode_image_with_raw_order` wrapper re-applies orientation from the
    // ORIGINAL container bytes, where the 0xCF 0x84 magic fails `has_exif_container`
    // and is a no-op; applying from the reconstructed JPEG here (like the
    // embedded-thumbnail path in thumb.rs) is the only active application.
    Ok(apply_exif_orientation(
        super::decode_with_image(&jpeg)?,
        &jpeg,
    ))
}

/// Decompress the container's compressed header and return the embedded RAW
/// JPEG header (SOI..SOS, SOI excluded — the lepton format stores it without
/// the SOI). Shared by [`probe_dimensions`] and [`probe_exif`]. Hostile files
/// cannot panic: every slice index is bounds-checked, every declared length is
/// capped at [`MAX_JPEG_FILE_SIZE`] (the same budget the decode tier applies),
/// and the zlib stream is read through `Take` limits, so a deflate bomb stops
/// at the declared header size. `None` on any malformation.
fn decompress_raw_header(bytes: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;

    // Fixed header (28 bytes, offsets mirror vendor/lepton_jpeg's
    // `read_lepton_fixed_header`): 2 magic + 1 version + 1 type byte + 12 bytes
    // revision/flags + u32 jpeg_file_size + u32 compressed_header_size (both
    // little-endian). The zlib-compressed header follows at offset 28.
    const FIXED_HEADER_SIZE: usize = 28;

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
    Some(raw)
}

/// Camera EXIF from the container's compressed header — the camera tags live
/// in the JPEG header's APP1 segment, which the container stores
/// zlib-compressed along with the rest of the SOI..SOS header. Same bounded
/// header probe as [`probe_dimensions`] (no pixel decode, no thread pool);
/// the reconstructed stream (SOI prefix included — the EXIF reader requires
/// it) is handed to the parser. `None` on malformation or no EXIF.
pub(crate) fn probe_exif(bytes: &[u8]) -> Option<exif::Exif> {
    use exif::Reader;
    let mut raw = decompress_raw_header(bytes)?;
    raw.insert(0, 0xFF); // SOI — the EXIF reader rejects a stream without it
    raw.insert(1, 0xD8);
    Reader::new()
        .read_from_container(&mut std::io::Cursor::new(raw))
        .ok()
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
/// `None` on any malformation.
pub(crate) fn probe_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    let raw = decompress_raw_header(bytes)?;

    // Walk the JPEG segments to the first SOF0/1/2 (FF C0/C1/C2), mirroring
    // the vendored decoder's parse_next_segment strictness so a "plausible
    // header" means the same thing on both paths: fill bytes (FF FF), TEM,
    // in-stream RSTn/SOI, a SECOND SOF, a lone SOF with no scan, and unknown
    // markers are all errors there, and a hostile header could otherwise
    // plant a FAKE SOF that the probe reports while the crate rejects the
    // file (attacker-chosen dimensions in the Details pane for a file that
    // can never decode). Every index is bounds-checked; a segment whose
    // declared length is not fully present (or is absurdly small) ends the
    // probe with None.
    let mut i = 0usize;
    // Dimensions of the FIRST (and only) SOF, returned only once a real SOS
    // scan has been seen — the decode tier's scan gate rejects a lone SOF.
    let mut sof_dims: Option<(u32, u32)> = None;
    while i + 1 < raw.len() {
        if raw[i] != 0xFF {
            return None; // marker byte expected between segments
        }
        let marker = raw[i + 1];
        // Every marker except the lengthless ones carries a u16 length; read it
        // up front so the SOF branch can validate its payload against it.
        let seg_len = if matches!(marker, 0x01 | 0xD0..=0xD8 | 0xD9 | 0xDA | 0xFF) {
            0
        } else {
            u16::from_be_bytes(raw.get(i + 2..i + 4)?.try_into().ok()?) as usize
        };
        match marker {
            // Fill byte (FF FF) — the decoder errors on it; so do we.
            0xFF => return None,
            // TEM and RSTn are standalone (lengthless) markers that are only
            // legal INSIDE scan data, never in the header — the decoder
            // rejects them here.
            0x01 | 0xD0..=0xD7 => return None,
            // A second SOI inside the stream is rejected by the decoder.
            0xD8 => return None,
            // EOI before any SOS: the header has no decodable scan.
            0xD9 => return None,
            // SOS: the header is decodable only if a SOF was seen; a lone SOF
            // (or no SOF at all) means the decode tier rejects the file.
            0xDA => return sof_dims,
            // A SOF0/1/2 must carry a well-formed payload: precision 8,
            // dimensions within the tier caps, 1..=3 components (the lepton
            // format and the decode tier reject 4-color JPEGs — mirroring the
            // decoder here keeps "plausible header" identical on both paths)
            // with their 3-byte entries fully present (seg_len >= 8 + 3*cmpc)
            // and the whole declared segment present in the stream.
            0xC0..=0xC2 => {
                if seg_len < 8 {
                    return None;
                }
                let seg_end = i.checked_add(2)?.checked_add(seg_len)?;
                raw.get(i + 2..seg_end)?; // declared segment must be fully present
                let payload = i + 4;
                raw.get(payload..payload + 6)?;
                if raw[payload] != 8 {
                    return None; // only 8-bit precision is supported
                }
                let height = u32::from_be_bytes([0, 0, raw[payload + 1], raw[payload + 2]]);
                let width = u32::from_be_bytes([0, 0, raw[payload + 3], raw[payload + 4]]);
                let cmpc = usize::from(raw[payload + 5]);
                if !(1..=3).contains(&cmpc) {
                    return None;
                }
                // Component entries (jid, sampling nibbles, qt index) must all
                // be present, and the dimensions must fit the same caps the
                // decode tier applies (every other header probe in the repo
                // rejects above MAX_DIM; so do we).
                if seg_len < 8 + 3 * cmpc {
                    return None;
                }
                if height == 0
                    || width == 0
                    || height > limits::MAX_DIM
                    || width > limits::MAX_DIM
                    || u64::from(height) * u64::from(width) > limits::MAX_PIXELS
                {
                    return None;
                }
                // The decoder rejects images with MULTIPLE SOF blocks; a
                // second SOF anywhere in the header makes the file
                // undecodable, so keep walking instead of returning here.
                if sof_dims.is_some() {
                    return None;
                }
                sof_dims = Some((height, width));
                i = seg_end;
            }
            // Any other marker carries a length field.
            _ => {
                if seg_len < 2 {
                    return None;
                }
                let seg_end = i.checked_add(2)?.checked_add(seg_len)?;
                raw.get(i + 2..seg_end)?; // declared segment must be fully present
                i = seg_end;
            }
        }
    }
    // Header ended without a scan (or without any SOF): not decodable.
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
            // The encoder supports up to 16386 (its compat default); MAX_DIM
            // (16384) matches the decode tier's ceiling, so every corpus jpg
            // the DECODER accepts is also roundtripped — the old 4096 helper
            // cap silently skipped all larger images in BOTH directions.
            max_jpeg_width: limits::MAX_DIM,
            max_jpeg_height: limits::MAX_DIM,
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

    /// P0 regression for patch 11 (EEE `max_dpos + 1` overflow): the EEE
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
        // 64 < real header (621 bytes) + EOI garbage (2) + SOI (2): underflows
        // without the patch; clamps to an empty decode with it.
        assert!(decode_lepton(&hostile_lep_full(&payload, 64)).is_err());
    }

    /// Deterministic discriminator for SAGETHUMBS PATCH 1 (early_eof size
    /// arithmetic). The hostile_lep fixed prefix declares jpeg_file_size = 64;
    /// this header adds an EEE (early-EOF) marker plus a GRB garbage blob of 64
    /// bytes, so in `read_compressed_lepton_header` the early_eof branch computes
    /// `jpeg_file_size - garbage(64) - raw_jpeg_header_read_index(92) - SOI(2)`:
    /// unpatched, that plain `-` chain UNDERFLOWS u32 (panic in every
    /// overflow-checked build — the gold-legacy.lep P0); patched, saturating_sub
    /// clamps to 0 and the zero-size segment makes the body decode fail cleanly.
    #[test]
    fn lepton_early_eof_with_tiny_file_size_is_clean_error() {
        // Raw JPEG header (no SOI — the format stores the header without it):
        // SOF0 64x64 / 1 component, DQT with a non-zero table 0
        // (JpegHeader::parse rejects q_tables[..][0] == 0), SOS. 13+69+10 = 92
        // bytes consumed by the parse gate, which is what drives the underflow.
        let mut raw = Vec::new();
        raw.extend_from_slice(&[
            0xFF, 0xC0, 0x00, 0x0B, // SOF0, len 11
            0x08, // precision 8
            0x00, 0x40, 0x00, 0x40, // 64x64
            0x01, 0x01, 0x11, 0x00, // 1 component, 1x1 sampling, qt 0
        ]);
        raw.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43, 0x00]); // DQT, len 67, table 0
        raw.extend_from_slice(&[1; 64]); // non-zero quantization values
        raw.extend_from_slice(&[
            0xFF, 0xDA, 0x00, 0x08, // SOS, len 8
            0x01, // 1 component in scan
            0x01, 0x00, // comp 1, huff_dc 0 / huff_ac 0
            0x00, 0x3F, 0x00, // Ss 0, Se 63, Ah/Al 0
        ]);
        let mut hdr = b"HDR".to_vec();
        hdr.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        hdr.extend_from_slice(&raw);
        // EEE marker: max_cmp, max_bpos, max_sah, max_dpos[0..4] (all 0).
        hdr.extend_from_slice(b"EEE");
        for _ in 0..7 {
            hdr.extend_from_slice(&0u32.to_le_bytes());
        }
        // HH: one thread (passes the zero-handoff guard), zero-size segment.
        hdr.extend_from_slice(b"HH");
        hdr.push(1);
        hdr.extend_from_slice(&0u16.to_le_bytes()); // luma_y_start
        hdr.extend_from_slice(&0u32.to_le_bytes()); // segment_size
        hdr.push(0); // overhang_byte
        hdr.push(0); // num_overhang_bits
        for _ in 0..3 {
            hdr.extend_from_slice(&0i16.to_le_bytes()); // last_dc
        }
        hdr.extend_from_slice(&0u16.to_le_bytes()); // padding
        // GRB: 64 bytes of garbage. 64 (file size) - 64 (garbage) - 92 (header
        // read) - 2 (SOI) underflows on unpatched code.
        hdr.extend_from_slice(b"GRB");
        hdr.extend_from_slice(&64u32.to_le_bytes());
        hdr.extend_from_slice(&[0; 64]);
        assert!(decode_lepton(&hostile_lep(&hdr)).is_err());
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

    /// Deterministic discriminator for SAGETHUMBS PATCH 4 (thread-range
    /// validation). The HH serialization only carries each thread's
    /// luma_y_start — `ThreadHandoff::deserialize` derives `end[i] = start[i+1]`
    /// and the last end is filled with max_luma afterwards — so the only
    /// invalid range reachable through the wire format is a DECREASING start
    /// sequence: [4, 2) on thread 0. Unpatched, the inverted range later hits
    /// `BlockBasedImage::merge`'s contiguity assert or `luma_y_end -
    /// luma_y_start` (SAGETHUMBS PATCH 7), a panic in ALL builds; patched, the
    /// header is rejected as a clean BadLeptonFile.
    #[test]
    fn lepton_inverted_thread_luma_ranges_are_clean_error() {
        // Same parseable raw header as above (SOF0 + DQT + SOS, 92 bytes).
        let mut raw = Vec::new();
        raw.extend_from_slice(&[
            0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x40, 0x00, 0x40, 0x01, 0x01, 0x11, 0x00,
        ]);
        raw.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43, 0x00]);
        raw.extend_from_slice(&[1; 64]);
        raw.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]);
        let mut hdr = b"HDR".to_vec();
        hdr.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        hdr.extend_from_slice(&raw);
        // HH with two threads and DECREASING starts (4 then 2): deserialize
        // derives thread 0's end from thread 1's start → inverted [4, 2).
        hdr.extend_from_slice(b"HH");
        hdr.push(2);
        for start in [4u16, 2u16] {
            hdr.extend_from_slice(&start.to_le_bytes()); // luma_y_start
            hdr.extend_from_slice(&0u32.to_le_bytes()); // segment_size
            hdr.push(0); // overhang_byte
            hdr.push(0); // num_overhang_bits
            for _ in 0..3 {
                hdr.extend_from_slice(&0i16.to_le_bytes()); // last_dc
            }
            hdr.extend_from_slice(&0u16.to_le_bytes()); // padding
        }
        assert!(decode_lepton(&hostile_lep(&hdr)).is_err());
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

        // SAGETHUMBS PATCH 5 discriminator (capped header length fields): a
        // header whose HDR marker declares hdrs = u32::MAX must be a clean Err.
        // Unpatched, `read_lepton_compressed_header` runs
        // `hdr_data.resize(hdrs, 0)` with no bound — a ~4 GiB allocation that
        // aborts the process (panic=abort) wherever the allocator fails, i.e.
        // the original OOM P0. Patched, the cap() closure rejects it as
        // BadLeptonFile before any allocation.
        let mut hdr = b"HDR".to_vec();
        hdr.extend_from_slice(&u32::MAX.to_le_bytes());
        hdr.push(0); // one payload byte so the declared length is the only defect
        assert!(decode_lepton(&hostile_lep(&hdr)).is_err());
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
    /// vendored decode fix), iphone16.lep is a format-compatible C++ v1 file (the
    /// "16" is its 16 thread handoffs; it carries CRS+FRS restart markers),
    /// narrowrst.lep is v4 (unsupported by
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
    /// encoder rejects (broken/truncated) are skipped — they exist in the corpus
    /// precisely as decode-robustness samples.
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
                // narrowrst.jpg is the one corpus JPEG with in-scan DRI restart
                // markers; the encoder refuses bit-exact re-encoding of restart
                // streams (InvalidResetCode in read_first_scan) BY DESIGN — a
                // capability limitation, not a broken file (the C++ encoder
                // handles it), and the RST encode/decode path stays
                // unexercised by roundtrips (see SAGETHUMBS-PATCH.md fix 6).
                let why = if name == "narrowrst.jpg" {
                    "restart-marker JPEG, encoder refuses bit-exact re-encode"
                } else {
                    "encode rejected"
                };
                skipped.push(format!("{name}: {why}"));
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
            // `decode_lepton` applies the reconstructed JPEG's EXIF orientation
            // exactly once (the container is bit-exact, so the tags survive);
            // mirror that on the reference so files with orientation != 1
            // (slrcity.jpg = 8) compare apples-to-apples.
            let reference = super::super::apply_exif_orientation(reference, &jpg);
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
                // Same orientation mirror as above (plain load keeps raw order).
                let plain = super::super::apply_exif_orientation(plain, &jpg);
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

    /// Bit-exact decode of a C++-ENCODED .lep file, anchored to its source JPEG.
    /// Every other pixel comparison in the suite goes through the RUST encoder's
    /// output, so a coordinated regression in the vpx/model/IDCT layer shared by
    /// encoder and decoder would keep every gate green while C++-encoded files
    /// misdecode. iphone16.lep is the one C++-v1 file in the corpus that decodes
    /// (verified: version byte 1, 16 thread handoffs, CRS+FRS markers); its
    /// source iphone.jpg sits beside it. Orientation is 1 for this pair, so the
    /// tier's EXIF orientation application is a no-op on both sides.
    #[test]
    fn cpp_encoded_iphone16_decodes_bit_exact_to_source_jpeg() {
        let Some(dir) = cpp_corpus_dir() else { return };
        let lep = std::fs::read(dir.join("iphone16.lep")).unwrap();
        let jpg = std::fs::read(dir.join("iphone.jpg")).unwrap();
        let img = decode_lepton(&lep).expect("C++-encoded v1 file must decode");
        let reference = super::super::decode_with_image(&jpg).expect("source JPEG must decode");
        assert_eq!(
            (img.width(), img.height()),
            (reference.width(), reference.height()),
            "iphone16.lep dims must match iphone.jpg"
        );
        assert_eq!(
            img.to_rgb8().into_raw(),
            reference.to_rgb8().into_raw(),
            "iphone16.lep pixels must be bit-exact to iphone.jpg"
        );
    }

    /// A progressive JPEG must round-trip identically through lepton. The image
    /// crate's encoder is baseline-only, so the progressive source comes from the
    /// C++ corpus. All three candidates contain a genuine SOF2 (FF C2) marker —
    /// including iphoneprogressive2.jpg and androidprogressive.jpg, which an
    /// earlier comment wrongly called baseline — so the byte probe is the only
    /// reliable discriminator (name-based assumptions proved wrong), and
    /// non-progressive files are skipped by it.
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
            // Same orientation mirror as cpp_jpeg_roundtrip (decode_lepton
            // applies the EXIF orientation exactly once; the raw decode does
            // not — orientation != 1 sources must compare apples-to-apples).
            let reference = super::super::apply_exif_orientation(
                super::super::decode_with_image(&jpg).unwrap(),
                &jpg,
            );
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
        hdr.extend_from_slice(&43u32.to_le_bytes());
        hdr.extend_from_slice(&[
            0xFF, 0xE0, 0x00, 0x12, // APP0, len 18 (2 length bytes + 16 payload)
            b'J', b'F', b'I', b'F', 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, // 16-byte APP0 payload
            0xFF, 0xC0, 0x00, 0x0B, // SOF0, len 11
            0x08, // precision 8
            0x01, 0xE0, 0x02, 0x80, // height 480, width 640
            0x01, 0x01, 0x11, 0x00, // 1 component
            // SOS so the header is DECODABLE — a lone SOF with no scan is
            // rejected by the decode tier's scan gate, and the probe mirrors
            // that (returning dims for an undecodable header would break the
            // "plausible header means the same thing on both paths"
            // invariant).
            0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00,
        ]);
        assert_eq!(probe_dimensions(&hostile_lep(&hdr)), Some((480, 640)));
    }

    /// The decoder rejects headers with MULTIPLE SOF blocks and headers whose
    /// SOF is never followed by a scan; the probe must mirror both instead of
    /// reporting the first SOF's dimensions for an undecodable file.
    #[test]
    fn probe_dimensions_rejects_second_sof_and_lone_sof() {
        // A valid SOF followed by a SECOND SOF (no SOS): undecodable.
        let mut hdr = b"HDR".to_vec();
        hdr.extend_from_slice(&26u32.to_le_bytes());
        hdr.extend_from_slice(&[
            0xFF, 0xC0, 0x00, 0x0B, // SOF0, len 11
            0x08, 0x00, 0x10, 0x00, 0x10, 0x01, 0x01, 0x11, 0x00, // 16x16, 1 comp
            0xFF, 0xC1, 0x00, 0x0B, // SOF1, len 11 — second SOF
            0x08, 0x00, 0x10, 0x00, 0x10, 0x01, 0x01, 0x11, 0x00,
        ]);
        assert_eq!(probe_dimensions(&hostile_lep(&hdr)), None);

        // A valid SOF with NO SOS at all (header ends): undecodable.
        let mut hdr = b"HDR".to_vec();
        hdr.extend_from_slice(&13u32.to_le_bytes());
        hdr.extend_from_slice(&[
            0xFF, 0xC0, 0x00, 0x0B, // SOF0, len 11
            0x08, 0x00, 0x10, 0x00, 0x10, 0x01, 0x01, 0x11, 0x00,
        ]);
        assert_eq!(probe_dimensions(&hostile_lep(&hdr)), None);
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

    /// The container's compressed header carries the camera's EXIF APP1 — the
    /// probe must surface it WITHOUT decoding a pixel. Minimal TIFF in IFD0:
    /// Make "Canon" (tag 0x010F, ASCII) and DateTimeOriginal
    /// "2026:07:31 12:00:00" (0x9003), all offsets TIFF-relative.
    #[test]
    fn probe_exif_reads_camera_tags_from_container_header() {
        let mut raw = Vec::new();
        // APP1 segment: len 89 = 2 length bytes + 87 payload.
        raw.extend_from_slice(&[0xFF, 0xE1, 0x00, 0x59]);
        raw.extend_from_slice(b"Exif\0\0");
        raw.extend_from_slice(b"II*\0");
        raw.extend_from_slice(&8u32.to_le_bytes()); // IFD0 at TIFF-relative 8
        raw.extend_from_slice(&2u16.to_le_bytes()); // two entries
                                                    // Make (0x010F) ASCII count 5 -> value at offset 38. Lives in the
                                                    // plain TIFF IFD0 (Context::Tiff).
        raw.extend_from_slice(&0x010Fu16.to_le_bytes());
        raw.extend_from_slice(&2u16.to_le_bytes()); // ASCII
        raw.extend_from_slice(&5u32.to_le_bytes());
        raw.extend_from_slice(&38u32.to_le_bytes());
        // ExifIFDPointer (0x8769) LONG -> the Exif sub-IFD at offset 44;
        // DateTimeOriginal lives THERE (Context::Exif — kamadak's tag
        // constants carry the context, so a bare IFD0 entry would not match
        // Tag::DateTimeOriginal).
        raw.extend_from_slice(&0x8769u16.to_le_bytes());
        raw.extend_from_slice(&4u16.to_le_bytes()); // LONG
        raw.extend_from_slice(&1u32.to_le_bytes());
        raw.extend_from_slice(&44u32.to_le_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes()); // next IFD offset
        raw.extend_from_slice(b"Canon"); // at TIFF-relative 38
        raw.push(0); // pad — the Exif IFD must start at TIFF-relative 44
        raw.extend_from_slice(&1u16.to_le_bytes()); // Exif IFD: one entry
                                                    // DateTimeOriginal (0x9003) ASCII count 19 -> value at offset 62.
        raw.extend_from_slice(&0x9003u16.to_le_bytes());
        raw.extend_from_slice(&2u16.to_le_bytes());
        raw.extend_from_slice(&19u32.to_le_bytes());
        raw.extend_from_slice(&62u32.to_le_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes()); // next Exif IFD offset
        raw.extend_from_slice(b"2026:07:31 12:00:00"); // at TIFF-relative 62
                                                       // SOF0 + SOS so the header is a parseable JPEG too.
        raw.extend_from_slice(&[
            0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x40, 0x00, 0x40, 0x01, 0x01, 0x11, 0x00, 0xFF,
            0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00,
        ]);
        let lep = hostile_lep(&hdr_payload(&raw, &[]));
        let exif = probe_exif(&lep).expect("container header carries EXIF");

        let make = exif.get_field(exif::Tag::Make, exif::In::PRIMARY).unwrap();
        match &make.value {
            exif::Value::Ascii(v) => assert_eq!(v.first().unwrap(), b"Canon"),
            other => panic!("Make should be ASCII, got {other:?}"),
        }
        let dt = exif
            .get_field(exif::Tag::DateTimeOriginal, exif::In::PRIMARY)
            .unwrap();
        match &dt.value {
            exif::Value::Ascii(v) => assert_eq!(v.first().unwrap(), b"2026:07:31 12:00:00"),
            other => panic!("DateTimeOriginal should be ASCII, got {other:?}"),
        }
    }

    /// The committed fixture's header has no EXIF APP1 — the probe must return
    /// None, not decode, and never panic.
    #[test]
    fn probe_exif_none_without_exif_segment() {
        let lep = include_bytes!("../../tests/fixtures/lepton.lep");
        assert!(probe_exif(lep).is_none());
        // Hostile garbage still decompresses-guarded: None, no panic.
        assert!(probe_exif(&[0xCF, 0x84, 0x01, b'Z', 0, 0, 0, 0]).is_none());
    }

    /// PATCH 16 regression: the marker loop's trailing `assert!(remaining == 0)`
    /// was reachable — a stream ending with 1-2 bytes after the last marker
    /// breaks the 3-byte prefix read on UnexpectedEof, then `read_to_end`
    /// finds the bytes and the assert fires: a PANIC in ALL builds on the
    /// header-parse main thread (no catch_unwind). Must be a clean error.
    #[test]
    fn trailing_bytes_after_markers_clean_error() {
        let (raw, markers) = real_header_parts();
        let mut payload = hdr_payload(&raw, &markers);
        payload.extend_from_slice(&[0x00, 0x00]); // 2 trailing bytes after the last marker
        let lep = hostile_lep_full(&payload, 64);
        let r = std::panic::catch_unwind(|| decode_lepton(&lep));
        assert!(
            r.is_ok(),
            "trailing bytes after the recovery markers must not hit the upstream assert"
        );
        assert!(r.unwrap().is_err());
    }
}
