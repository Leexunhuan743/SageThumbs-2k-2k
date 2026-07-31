//! Hostile-header regression tests for the SAGETHUMBS hardening patches
//! (12-16). These exercise the DECODE side's error codes directly — the app
//! layer flattens every failure to E_FAIL, so only here can the tests assert
//! which clean ExitCode a hostile file produces (vs. an upstream
//! AssertionFailure/panic path). Every test fails against the unpatched code.

use std::io::{Cursor, Read, Write};

use lepton_jpeg::{
    EnabledFeatures, ExitCode, LeptonError, LeptonThreadPriority, SimpleThreadPool, decode_lepton,
};

fn features() -> EnabledFeatures {
    // Mirrors the app tier's decode configuration (src/decode/lepton.rs).
    EnabledFeatures {
        progressive: true,
        reject_dqts_with_zeros: false,
        max_jpeg_width: 16384,
        max_jpeg_height: 16384,
        use_16bit_dc_estimate: true,
        use_16bit_adv_predict: true,
        accept_invalid_dht: true,
        max_partitions: 8,
        max_processor_threads: 2,
        max_jpeg_file_size: 128 * 1024 * 1024,
        stop_reading_at_eoi: false,
    }
}

fn decode_err(lep: &[u8]) -> LeptonError {
    let features = features();
    let pool = SimpleThreadPool::new(LeptonThreadPriority::Normal);
    let mut out = Vec::new();
    decode_lepton(&mut Cursor::new(lep), &mut out, &features, &pool)
        .expect_err("hostile .lep must fail decode")
}

/// Build a hostile .lep whose zlib-compressed header is `header_payload` (the
/// "HDR" marker + u32 raw-header length + raw header + recovery markers). The
/// fixed 28-byte prefix mirrors the app tier's `hostile_lep_full` and the Rust
/// encoder's layout; the trailing CMP junk is never reached by these tests.
fn hostile_lep(header_payload: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(header_payload).unwrap();
    let compressed = enc.finish().unwrap();

    let mut lep = Vec::new();
    lep.extend_from_slice(&[0xCF, 0x84, 0x01, b'Z', 0, 0, 0, 0]);
    lep.extend_from_slice(b"MS");
    lep.extend_from_slice(&0u32.to_le_bytes()); // legacy uncompressed header size
    lep.push(0x80); // flags
    lep.push(1); // encoder_version — != 55 so the patch-8 path runs
    lep.extend_from_slice(&[0; 4]); // git revision prefix
    lep.extend_from_slice(&64u32.to_le_bytes()); // jpeg_file_size
    lep.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
    lep.extend_from_slice(&compressed);
    lep.extend_from_slice(b"CMP");
    lep.extend_from_slice(&(lep.len() as u32 + 4).to_le_bytes());
    lep
}

fn hdr_payload(raw: &[u8], markers: &[u8]) -> Vec<u8> {
    let mut hdr = b"HDR".to_vec();
    hdr.extend_from_slice(&(raw.len() as u32).to_le_bytes());
    hdr.extend_from_slice(raw);
    hdr.extend_from_slice(markers);
    hdr
}

/// Parseable JPEG header: SOF0 (baseline) with the given component table,
/// DQT (non-zero table 0), SOS matching the components — enough to pass the
/// scan gate so the decode path runs.
fn raw_header(sof: &[u8], sos_components: &[u8]) -> Vec<u8> {
    let mut raw = sof.to_vec();
    raw.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43, 0x00]); // DQT len 67 table 0
    raw.extend_from_slice(&[1; 64]); // non-zero quantization values
    raw.extend_from_slice(sos_components);
    raw
}

/// SOF0 for 64x64, N components, all 1x1 sampling, qt 0.
fn sof0_64x64(n: u8) -> Vec<u8> {
    let mut sof: Vec<u8> = vec![
        0xFF,
        0xC0,
        0x00,
        (6 + 3 * n as u16 + 2) as u8,
        0x08,
        0x00,
        0x40,
        0x00,
        0x40,
        n,
    ];
    for c in 1..=n {
        sof.extend_from_slice(&[c, 0x11, 0x00]);
    }
    sof
}

/// SOS referencing `components` (jid, huff_dc/ac pairs), single-scan spectral
/// selection 0..63.
fn sos(components: &[u8]) -> Vec<u8> {
    let mut s: Vec<u8> = vec![
        0xFF,
        0xDA,
        0x00,
        (6 + 2 * components.len() as u16) as u8, // payload = Ns(1) + 2N + Ss/Se/AhAl(3)
        components.len() as u8,
    ];
    for c in components {
        s.extend_from_slice(&[*c, 0x00]);
    }
    s.extend_from_slice(&[0x00, 0x3F, 0x00]);
    s
}

/// One-thread HH marker (16 bytes per handoff).
fn hh1(start: u16, size: u32, overhang_bits: u8) -> Vec<u8> {
    let mut hh = b"HH".to_vec();
    hh.push(1);
    hh.extend_from_slice(&start.to_le_bytes());
    hh.extend_from_slice(&size.to_le_bytes());
    hh.push(0); // overhang_byte
    hh.push(overhang_bits);
    for _ in 0..3 {
        hh.extend_from_slice(&0i16.to_le_bytes());
    }
    hh.extend_from_slice(&0u16.to_le_bytes());
    hh
}

/// Two-thread HH marker with explicit starts.
fn hh2(starts: &[u16]) -> Vec<u8> {
    let mut hh = b"HH".to_vec();
    hh.push(2);
    for start in starts {
        hh.extend_from_slice(&start.to_le_bytes());
        hh.extend_from_slice(&0u32.to_le_bytes()); // segment_size
        hh.push(0); // overhang_byte
        hh.push(0); // num_overhang_bits
        for _ in 0..3 {
            hh.extend_from_slice(&0i16.to_le_bytes());
        }
        hh.extend_from_slice(&0u16.to_le_bytes());
    }
    hh
}

/// PATCH 13 discriminator (CMYK gate): the vendored `JpegHeader::parse` used
/// to accept up to 4 components (`cmpc > 4`), while the C++ reference rejects
/// 4-color JPEGs at header-parse time (`custom_exit(UNSUPPORTED_4_COLORS)`)
/// and the Rust port only kept that rejection on the ENCODE side. A hostile
/// 4-component .lep then reached `RowSpec::get_row_spec_from_index`'s
/// `image_data.len() <= COLOR_CHANNEL_NUM_BLOCK_TYPES` assert on a decode
/// worker — a panic in ALL builds (release: process abort in the shell host).
/// Patched: parse rejects cmpc > 3 with UnsupportedJpeg before any decode.
#[test]
fn four_component_sof_rejected() {
    let raw = raw_header(&sof0_64x64(4), &sos(&[1, 2, 3, 4]));
    let lep = hostile_lep(&hdr_payload(&raw, &hh1(0, 0, 0)));
    let err = decode_err(&lep);
    assert_eq!(
        err.exit_code(),
        ExitCode::UnsupportedJpeg,
        "4-component (CMYK) header must be rejected at parse time, got {err}"
    );
}

/// PATCH 14 discriminator (MCU-row grid alignment): patch 4 validated thread
/// ranges for inversion/contiguity/start-at-0 but NOT MCU-row alignment. A
/// hostile HH with starts [0,1) on a 4:2:0 image (grid = bcv[0]/mcuv = 2)
/// passes those checks yet makes thread 0 decode a WHOLE MCU row (2 luma
/// block rows) into a partition whose capacity only covers 1 luma row —
/// `append_block`'s capacity assert fires on a worker (release: abort).
/// Patched: off-grid boundaries are rejected as BadLeptonFile in the header.
#[test]
fn off_grid_thread_range_rejected() {
    // 64x64, 3 components, luma 2x2 / chroma 1x1 (4:2:0): bcv[0] = 8,
    // mcuv = 4, grid = 2.
    let mut sof = vec![0xFF, 0xC0, 0x00, 0x11, 0x08, 0x00, 0x40, 0x00, 0x40, 0x03];
    sof.extend_from_slice(&[0x01, 0x22, 0x00]); // luma 2x2
    sof.extend_from_slice(&[0x02, 0x11, 0x00]);
    sof.extend_from_slice(&[0x03, 0x11, 0x00]);
    let raw = raw_header(&sof, &sos(&[1, 2, 3]));
    // Thread 1 starts at luma row 1 — between the two rows of MCU row 0.
    let lep = hostile_lep(&hdr_payload(&raw, &hh2(&[0, 1])));
    let err = decode_err(&lep);
    assert_eq!(
        err.exit_code(),
        ExitCode::BadLeptonFile,
        "off-grid thread range must be rejected in the header, got {err}"
    );
}

/// PATCH 15 discriminator lives in `structs/thread_handoff.rs` (the type is
/// not re-exported from the crate root, so it is tested in-module).

/// PATCH 16 discriminator (CRS entry-count budget): the patch-10 cap bounded
/// ONE CRS marker's entry count at max_jpeg_file_size entries (a 512 MiB Vec)
/// but not the byte-equivalent budget, and nothing capped the decompressed
/// stream as a whole. A single CRS declaring 33M entries (132 MiB of reads)
/// used to pass the per-marker cap and fail only on stream exhaustion;
/// patched, the entry count is capped at max_jpeg_file_size/4 (byte-consistent
/// with the sibling caps) and rejected as BadLeptonFile before any read.
#[test]
fn crs_entry_count_capped() {
    let raw = raw_header(&sof0_64x64(1), &sos(&[1]));
    let mut payload = hdr_payload(&raw, &hh1(0, 0, 0));
    payload.extend_from_slice(b"CRS");
    payload.extend_from_slice(&(33 * 1024 * 1024u32).to_le_bytes()); // > 128MiB/4
    let lep = hostile_lep(&payload);
    let err = decode_err(&lep);
    assert_eq!(
        err.exit_code(),
        ExitCode::BadLeptonFile,
        "CRS entry count above the byte budget must be rejected, got {err}"
    );
}
