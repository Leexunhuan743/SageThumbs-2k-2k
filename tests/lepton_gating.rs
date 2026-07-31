//! Regression coverage for the Lepton (.lep) wiring across every shell gating
//! surface: the FORMATS table (which `register.rs` loops to write the
//! thumbnail/property/preview shellex keys), the `is_known` menu gate, the
//! Options-list `category`, the `is_archive` exclusion, and the verb-menu gate
//! (`verbs::actions::is_image` = `is_known && !is_archive`).
//!
//! Pure unit assertions — no COM registration (that needs admin/shell), no
//! decoding. Each test would FAIL if a future per-format change dropped `.lep`
//! from any one of these surfaces, so the next maintainer can't silently
//! unregister the format without CI noticing.

use sagethumbs2k_core::formats::{self, Category};

/// The verb-menu gate lives in the private `verbs` module and is not
/// re-exported from the crate root, so an integration test cannot call
/// `is_image` directly. This mirrors `src/verbs/actions.rs`'s `is_image`
/// one-for-one (`is_known(ext) && !is_archive(ext)`) and fails exactly when
/// that gate stops accepting `.lep` (i.e. when `.lep` leaves FORMATS).
fn verb_image_gate(path: &str) -> bool {
    std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| formats::is_known(e) && !formats::is_archive(e))
}

#[test]
fn lep_is_known_case_insensitively() {
    assert!(formats::is_known("lep"));
    assert!(formats::is_known("LEP"));
    assert!(formats::is_known("Lep"));
}

#[test]
fn lep_is_categorized_as_image() {
    assert_eq!(formats::category("lep"), Category::Image);
    assert_eq!(formats::category("LEP"), Category::Image);
}

#[test]
fn lep_is_not_an_archive() {
    assert!(!formats::is_archive("lep"));
}

#[test]
fn lep_is_registered_with_lepton_display_name() {
    let entry = formats::FORMATS
        .iter()
        .find(|(ext, _)| ext.eq_ignore_ascii_case("lep"))
        .expect("FORMATS must contain a .lep entry");
    assert_eq!(
        entry.0, "lep",
        "the registered extension should be lowercase"
    );
    assert!(
        entry.1.contains("Lepton"),
        "display name {:?} should mention Lepton",
        entry.1
    );
}

#[test]
fn lep_passes_the_verb_image_gate() {
    assert!(verb_image_gate("photo.lep"));
    assert!(
        verb_image_gate("photo.LEP"),
        "gate must be case-insensitive"
    );
    // A non-format extension is not an image.
    assert!(!verb_image_gate("photo.xyz"));
    // A known-but-archive extension is excluded by the same gate (.zip is in
    // FORMATS), proving the archive half of the composition is exercised too.
    assert!(!verb_image_gate("archive.zip"));
}

#[test]
fn formats_table_has_327_entries() {
    // The FORMATS count is a cross-file contract: scripts/check-consistency.ps1
    // enforces the same 327 against the README badge and docs/FEATURES.md, and
    // register.rs derives the Explorer shellex keys from this table. When the
    // count changes, bump all four copies together.
    assert_eq!(formats::FORMATS.len(), 327);
}
