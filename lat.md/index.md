# SageThumbs 2K

A modern, crash-isolated Rust shell extension for Windows 11: thumbnails, right-click tools, Quick preview, and a property store for 327 formats Windows can't read natively.

A clean-room revival of the GFL-based SageThumbs (2004–2017), PolyForm-Noncommercial licensed.

## Knowledge graph

Every load-bearing concept lives in one of these sections:

- [[architecture#Workspace Layout]] — crate split, artifacts, build layout
- [[architecture#Decode Pipeline]] — how a thumbnail is decoded, tier by tier
- [[architecture#COM Surface]] — the coclasses one DLL exposes
- [[architecture#Crash Isolation]] — why a corrupt file can't take down Explorer
- [[architecture#Settings and Localization]] — registry settings and baked-in i18n
- [[decoding#Decoder Tiers]] — the full decode ladder
- [[decoding#Lepton]] — .lep (Dropbox lossless JPEG) decode + vendored crash-safety patch
- [[decoding#Video Frames]] — Media Foundation frame grabs
- [[decoding#PDF Rendering]] — the in-box WinRT first-page renderer
- [[decoding#Quick Preview]] — the Space-bar viewer pipeline
- [[packaging#Release Pipeline]] — from `cargo build` to the Inno Setup installer
- [[packaging#DLL and EXE Conventions]] — co-located install layout and name contracts
