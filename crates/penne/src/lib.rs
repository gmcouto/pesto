//! Public API of `penne`, a fast NZB downloader for Usenet.
//!
//! `penne` reads a `.nzb` file, fetches its articles over NNTP, reassembles
//! them into the original files, and verifies/repairs the result with PAR2.
//! See `ROADMAP.md` for the development plan and current phase.
//!
//! `penne` reuses `pesto`'s NNTP connection (TLS + `AUTHINFO`) and `.nzb`
//! parser rather than duplicating that logic — see [`pesto::nntp`] and
//! [`pesto::nzb::parse`].
//!
//! This crate is the download engine underneath the future `penne` CLI and,
//! eventually, a web UI (à la SABnzbd) built on top of it. The web UI is out
//! of scope until the CLI reaches feature parity with the roadmap.

/// Shown by `--version`.
pub const DISPLAY_VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod assemble;
pub mod cache;
pub mod check;
pub mod cleanup;
pub mod client;
pub mod config;
pub mod deobfuscate;
pub mod diskspace;
pub mod download;
pub mod extract;
pub mod health;
pub mod nzb;
pub mod progress;
pub mod queue;
pub mod quickcheck;
pub mod repair;
pub mod ui;
pub mod wizard;

/// PT-03 stale-binary check: `binary` is stale iff it is older than
/// `manifest` (the pesto crate manifest, `crates/pesto/Cargo.toml`).
///
/// This is the sole definition of the predicate; integration tests must
/// import it here rather than redefining it locally. A missing/unreadable
/// mtime on either side counts as stale (`true`) so callers hard-fail
/// rather than exercising a possibly-outdated binary. Pure predicate —
/// no cargo process is spawned here, keeping the no-nested-cargo guarantee.
#[doc(hidden)]
pub fn binary_is_stale(binary: &std::path::Path, manifest: &std::path::Path) -> bool {
    let Some(bmtime) = std::fs::metadata(binary).and_then(|m| m.modified()).ok() else {
        return true;
    };
    let Some(mmtime) = std::fs::metadata(manifest).and_then(|m| m.modified()).ok() else {
        return true;
    };
    bmtime < mmtime
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_is_stale_flags_older_binary_and_accepts_fresher_one() {
        use std::time::{Duration, UNIX_EPOCH};
        let root = tempfile::tempdir().unwrap();
        let manifest = root.path().join("Cargo.toml");
        let binary = root.path().join("pesto");
        std::fs::write(&manifest, b"[package]\n").unwrap();
        std::fs::write(&binary, b"binary").unwrap();
        let base = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        std::fs::File::open(&manifest)
            .unwrap()
            .set_modified(base)
            .unwrap();
        // Binary newer than manifest by 3600s => not stale.
        std::fs::File::open(&binary)
            .unwrap()
            .set_modified(base + Duration::from_secs(3600))
            .unwrap();
        assert!(!binary_is_stale(&binary, &manifest));
        // Binary older than manifest by 3600s => stale.
        std::fs::File::open(&binary)
            .unwrap()
            .set_modified(base - Duration::from_secs(3600))
            .unwrap();
        assert!(binary_is_stale(&binary, &manifest));
        // Missing binary / missing manifest => stale.
        assert!(binary_is_stale(
            root.path().join("missing-bin").as_path(),
            &manifest
        ));
        assert!(binary_is_stale(
            &binary,
            root.path().join("missing-Cargo.toml").as_path()
        ));
    }
}
