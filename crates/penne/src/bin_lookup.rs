//! Test-helper lookup for the prebuilt `pesto` producer binary
//! (PT-03 freshness simplification; reviewer final design). NOT used on
//! penne's download path -- integration-test producer lookup only.
//!
//! Design: `binary_is_stale` is the ONLY staleness decision anywhere
//! (one mtime comparison site). `pesto_binary` returns a fresh candidate
//! as-is; a stale/missing candidate gets exactly one rebuild attempt per
//! call, and whatever the rebuild produces is accepted without a
//! post-rebuild staleness re-check. No persistent freshness files exist.
//! Externally preserved: when no rebuild is possible (e.g. `CARGO`
//! unset) an existing stale candidate is
//! returned with `stale_detected=true` on stderr (the prior skip
//! contract for callers/tests that grep that marker); when there is no
//! candidate at all, `None` is returned. Accepted change vs the previous layered machinery: a permanently-
//! missing manifest now costs one rebuild attempt per `pesto_binary`
//! call instead of loop avoidance -- fine for a test helper.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

/// Modification-time key for `path`: `None` when the file is missing or
/// its metadata/mtime cannot be read.
#[inline]
fn mtime_key(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// PT-03 stale-binary check: `binary` is stale iff it is older than
/// `manifest` (the pesto crate manifest, `crates/pesto/Cargo.toml`).
/// Missing/unreadable mtime on either side counts as stale (`true`):
/// freshness cannot be proven, so callers skip/rebuild rather than
/// exercising a possibly-outdated binary.
#[doc(hidden)]
pub fn binary_is_stale(binary: &Path, manifest: &Path) -> bool {
    let (Some(bmtime), Some(mmtime)) = (mtime_key(binary), mtime_key(manifest)) else {
        return true;
    };
    bmtime < mmtime
}

/// Candidate paths for the prebuilt `pesto` producer CLI, in search
/// order: `CARGO_BIN_EXE_pesto`, beside the running test executable,
/// then workspace `target/{debug,release}`.
#[doc(hidden)]
pub fn pesto_bin_search_order() -> Vec<PathBuf> {
    let exe_name = if cfg!(windows) { "pesto.exe" } else { "pesto" };
    let mut order = Vec::new();
    if let Some(p) = std::env::var_os("CARGO_BIN_EXE_pesto") {
        order.push(PathBuf::from(p));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(profile_dir) = exe.parent().and_then(Path::parent) {
            order.push(profile_dir.join(exe_name));
        }
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(workspace) = manifest_dir.parent().and_then(Path::parent) {
        for profile in ["debug", "release"] {
            order.push(workspace.join("target").join(profile).join(exe_name));
        }
    }
    order
}

fn locate_pesto_bin() -> Option<PathBuf> {
    pesto_bin_search_order().into_iter().find(|p| p.exists())
}

/// Pesto crate manifest: the staleness reference / workspace Cargo.toml neighbour.
#[doc(hidden)]
pub fn pesto_manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("penne lives under crates/")
        .join("pesto")
        .join("Cargo.toml")
}

fn workspace_root() -> Option<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .parent()
        .map(Path::to_path_buf)
}

/// Attempt ONE rebuild of the `pesto` producer CLI via the active cargo
/// (existing rebuild mechanism, kept as-is). Returns the rebuilt binary
/// path (from cargo's JSON artifact report, else re-located) on success;
/// `None` when `CARGO` is unset or the build/report fails.
fn rebuild_pesto_bin() -> Option<PathBuf> {
    let cargo = std::env::var_os("CARGO")?;
    let workspace = workspace_root()?;
    let output = Command::new(cargo)
        .current_dir(&workspace)
        .args([
            "build",
            "--offline",
            "--bin",
            "pesto",
            "-p",
            "pesto-poster",
            "--message-format=json",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Ok(msg) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let is_pesto_bin = msg.get("reason").and_then(|r| r.as_str()) == Some("compiler-artifact")
            && msg
                .get("target")
                .and_then(|t| t.get("name"))
                .and_then(|n| n.as_str())
                == Some("pesto")
            && msg
                .get("target")
                .and_then(|t| t.get("kind"))
                .and_then(|k| k.as_array())
                .is_some_and(|kinds| kinds.iter().any(|k| k.as_str() == Some("bin")));
        if is_pesto_bin {
            if let Some(exe) = msg.get("executable").and_then(|e| e.as_str()) {
                let p = PathBuf::from(exe);
                if p.exists() {
                    return Some(p);
                }
            }
        }
    }
    locate_pesto_bin()
}

/// Production lookup (test-helper only, not the penne download path):
/// 1. fresh candidate -> return it;
/// 2. stale/missing candidate -> rebuild at most once; return the
///    rebuilt binary if it exists (accepted as current, NO re-check);
/// 3. rebuild failed/impossible -> return the existing stale candidate
///    if any (with `stale_detected=true` on stderr, preserving the prior
///    external contract), else `None`.
#[doc(hidden)]
pub fn pesto_binary() -> Option<PathBuf> {
    let candidate = locate_pesto_bin();
    if let Some(bin) = &candidate {
        if !binary_is_stale(bin, &pesto_manifest()) {
            return Some(bin.clone());
        }
    }
    // Stale or missing: at most one rebuild attempt per call.
    if let Some(rebuilt) = rebuild_pesto_bin() {
        return Some(rebuilt);
    }
    if let Some(bin) = candidate {
        eprintln!(
            "stale_detected=true: {} is stale vs {}; rebuild unavailable, returning stale candidate",
            bin.display(),
            pesto_manifest().display()
        );
        return Some(bin);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_is_stale_flags_older_binary_and_accepts_fresher_one() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("Cargo.toml");
        let bin = dir.path().join("pesto");

        // Controlled mtimes (explicit, no write-ordering reliance):
        // manifest pinned to a fixed instant, binary placed around it.
        let manifest_time =
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        std::fs::write(&manifest, b"manifest").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&manifest)
            .unwrap()
            .set_modified(manifest_time)
            .unwrap();
        std::fs::write(&bin, b"bin").unwrap();

        // Fresh: binary newer than manifest -> false.
        std::fs::File::options()
            .write(true)
            .open(&bin)
            .unwrap()
            .set_modified(manifest_time + std::time::Duration::from_secs(3600))
            .unwrap();
        assert!(!binary_is_stale(&bin, &manifest));

        // Stale: binary older than manifest -> true.
        std::fs::File::options()
            .write(true)
            .open(&bin)
            .unwrap()
            .set_modified(manifest_time - std::time::Duration::from_secs(3600))
            .unwrap();
        assert!(binary_is_stale(&bin, &manifest));

        // Missing binary / missing manifest: cannot prove freshness, stale.
        assert!(binary_is_stale(&dir.path().join("absent"), &manifest));
        assert!(binary_is_stale(&bin, &dir.path().join("absent.toml")));
    }
}
