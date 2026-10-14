//! Loading `.nzb` files.
//!
//! Parsing itself is not reimplemented here — [`pesto::nzb::parse`] already
//! does it (it is the same format `pesto` writes when posting). This module
//! adds the download-side conveniences: reading from disk and summarizing.

use std::path::Path;

use anyhow::{bail, Context, Result};
use pesto::nzb::ParsedNzb;

/// Read and parse a `.nzb` file from disk.
pub fn load(path: &Path) -> Result<ParsedNzb> {
    let contents =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    pesto::nzb::parse(&contents).with_context(|| format!("parsing {}", path.display()))
}

/// Construct a transport decryption adapter from NZB metadata.
///
/// Decryption is activated strictly when `meta.yenc_encrypted` is true.
/// If `meta.yenc_encrypted` is false (e.g. unencrypted NZBs or NZBs with an archive password only),
/// returns `Ok(None)`.
/// If `meta.yenc_encrypted` is true, requires `meta.password`.
/// The password is never printed in error messages.
pub fn download_decryptor(
    meta: &pesto::nzb::NzbMeta,
) -> Result<Option<std::sync::Arc<pesto::crypto::DownloadDecryptionAdapter>>> {
    if !meta.yenc_encrypted {
        return Ok(None);
    }
    let password = meta
        .password
        .as_deref()
        .context("encrypted NZB is missing password metadata")?;
    if password.is_empty() {
        bail!("encrypted NZB password is empty");
    }
    Ok(Some(std::sync::Arc::new(
        pesto::crypto::DownloadDecryptionAdapter::with_password(password),
    )))
}

/// Aggregate counts over a parsed `.nzb`, used for `penne info` and for the
/// pre-download summary printed before a download starts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    pub files: usize,
    pub segments: usize,
    pub total_bytes: u64,
}

/// Compute a [`Summary`] over every segment in a parsed `.nzb`.
pub fn summarize(parsed: &ParsedNzb) -> Summary {
    let mut files = std::collections::HashSet::new();
    let mut total_bytes = 0u64;
    for seg in &parsed.segments {
        files.insert(&seg.file_name);
        total_bytes += seg.bytes;
    }
    Summary {
        files: files.len(),
        segments: parsed.segments.len(),
        total_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn summarize_counts_files_and_segments() {
        let groups = vec!["alt.test".to_string()];
        let segments = vec![
            pesto::poster::PostedSegment {
                file_name: "a.bin".into(),
                file_path: Path::new("a.bin").into(),
                subject_name: "a.bin".into(),
                wire_name: "a.bin".into(),
                wire_yenc_name: "a.bin".into(),
                file_size: 1000,
                part: 1,
                total: 2,
                message_id: "<a1@x>".into(),
                bytes: 500,
                from: "poster <p@x>".into(),
                date: (None, None),
                full_crc32: 0,
                server_idx: 0,
                file_index: 0,
                total_files: 0,
                segment_index: 0,
            },
            pesto::poster::PostedSegment {
                file_name: "a.bin".into(),
                file_path: Path::new("a.bin").into(),
                subject_name: "a.bin".into(),
                wire_name: "a.bin".into(),
                wire_yenc_name: "a.bin".into(),
                file_size: 1000,
                part: 2,
                total: 2,
                message_id: "<a2@x>".into(),
                bytes: 500,
                from: "poster <p@x>".into(),
                date: (None, None),
                full_crc32: 0,
                server_idx: 0,
                file_index: 0,
                total_files: 0,
                segment_index: 0,
            },
        ];
        let xml = pesto::nzb::generate(
            &groups,
            &segments,
            &pesto::nzb::NzbMeta::default(),
            pesto::config::ObfuscateMode::None,
        );

        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(xml.as_bytes()).unwrap();

        let parsed = load(file.path()).unwrap();
        let summary = summarize(&parsed);
        assert_eq!(summary.files, 1);
        assert_eq!(summary.segments, 2);
        assert_eq!(summary.total_bytes, 1000);
    }

    #[test]
    fn test_download_decryptor_mode_selection() {
        // Unencrypted metadata yields None even if password is set (archive
        // password only); encrypted metadata without a password errors
        // fail-closed; encrypted metadata with a password creates one. A
        // whitespace-only password is a valid (if unusual) secret; only the
        // empty string is rejected.
        let meta_unencrypted = pesto::nzb::NzbMeta {
            yenc_encrypted: false,
            password: Some("archive-secret".into()),
            ..Default::default()
        };
        assert!(download_decryptor(&meta_unencrypted).unwrap().is_none());

        let meta_missing_pwd = pesto::nzb::NzbMeta {
            yenc_encrypted: true,
            password: None,
            ..Default::default()
        };
        let err = match download_decryptor(&meta_missing_pwd) {
            Err(e) => e,
            Ok(_) => panic!("expected error for missing password on encrypted NZB"),
        };
        assert!(err.to_string().contains("missing password metadata"));

        let meta_encrypted = pesto::nzb::NzbMeta {
            yenc_encrypted: true,
            password: Some("transport-secret".into()),
            ..Default::default()
        };
        assert!(download_decryptor(&meta_encrypted).unwrap().is_some());

        let meta_empty_pwd = pesto::nzb::NzbMeta {
            yenc_encrypted: true,
            password: Some(String::new()),
            ..Default::default()
        };
        assert!(download_decryptor(&meta_empty_pwd).is_err());
        let meta_whitespace_pwd = pesto::nzb::NzbMeta {
            yenc_encrypted: true,
            password: Some("   ".into()),
            ..Default::default()
        };
        assert!(download_decryptor(&meta_whitespace_pwd).is_ok());
    }
}
