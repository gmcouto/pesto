//! NZB parsing: reconstructing posted segments from NZB 1.1 XML.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};

use crate::crypto::{attach_crypto_error_kind, CryptoErrorKind};
use crate::poster::PostedSegment;

use super::{NzbMeta, ParsedNzb, YENC_SPEC_VERSION};

struct RawSegment {
    file_name: String,
    subject_name: String,
    poster: String,
    date: Option<u64>,
    bytes: u64,
    part: u32,
    total: u32,
    message_id: String,
    file_ordinal: u32,
    total_files: u32,
}

/// Parse a `.nzb` document and reconstruct its [`PostedSegment`] list.
///
/// Unencrypted releases and archive-password-only releases parse with `segment_identities: None`.
/// Encrypted releases (indicated by `<meta type="yenc_encrypted">true</meta>`) are marked
/// `yenc_encrypted`; segment identity is derived exclusively from each article's Line 1
/// bootstrap bytes at download time (Body Encryption Standard v1.2 §8 consumer req 3:
/// readers MUST NOT consume legacy segment-index XML attributes — if present, they are ignored).
pub fn parse(content: &str) -> Result<ParsedNzb> {
    parse_internal(content, false)
}

/// Parse an encrypted `.nzb` document.
///
/// Requires encryption provenance (`<meta type="yenc_encrypted">true</meta>`).
/// Segment identity is bootstrap-only: no segment-index XML attribute is
/// read, validated, or required (v1.2 §8 — readers MUST NOT consume legacy
/// segment-index attributes; writers MUST NOT emit them).
pub fn parse_encrypted(content: &str) -> Result<ParsedNzb> {
    parse_internal(content, true)
}

fn parse_internal(content: &str, force_encrypted: bool) -> Result<ParsedNzb> {
    let mut poster = String::new();
    let mut groups: Vec<String> = Vec::new();
    let mut meta = NzbMeta::default();
    let mut explicit_yenc_encrypted = false;

    let mut current_file_name = String::new();
    let mut current_subject_name = String::new();
    let mut current_poster = String::new();
    let mut current_date: Option<u64> = None;
    let mut current_file_ordinal = 0u32;
    let mut current_total_files = 0u32;
    let mut file_segment_start: usize = 0;
    let mut in_groups = false;
    let mut in_file = false;

    let mut raw_segments: Vec<RawSegment> = Vec::new();

    let mut pending = String::new();
    let mut tags: Vec<String> = Vec::new();

    for line in content.lines() {
        if pending.is_empty() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            pending.push_str(trimmed);
        } else {
            pending.push('\n');
            pending.push_str(line.trim_end());
        }

        if pending.starts_with('<') {
            let quotes = pending.bytes().filter(|&b| b == b'"').count();
            if quotes % 2 != 0 || !pending.contains('>') {
                continue;
            }
        }

        tags.push(std::mem::take(&mut pending));
    }
    if !pending.is_empty() {
        tags.push(pending);
    }

    for t in &tags {
        let t = t.trim();
        if t.starts_with("<file ") {
            in_file = true;
            in_groups = false;
            current_poster = xml_attr(t, "poster").unwrap_or_default();
            if poster.is_empty() {
                poster = current_poster.clone();
            }
            current_date = xml_attr(t, "date").and_then(|s| s.parse().ok());
            let subject = xml_attr(t, "subject").unwrap_or_default();

            match parse_file_counter(&subject) {
                Some((n, m, _residual)) => {
                    current_file_ordinal = n;
                    current_total_files = m;
                }
                None => {
                    current_file_ordinal = 0;
                    current_total_files = 0;
                }
            }

            current_subject_name = strip_part_suffix(&subject);
            current_file_name = current_subject_name.clone();
            file_segment_start = raw_segments.len();
        } else if t == "</file>" {
            let total = (raw_segments.len() - file_segment_start) as u32;
            for seg in &mut raw_segments[file_segment_start..] {
                seg.total = total;
            }
            in_file = false;
        } else if t == "<groups>" {
            in_groups = true;
        } else if t == "</groups>" {
            in_groups = false;
        } else if in_groups {
            let g = xml_text(t, "group").context("malformed XML text in group")?;
            if !groups.contains(&g) {
                groups.push(g);
            }
        } else if in_file && t.starts_with("<segment ") {
            let bytes: u64 = xml_attr(t, "bytes")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let part: u32 = xml_attr(t, "number")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let raw_id = xml_text(t, "segment").context("malformed XML text in segment")?;
            let message_id = if raw_id.starts_with('<') {
                raw_id
            } else {
                format!("<{raw_id}>")
            };
            // v1.2 §8: any legacy segment-index XML attribute is IGNORED — not
            // consumed, not validated. Segment identity derives exclusively
            // from each article's Line 1 bootstrap bytes at download time.

            raw_segments.push(RawSegment {
                file_name: current_file_name.clone(),
                subject_name: current_subject_name.clone(),
                poster: current_poster.clone(),
                date: current_date,
                bytes,
                part,
                total: 0,
                message_id,
                file_ordinal: current_file_ordinal,
                total_files: current_total_files,
            });
        } else if t.starts_with("<meta ") {
            let kind = xml_attr(t, "type").unwrap_or_default();
            let value = xml_text(t, "meta").context("malformed XML text in meta")?;
            match kind.as_str() {
                "title" => meta.name = Some(value),
                "password" => meta.password = Some(value),
                "category" => meta.category = Some(value),
                "tag" => meta.tags.push(value),
                "yenc_encrypted" if value == "true" => {
                    explicit_yenc_encrypted = true;
                }
                "yenc_version" => {
                    meta.yenc_version = Some(value.clone());
                }
                "yenc_cipher" => {
                    meta.yenc_cipher = Some(value.clone());
                }
                _ => {}
            }
        }
    }

    // Encryption provenance: explicit `yenc_encrypted` meta (v1.2 §8), or —
    // for `parse_encrypted`'s caller contract — forced. The legacy
    // `(password && any segment-index attribute)` inference heuristic is
    // DELETED (Phase 58 T3): XML attributes are never consumed, so they can
    // never prove encryption.
    let is_encrypted = force_encrypted || explicit_yenc_encrypted;

    if is_encrypted {
        // T10 fail-closed gating (Body Encryption Standard v1.2 §8): a
        // declared-encrypted NZB with unsupported provenance metadata is a
        // STRUCTURAL failure — it would reproduce identically against every
        // server — so it is typed `MetadataValidation` at the parse origin
        // (the downloader aborts instead of rotating providers, and releases
        // no plaintext).
        if let Some(ref ver) = meta.yenc_version {
            if ver != "1.0" && ver != "1.1" && ver != YENC_SPEC_VERSION {
                return Err(attach_crypto_error_kind(
                    anyhow::anyhow!("unsupported yenc_version in nzb: {ver}"),
                    CryptoErrorKind::MetadataValidation,
                ));
            }
        }
        if let Some(ref cipher) = meta.yenc_cipher {
            if cipher != "XChaCha20-Poly1305" {
                return Err(attach_crypto_error_kind(
                    anyhow::anyhow!("unsupported yenc_cipher in nzb: {cipher}"),
                    CryptoErrorKind::MetadataValidation,
                ));
            }
        }
        meta.yenc_encrypted = true;
    }

    // Bootstrap-only identity (v1.2 §8): no segment identity is constructed
    // at NZB parse time. Identity comes exclusively from each article's
    // Line 1 bootstrap bytes after fetch; download-time validation is
    // per-article only (non-zero, CR-02-safe) — release-wide uniqueness is a
    // PRODUCER obligation (nth_safe_segment_index mapping), because bootstrap
    // indices live inside unfetched articles and cannot be validated here.
    let mut segments = Vec::with_capacity(raw_segments.len());
    for raw in raw_segments {
        segments.push(PostedSegment {
            file_name: raw.file_name.clone(),
            file_path: Arc::from(Path::new(&raw.file_name)),
            subject_name: Arc::from(raw.subject_name.as_str()),
            wire_name: Arc::from(""),
            wire_yenc_name: Arc::from(""),
            file_size: 0,
            part: raw.part,
            total: raw.total,
            message_id: raw.message_id,
            bytes: raw.bytes,
            from: Arc::from(raw.poster.as_str()),
            date: (None, raw.date),
            full_crc32: 0,
            server_idx: 0,
            file_index: raw.file_ordinal,
            total_files: raw.total_files,
            segment_identity: None,
        });
    }

    segments.sort_by(|a, b| a.file_name.cmp(&b.file_name).then(a.part.cmp(&b.part)));

    Ok(ParsedNzb {
        poster,
        groups,
        segments,
        meta,
        segment_identities: None,
    })
}

/// Extract the value of `name="..."` from an XML tag string.
fn xml_attr(tag: &str, name: &str) -> Option<String> {
    let key = format!("{name}=\"");
    let start = tag.find(&key)? + key.len();
    let end = tag[start..].find('"')? + start;
    Some(xml_unescape(&tag[start..end]))
}

/// Extract text content from `<tag ...>text</tag>` on a single line.
fn xml_text(line: &str, tag: &str) -> Option<String> {
    let open_end = line.find('>')?;
    let close = format!("</{tag}>");
    let close_start = line.rfind(&close)?;
    if close_start < open_end + 1 {
        return None;
    }
    let text = &line[open_end + 1..close_start];
    let mut without_comments = String::with_capacity(text.len());
    let mut remaining = text;
    while let Some(start) = remaining.find("<!--") {
        without_comments.push_str(&remaining[..start]);
        let after_start = &remaining[start + 4..];
        let end = after_start.find("-->")?;
        remaining = &after_start[end + 3..];
    }
    without_comments.push_str(remaining);
    Some(xml_unescape(&without_comments))
}

/// Strip the `"name" yEnc (N/M)` or `"name" yEnc` wrapper from a subject line.
///
/// Handles both the current yEnc-spec format and the legacy `name (N/M)` format.
/// Backward compatibility is needed because `pesto --merge-season` can read
/// NZBs created before the yEnc spec fix (e.g. subjects like `movie.mkv (1/3)`).
pub(super) fn strip_part_suffix(subject: &str) -> String {
    let unquote = |s: &str| {
        if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
            s[1..s.len() - 1].to_string()
        } else {
            s.to_string()
        }
    };

    // New format: "name" yEnc (N/M)  →  strip " yEnc (N/M)"
    // New format: "name" yEnc        →  strip " yEnc"
    if let Some(pos) = subject.rfind(" yEnc") {
        let tail = &subject[pos + 5..];
        if tail.is_empty() || tail.starts_with(" (") {
            return unquote(strip_filenum_prefix(&subject[..pos]));
        }
    }

    // Legacy format: name (N/M)
    if let Some(pos) = subject.rfind(" (") {
        let tail = &subject[pos..];
        if tail.contains('/') && tail.ends_with(')') {
            return subject[..pos].to_string();
        }
    }
    subject.to_string()
}

/// Parse a leading `[N/M]` file counter from a subject string.
///
/// Returns `Some((file_ordinal, total_files, residual))` when the subject
/// begins with a well-formed `[N/M] - ...` counter where both `N` and `M`
/// are non-zero ASCII decimal integers that fit in `u32`. The residual is
/// the part of the subject after the `] - ` separator.
///
/// Returns `None` when the prefix is absent, malformed, or contains zero
/// values — the subject is then treated as ordinary with no counter.
pub fn parse_file_counter(s: &str) -> Option<(u32, u32, &str)> {
    let rest = s.strip_prefix('[')?;
    let (counter, after) = rest.split_once(']')?;
    let (n_str, m_str) = counter.split_once('/')?;
    // Both parts must be non-empty pure ASCII digits.
    if n_str.is_empty()
        || m_str.is_empty()
        || !n_str.bytes().all(|b| b.is_ascii_digit())
        || !m_str.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    // Reject counters with more than one `/` (e.g. `[1/2/3]`).
    if counter.matches('/').count() != 1 {
        return None;
    }
    let n: u32 = n_str.parse().ok()?;
    let m: u32 = m_str.parse().ok()?;
    if n == 0 || m == 0 {
        return None;
    }
    let residual = after.strip_prefix(" - ")?;
    Some((n, m, residual))
}

/// Strip a leading `[filenum/files] - ` counter, if present, returning only
/// the residual. This is the legacy compatibility wrapper around
/// [`parse_file_counter`].
fn strip_filenum_prefix(s: &str) -> &str {
    match parse_file_counter(s) {
        Some((_, _, residual)) => residual,
        None => s,
    }
}

/// Reverse the XML entity escaping applied by [`escape`].
fn xml_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}
