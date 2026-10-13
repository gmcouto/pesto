//! NZB parsing: reconstructing posted segments from NZB 1.1 XML.

use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Result};

use crate::poster::PostedSegment;

use super::{NzbMeta, ParsedNzb, YENC_SPEC_VERSION};

/// Parse a `.nzb` document and reconstruct its [`PostedSegment`] list.
///
/// The parser targets the format produced by [`crate::nzb::generate`] but
/// tolerates minor whitespace variation. Attributes must use double quotes.
/// Segments are sorted by `(file_name, part)` before returning so they can be
/// passed directly to [`crate::nzb::generate`].
pub fn parse(content: &str) -> Result<ParsedNzb> {
    let mut poster = String::new();
    let mut groups: Vec<String> = Vec::new();
    let mut meta = NzbMeta::default();
    let mut segments: Vec<PostedSegment> = Vec::new();
    let mut explicit_yenc_encrypted = false;
    let mut explicit_yenc_versions: Vec<String> = Vec::new();
    let mut explicit_yenc_ciphers: Vec<String> = Vec::new();

    let mut current_file_name = String::new();
    let mut current_subject_name = String::new();
    let mut file_segment_start: usize = 0;
    let mut in_groups = false;
    let mut in_file = false;

    let mut current_poster = String::new();
    let mut current_date: Option<u64> = None;

    let lines = split_lines_preserving_endings(content);
    let mut idx = 0;
    while idx < lines.len() {
        let (line, ending) = lines[idx];
        let t = line.trim();

        if t.starts_with("<file ") {
            in_file = true;
            in_groups = false;
            current_poster = xml_attr(t, "poster").unwrap_or_default();
            if poster.is_empty() {
                poster = current_poster.clone();
            }
            current_date = xml_attr(t, "date").and_then(|s| s.parse().ok());
            let subject = xml_attr(t, "subject").unwrap_or_default();
            current_subject_name = strip_part_suffix(&subject);
            current_file_name = current_subject_name.clone();
            file_segment_start = segments.len();
        } else if t == "</file>" {
            let total = (segments.len() - file_segment_start) as u32;
            for seg in &mut segments[file_segment_start..] {
                seg.total = total;
            }
            in_file = false;
        } else if t == "<groups>" {
            in_groups = true;
        } else if t == "</groups>" {
            in_groups = false;
        } else if in_groups {
            if let Some(g) = xml_text(t, "group") {
                if !groups.contains(&g) {
                    groups.push(g);
                }
            }
        } else if in_file && t.starts_with("<segment ") {
            let bytes: u64 = xml_attr(t, "bytes")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let part: u32 = xml_attr(t, "number")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let raw_id = xml_text(t, "segment").unwrap_or_default();
            let message_id = if raw_id.starts_with('<') {
                raw_id
            } else {
                format!("<{raw_id}>")
            };
            segments.push(PostedSegment {
                file_name: current_file_name.clone(),
                file_path: Arc::from(Path::new(&current_file_name)),
                subject_name: Arc::from(current_subject_name.as_str()),
                wire_name: Arc::from(""),
                wire_yenc_name: Arc::from(""),
                file_size: 0,
                part,
                total: 0, // fixed up when </file> is seen
                message_id,
                bytes,
                from: Arc::from(current_poster.as_str()),
                date: (None, current_date),
                full_crc32: 0,
                server_idx: 0,
                file_index: 0,
                total_files: 0,
                segment_index: 0,
            });
        } else if t.starts_with("<meta ") {
            let kind = xml_attr(t, "type").unwrap_or_default();
            if t.ends_with("/>") {
                match kind.as_str() {
                    "title" => meta.name = Some(String::new()),
                    "password" => meta.password = Some(String::new()),
                    "category" => meta.category = Some(String::new()),
                    "yenc_version" => explicit_yenc_versions.push(String::new()),
                    "yenc_cipher" => explicit_yenc_ciphers.push(String::new()),
                    _ => {}
                }
            } else if let Some(value) = xml_text(t, "meta") {
                match kind.as_str() {
                    "title" => meta.name = Some(value),
                    "password" => meta.password = Some(value),
                    "category" => meta.category = Some(value),
                    "tag" => meta.tags.push(value),
                    "yenc_encrypted" if value.trim().eq_ignore_ascii_case("true") => {
                        explicit_yenc_encrypted = true;
                    }
                    "yenc_version" => {
                        explicit_yenc_versions.push(value.trim().to_string());
                    }
                    "yenc_cipher" => {
                        explicit_yenc_ciphers.push(value.trim().to_string());
                    }
                    _ => {}
                }
            } else if kind == "password" {
                if let Some(open_tag_end) = line.find('>') {
                    let mut full_val = String::from(&line[open_tag_end + 1..]);
                    full_val.push_str(ending);
                    let mut closed = false;
                    while idx + 1 < lines.len() {
                        idx += 1;
                        let (next_line, next_ending) = lines[idx];
                        if let Some(close_pos) = next_line.find("</meta>") {
                            full_val.push_str(&next_line[..close_pos]);
                            closed = true;
                            break;
                        } else {
                            full_val.push_str(next_line);
                            full_val.push_str(next_ending);
                        }
                    }
                    if closed {
                        meta.password = Some(xml_unescape(&full_val));
                    }
                }
            }
        }
        idx += 1;
    }

    if explicit_yenc_encrypted {
        for ver in &explicit_yenc_versions {
            if ver != YENC_SPEC_VERSION {
                bail!("unsupported yenc_version in nzb: {ver}");
            }
        }
        for cipher in &explicit_yenc_ciphers {
            if !cipher.eq_ignore_ascii_case("XChaCha20-Poly1305") {
                bail!("unsupported yenc_cipher in nzb: {cipher}");
            }
        }
        meta.yenc_encrypted = true;
    }

    segments.sort_by(|a, b| a.file_name.cmp(&b.file_name).then(a.part.cmp(&b.part)));

    Ok(ParsedNzb {
        poster,
        groups,
        segments,
        meta,
    })
}

fn split_lines_preserving_endings(content: &str) -> Vec<(&str, &str)> {
    let mut lines = Vec::new();
    let mut rest = content;
    while !rest.is_empty() {
        if let Some(pos) = rest.find('\n') {
            let (line_with_lf, remaining) = rest.split_at(pos + 1);
            let (line, ending) = if let Some(stripped) = line_with_lf[..pos].strip_suffix('\r') {
                (stripped, "\r\n")
            } else {
                (&line_with_lf[..pos], "\n")
            };
            lines.push((line, ending));
            rest = remaining;
        } else {
            lines.push((rest, ""));
            break;
        }
    }
    lines
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
    Some(xml_unescape(&line[open_end + 1..close_start]))
}

/// Strip the `"name" yEnc (N/M)` or `"name" yEnc` wrapper from a subject line.
pub(super) fn strip_part_suffix(subject: &str) -> String {
    let unquote = |s: &str| {
        if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
            s[1..s.len() - 1].to_string()
        } else {
            s.to_string()
        }
    };

    if let Some(pos) = subject.rfind(" yEnc") {
        let tail = &subject[pos + 5..];
        if tail.is_empty() || tail.starts_with(" (") {
            return unquote(strip_filenum_prefix(&subject[..pos]));
        }
    }

    if let Some(pos) = subject.rfind(" (") {
        let tail = &subject[pos..];
        if tail.contains('/') && tail.ends_with(')') {
            return subject[..pos].to_string();
        }
    }
    subject.to_string()
}

fn strip_filenum_prefix(s: &str) -> &str {
    (|| {
        let rest = s.strip_prefix('[')?;
        let (counter, after) = rest.split_once(']')?;
        let is_counter = !counter.is_empty()
            && counter
                .split('/')
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
        is_counter
            .then_some(())
            .and_then(|()| after.strip_prefix(" - "))
    })()
    .unwrap_or(s)
}

/// Reverse the XML entity escaping applied by [`escape`].
fn xml_unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}
