//! NZB parsing: reconstructing posted segments from NZB 1.1 XML.

use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use quick_xml::events::Event;
use quick_xml::reader::Reader;

use crate::poster::PostedSegment;

use super::{NzbMeta, ParsedNzb, YENC_SPEC_VERSION};

/// Parse a `.nzb` document and reconstruct its [`PostedSegment`] list.
///
/// Encrypted releases (indicated by `<meta type="yenc_encrypted">true</meta>`)
/// are marked `meta.yenc_encrypted`; a declared-encrypted NZB with unsupported
/// `yenc_version`/`yenc_cipher` provenance is rejected fail-closed (Body
/// Encryption Standard v1.2 §8).
pub fn parse(content: &str) -> Result<ParsedNzb> {
    let mut reader = Reader::from_str(content);
    // Crucial: do not trim text so that leading/trailing whitespace (LF, tabs)
    // in element content like <meta type="password"> is preserved verbatim.
    reader.config_mut().trim_text(false);

    let mut poster = String::new();
    let mut groups: Vec<String> = Vec::new();
    let mut meta = NzbMeta::default();
    let mut segments: Vec<PostedSegment> = Vec::new();
    let mut explicit_yenc_encrypted = false;
    let mut explicit_yenc_version: Option<String> = None;
    let mut explicit_yenc_cipher: Option<String> = None;

    let mut current_poster = String::new();
    let mut current_date: Option<u64> = None;
    let mut current_subject_name = String::new();
    let mut current_file_name = String::new();
    let mut file_segment_start: usize = 0;
    let mut in_file = false;
    let mut in_groups = false;
    let mut in_group = false;
    let mut in_meta: Option<String> = None;
    let mut in_segment: Option<(u64, u32)> = None; // (bytes, number)

    let mut text_buf = String::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let local_name = e.local_name();
                match local_name.as_ref() {
                    b"file" => {
                        in_file = true;
                        in_groups = false;
                        current_poster.clear();
                        current_date = None;
                        current_subject_name.clear();
                        current_file_name.clear();
                        file_segment_start = segments.len();

                        for attr in e.attributes() {
                            let attr = attr.context("malformed attribute in <file>")?;
                            match attr.key.local_name().as_ref() {
                                b"poster" => {
                                    current_poster = attr
                                        .decode_and_unescape_value(reader.decoder())?
                                        .into_owned();
                                    if poster.is_empty() {
                                        poster = current_poster.clone();
                                    }
                                }
                                b"date" => {
                                    let s = attr.decode_and_unescape_value(reader.decoder())?;
                                    current_date = s.parse().ok();
                                }
                                b"subject" => {
                                    let s = attr.decode_and_unescape_value(reader.decoder())?;
                                    current_subject_name = strip_part_suffix(&s);
                                    current_file_name = current_subject_name.clone();
                                }
                                _ => {}
                            }
                        }
                    }
                    b"groups" => {
                        in_groups = true;
                    }
                    b"group" => {
                        in_group = true;
                        text_buf.clear();
                    }
                    b"segment" => {
                        let mut bytes = 0u64;
                        let mut number = 0u32;
                        for attr in e.attributes() {
                            let attr = attr.context("malformed attribute in <segment>")?;
                            match attr.key.local_name().as_ref() {
                                b"bytes" => {
                                    let s = attr.decode_and_unescape_value(reader.decoder())?;
                                    bytes = s.parse().unwrap_or(0);
                                }
                                b"number" => {
                                    let s = attr.decode_and_unescape_value(reader.decoder())?;
                                    number = s.parse().unwrap_or(0);
                                }
                                _ => {}
                            }
                        }
                        in_segment = Some((bytes, number));
                        text_buf.clear();
                    }
                    b"meta" => {
                        let mut meta_type = String::new();
                        for attr in e.attributes() {
                            let attr = attr.context("malformed attribute in <meta>")?;
                            if attr.key.local_name().as_ref() == b"type" {
                                meta_type = attr
                                    .decode_and_unescape_value(reader.decoder())?
                                    .into_owned();
                            }
                        }
                        in_meta = Some(meta_type);
                        text_buf.clear();
                    }
                    _ => {}
                }
            }
            Ok(Event::Empty(e)) => {
                let local_name = e.local_name();
                if local_name.as_ref() == b"meta" {
                    let mut meta_type = String::new();
                    for attr in e.attributes() {
                        let attr = attr.context("malformed attribute in <meta>")?;
                        if attr.key.local_name().as_ref() == b"type" {
                            meta_type = attr
                                .decode_and_unescape_value(reader.decoder())?
                                .into_owned();
                        }
                    }
                    match meta_type.as_str() {
                        "title" => meta.name = Some(String::new()),
                        "password" => meta.password = Some(String::new()),
                        "category" => meta.category = Some(String::new()),
                        _ => {}
                    }
                }
            }
            Ok(Event::Text(t)) => {
                if in_meta.is_some() || (in_groups && in_group) || (in_file && in_segment.is_some())
                {
                    let unescaped = t.unescape().context("invalid XML text content")?;
                    text_buf.push_str(&unescaped);
                }
            }
            Ok(Event::CData(c)) => {
                if in_meta.is_some() || (in_groups && in_group) || (in_file && in_segment.is_some())
                {
                    let text = std::str::from_utf8(&c).context("invalid UTF-8 in CDATA")?;
                    text_buf.push_str(text);
                }
            }
            Ok(Event::End(e)) => {
                let local_name = e.local_name();
                match local_name.as_ref() {
                    b"file" => {
                        in_file = false;
                        let total = (segments.len() - file_segment_start) as u32;
                        for seg in &mut segments[file_segment_start..] {
                            seg.total = total;
                        }
                    }
                    b"groups" => {
                        in_groups = false;
                    }
                    b"group" => {
                        in_group = false;
                        let g = text_buf.trim().to_string();
                        if !g.is_empty() && !groups.contains(&g) {
                            groups.push(g);
                        }
                        text_buf.clear();
                    }
                    b"segment" => {
                        if let Some((bytes, part)) = in_segment.take() {
                            let raw_id = text_buf.trim().to_string();
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
                                total: 0,
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
                        }
                        text_buf.clear();
                    }
                    b"meta" => {
                        if let Some(meta_type) = in_meta.take() {
                            let value = std::mem::take(&mut text_buf);
                            match meta_type.as_str() {
                                "title" => meta.name = Some(value),
                                "password" => meta.password = Some(value),
                                "category" => meta.category = Some(value),
                                "tag" => meta.tags.push(value),
                                "yenc_encrypted" if value.trim() == "true" => {
                                    explicit_yenc_encrypted = true;
                                }
                                "yenc_version" => {
                                    explicit_yenc_version = Some(value.trim().to_string());
                                }
                                "yenc_cipher" => {
                                    explicit_yenc_cipher = Some(value.trim().to_string());
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => bail!("XML parse error: {e}"),
            _ => {}
        }
        buf.clear();
    }

    // Encryption provenance: explicit `yenc_encrypted` meta (v1.2 §8).
    if explicit_yenc_encrypted {
        // Fail-closed gating (Body Encryption Standard v1.2 §8): a
        // declared-encrypted NZB with unsupported provenance metadata is a
        // STRUCTURAL failure — it would reproduce identically against every
        // server — so the parse fails here (the downloader aborts instead of
        // rotating providers, and releases no plaintext).
        if let Some(ref ver) = explicit_yenc_version {
            if ver != YENC_SPEC_VERSION {
                bail!("unsupported yenc_version in nzb: {ver}");
            }
        }
        if let Some(ref cipher) = explicit_yenc_cipher {
            if cipher != "XChaCha20-Poly1305" {
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

/// Strip a leading `[filenum/files] - ` counter, if present.
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
