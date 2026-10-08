//! Encode and POST workers: the per-connection message pump.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use crate::article::{default_subject, generate_message_id, Article};
use crate::config::{ObfuscateMode, MAX_AUTO_PIPELINE_DEPTH};
use crate::nntp::pool::ConnectionSlot;
use crate::progress::ProgressEvent;
use crate::resume::{resume_action, ResumeAction};
use crate::yenc;

use super::outcome::PostedSegment;
use super::persisted_identity;
use super::result::commit_result;
use super::shared::Shared;
use super::task::{PostTask, ReadyArticle, TaskDispatcher};
/// Per-worker token-bucket rate limiter.
struct RateLimiter {
    /// Bytes per second; 0 = unlimited.
    rate: u64,
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    fn new(rate: u64) -> Self {
        RateLimiter {
            rate,
            tokens: rate as f64,
            last: Instant::now(),
        }
    }

    /// Wait until `bytes` tokens are available, then consume them.
    async fn acquire(&mut self, bytes: usize) {
        if self.rate == 0 {
            return;
        }
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate as f64).min(self.rate as f64);
        self.last = now;

        let bytes_f = bytes as f64;
        if self.tokens >= bytes_f {
            self.tokens -= bytes_f;
        } else {
            let needed = bytes_f - self.tokens;
            let wait = Duration::from_secs_f64(needed / self.rate as f64);
            tokio::time::sleep(wait).await;
            self.tokens = 0.0;
            self.last = Instant::now();
        }
    }
}

pub(super) async fn encode_worker(
    shared: Arc<Shared>,
    mut rx: tokio::sync::mpsc::Receiver<PostTask>,
    post_tx: Arc<TaskDispatcher<ReadyArticle>>,
) {
    while let Some(task) = rx.recv().await {
        if shared.cancelled.load(Ordering::Relaxed) {
            break;
        }
        if let Some(ready) = prepare_ready(&shared, task).await {
            if post_tx.send(ready).await.is_err() {
                break;
            }
        }
    }
}

/// Resume skip / spool / yEnc. `None` means the segment is already done
/// (skipped or re-queued for STAT of a stored id).
async fn prepare_ready(shared: &Arc<Shared>, mut task: PostTask) -> Option<ReadyArticle> {
    if let Some(resume) = &shared.resume {
        let existing = resume
            .lock()
            .unwrap()
            .get(&task.meta.real_name, task.part)
            .cloned();
        match resume_action(shared.config.check, existing.as_ref()) {
            ResumeAction::Post => {}
            action @ (ResumeAction::Skip | ResumeAction::ReStatStoredId) => {
                let existing = existing.expect("skip/re-STAT arms require a record");
                let wire_subject = existing
                    .wire_identity
                    .as_ref()
                    .map(|i| i.subject_name.as_str())
                    .unwrap_or(&task.subject_name);
                let wire_yenc = existing
                    .wire_identity
                    .as_ref()
                    .map(|i| i.yenc_name.as_str())
                    .unwrap_or(&task.yenc_name);
                let from = existing
                    .wire_identity
                    .as_ref()
                    .map(|i| i.from.as_str())
                    .unwrap_or(&task.from);
                let date = existing
                    .wire_identity
                    .as_ref()
                    .map(|i| (i.date.clone(), i.unix_date))
                    .unwrap_or_else(|| task.date.clone());
                let seg = PostedSegment {
                    file_name: task.meta.real_name.clone(),
                    file_path: Arc::from(task.meta.path.as_path()),
                    subject_name: Arc::from(task.meta.client_path.as_str()),
                    wire_name: Arc::from(wire_subject),
                    wire_yenc_name: Arc::from(wire_yenc),
                    file_size: task.meta.size,
                    part: task.part,
                    total: task.total,
                    message_id: existing.message_id,
                    bytes: existing.bytes,
                    from: Arc::from(from),
                    date,
                    full_crc32: task.file_crc32.unwrap_or(0),
                    server_idx: existing.server_idx,
                    segment_index: task.segment_index,
                    file_index: task.meta.file_index,
                    total_files: shared.total_files,
                };
                shared.results.lock().unwrap().push(seg.clone());
                if action == ResumeAction::ReStatStoredId {
                    if let Some(tx) = shared.check_tx.lock().unwrap().as_ref() {
                        let _ = tx.send(seg);
                    }
                }
                let raw_bytes = task.data.len() as u64;
                shared.release_buffer(task.data);
                shared.emit(ProgressEvent::SegmentDone {
                    file: task.meta.real_name.clone(),
                    bytes: raw_bytes,
                    ok: true,
                });
                return None;
            }
        }
    }

    let spooled = shared
        .spool_dir
        .as_ref()
        .and_then(|dir| crate::spool::read(dir, &task.meta.real_name, task.part));
    let spooled = match spooled {
        Some(entry)
            if shared.config.obfuscate != ObfuscateMode::None && entry.wire_identity.is_none() =>
        {
            // PST1 did not record the logical Subject/yEnc/From values next
            // to the raw bytes. Replaying it would post one identity while
            // recording another in resume/check state. Re-encoding is cheap
            // and gives the segment one coherent identity.
            warn!(
                file = %task.meta.real_name,
                part = task.part,
                "ignoring legacy spool entry without obfuscated wire identity"
            );
            None
        }
        entry => entry,
    };

    let (message_id, headers, encoded, encode_time) = if let Some(spooled) = spooled {
        if let Some(identity) = spooled.wire_identity {
            task.subject_name = identity.subject_name;
            task.yenc_name = identity.yenc_name;
            task.from = identity.from;
            task.date = (identity.date, identity.unix_date);
        }
        let encoded = yenc::EncodedPart {
            number: task.part,
            total: task.total,
            begin: 0,
            end: 0,
            crc32: 0,
            body: spooled.body,
        };
        (spooled.message_id, spooled.headers, encoded, Duration::ZERO)
    } else {
        let t_enc = Instant::now();
        let file_crc32 = task.file_crc32;
        let mut encode_buf = shared.acquire_encode_buf();
        // ── yEnc encryption (standards v1.2, combined wire mode) ────────────
        // Body encryption happens BEFORE yEnc encoding: only ciphertext is
        // yEnc-encoded (body standard §2). Control-line FF1 encryption
        // happens AFTER the complete yEnc block exists (control standard
        // §3), below. Both run together or not at all (wire-mode decision).
        let encrypted_header: Option<String> = match (&shared.encryption, task.segment_index) {
            (Some(session), Some(segment_index)) => {
                let session = session.lock().unwrap();
                match session.encrypt_segment(segment_index, &task.data) {
                    Ok((ciphertext, tag)) => {
                        task.data = ciphertext;
                        match session.yencryption_line(segment_index, &tag) {
                            Ok(line) => Some(line),
                            Err(e) => {
                                tracing::error!(error = %e, part = task.part,
                                    "=yencryption line build failed; posting segment unencrypted is forbidden, failing task");
                                return None;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, part = task.part, "segment encryption failed");
                        return None;
                    }
                }
            }
            (Some(_), None) => {
                tracing::error!(part = task.part,
                    "encryption enabled but task has no segmentIndex — deterministic identity bug, failing task");
                return None;
            }
            _ => None,
        };
        let mut encoded = yenc::encode_part_into(
            &task.yenc_name,
            task.meta.size,
            yenc::PartSpec {
                number: task.part,
                total: task.total,
                offset: task.offset,
            },
            &task.data,
            shared.config.line_length,
            file_crc32,
            &mut encode_buf,
        );
        let encode_time = t_enc.elapsed();
        // ── Control-line FF1 encryption (control standard §4) ───────────────
        // Applied AFTER the complete yEnc block (incl. =yencryption) exists
        // and BEFORE spool persistence + NNTP POST, so spooled/retried bytes
        // are already in wire form and a resume re-POSTs identical bytes.
        // Line 1 (lineIndex=1) additionally carries the 20-byte bootstrap
        // (16B salt || 4B BE segmentIndex). Data lines are untouched; line
        // endings are preserved exactly.
        if let (Some(line), Some(segment_index)) = (&encrypted_header, task.segment_index) {
            if let Some(master) = shared.encryption.as_ref() {
                let session = master.lock().unwrap();
                let insert_at = if task.total > 1 { 2 } else { 1 };
                let mut with_header = Vec::with_capacity(encoded.body.len() + line.len() + 2);
                let mut line_no = 0usize;
                let mut search = 0usize;
                let mut inserted = false;
                while search < encoded.body.len() {
                    let nl = encoded.body[search..].iter().position(|&b| b == b'\n');
                    let end = match nl {
                        Some(p) => search + p + 1,
                        None => encoded.body.len(),
                    };
                    if line_no == insert_at && !inserted {
                        with_header.extend_from_slice(line.as_bytes());
                        with_header.extend_from_slice(b"\r\n");
                        inserted = true;
                    }
                    with_header.extend_from_slice(&encoded.body[search..end]);
                    search = end;
                    line_no += 1;
                }
                if !inserted {
                    with_header.extend_from_slice(line.as_bytes());
                    with_header.extend_from_slice(b"\r\n");
                }
                match encrypt_control_lines(&session.key, segment_index, &session.salt, with_header)
                {
                    Ok(wire_body) => encoded.body = wire_body,
                    Err(e) => {
                        tracing::error!(error = %e, part = task.part, "control-line encryption failed");
                        return None;
                    }
                }
            }
        }
        let message_id = generate_message_id(shared.config.message_id_domain.as_deref());
        let (rfc_date, _ts) = &task.date;
        if let Some(d) = &rfc_date {
            debug!(segment = %message_id, date = %d, "article date");
        }
        let article = Article {
            message_id: message_id.clone(),
            from: task.from.clone(),
            newsgroups: shared.post_group.clone(),
            subject: default_subject(
                &task.subject_name,
                task.part,
                task.total,
                (shared.total_files > 0).then_some((task.meta.file_index, shared.total_files)),
            ),
            date: rfc_date.clone(),
            no_archive: shared.config.no_archive,
        };
        let headers = article.build_headers();
        if let Some(dir) = &shared.spool_dir {
            let identity =
                persisted_identity(&task.subject_name, &task.yenc_name, &task.from, &task.date);
            if let Err(e) = crate::spool::write_with_identity(
                dir,
                &task.meta.real_name,
                task.part,
                &message_id,
                &headers,
                &encoded.body,
                &identity,
            )
            .await
            {
                warn!(error = %e, "resume: failed to write spool entry; continuing without it");
            }
        }
        (message_id, headers, encoded, encode_time)
    };
    let date = task.date.clone();
    Some(ReadyArticle {
        task,
        message_id,
        headers,
        encoded,
        encode_time,
        date,
    })
}

pub(super) async fn worker(
    shared: Arc<Shared>,
    mut rx: tokio::sync::mpsc::Receiver<ReadyArticle>,
    conn_id: usize,
    mut slot: ConnectionSlot,
) -> ConnectionSlot {
    let mut rate_limiter = RateLimiter::new(
        // Divide the global rate across all workers proportionally.
        if shared.config.upload_rate > 0 {
            let total = shared.config.total_connections().max(1);
            (shared.config.upload_rate / total as u64).max(1)
        } else {
            0
        },
    );

    // pipeline_depth == 0 means adaptive: measure RTT on the first article and
    // compute depth = ceil(post_time / encode_time), capped at MAX_AUTO_PIPELINE_DEPTH.
    let cfg_depth = shared.config.pipeline_depth;
    let is_adaptive = cfg_depth == 0;
    // Effective depth used for batch-filling; starts at 1 until warm-up is done.
    let mut effective_depth: usize = if is_adaptive || cfg_depth == 1 {
        1
    } else {
        cfg_depth
    };
    let mut warmup_done = !is_adaptive; // true from the start when not adaptive

    // Track when the connection was last used so we can send periodic keepalives
    // on idle connections (prevents servers from closing them during long PAR2
    // computations, check-phase waits, and --each transitions).
    let keepalive_interval = shared.config.keepalive_interval;
    let keepalive_enabled = keepalive_interval > 0;
    // Short wakeup period while idle: cycle through all workers quickly enough
    // that every connection gets its keepalive before the server's idle timeout.
    // 2 s × 30 workers = 60 s worst-case round-trip, well within a 2-min timeout.
    const IDLE_POLL: Duration = Duration::from_secs(2);
    // Wakeup period while paused — much shorter than `IDLE_POLL`, which is
    // tuned for keepalive fan-out across many workers, not for how quickly a
    // paused worker notices `cancelled`/resume. Cancelling must stay roughly
    // as responsive while paused as it already is everywhere else.
    const PAUSE_POLL: Duration = Duration::from_millis(100);
    let mut last_used = Instant::now();

    'worker: loop {
        if shared.cancelled.load(Ordering::Relaxed) {
            break;
        }

        if shared.paused.load(Ordering::Relaxed) {
            // Suspended at a segment-batch boundary: keep the connection
            // alive (the same MODE READER keepalive used for idle time
            // within a run) without consuming from the queue, so a producer
            // racing ahead applies natural back-pressure instead of the run
            // continuing underneath a "paused" UI that lied about it.
            while shared.paused.load(Ordering::Relaxed) && !shared.cancelled.load(Ordering::Relaxed)
            {
                if keepalive_enabled
                    && last_used.elapsed() >= Duration::from_secs(keepalive_interval)
                {
                    slot.keepalive().await;
                    last_used = Instant::now();
                }
                tokio::time::sleep(PAUSE_POLL).await;
            }
            continue;
        }

        let first = loop {
            if keepalive_enabled && last_used.elapsed() >= Duration::from_secs(keepalive_interval) {
                slot.keepalive().await;
                last_used = Instant::now();
            }
            tokio::select! {
                task = rx.recv() => match task {
                    Some(t) => {
                        last_used = Instant::now();
                        break t;
                    }
                    None => break 'worker,
                },
                _ = tokio::time::sleep(IDLE_POLL), if keepalive_enabled => {}
            }
        };
        let mut pending = vec![first];

        if effective_depth > 1 {
            while pending.len() < effective_depth {
                match rx.try_recv() {
                    Ok(t) => pending.push(t),
                    Err(_) => break,
                }
            }
        }

        for p in &pending {
            shared.emit(ProgressEvent::ConnectionBusy {
                conn: conn_id,
                file: p.task.meta.real_name.clone(),
            });
        }

        if pending.is_empty() {
            continue;
        }

        if shared.config.dry_run {
            for p in pending {
                shared.results.lock().unwrap().push(PostedSegment {
                    file_name: p.task.meta.real_name.clone(),
                    file_path: Arc::from(p.task.meta.path.as_path()),
                    // NZB uses the real filename, not wire subject (may be obfuscated).
                    subject_name: Arc::from(p.task.meta.client_path.as_str()),
                    wire_name: Arc::from(p.task.subject_name.as_str()),
                    wire_yenc_name: Arc::from(p.task.yenc_name.as_str()),
                    file_size: p.task.meta.size,
                    part: p.task.part,
                    total: p.task.total,
                    message_id: p.message_id,
                    segment_index: p.task.segment_index,
                    bytes: (p.headers.len() + p.encoded.body.len()) as u64,
                    from: Arc::from(p.task.from.as_str()),
                    date: p.date.clone(),
                    full_crc32: p.task.file_crc32.unwrap_or(0),
                    // Nothing was actually posted in dry-run mode, so there's
                    // no real server and no check queue — see the field doc.
                    server_idx: 0,
                    file_index: p.task.meta.file_index,
                    total_files: shared.total_files,
                });
                let bytes = p.task.data.len() as u64;
                shared.release_buffer(p.task.data);
                shared.emit(ProgressEvent::SegmentDone {
                    file: p.task.meta.real_name.clone(),
                    bytes,
                    ok: true,
                });
            }
            continue;
        }

        // Rate-limit on total bytes for the whole batch.
        let total_bytes: usize = pending
            .iter()
            .map(|p| p.headers.len() + p.encoded.body.len())
            .sum();
        rate_limiter.acquire(total_bytes).await;

        let max_attempts = shared.config.retries;

        if pending.len() == 1 {
            // ── Sequential path (depth 1 or only one task left) ──────────────
            let mut p = pending.remove(0);
            let mut posted = false;
            let mut last_err = String::from("unknown error");
            let mut transient_attempts = 0u64;

            for attempt in 1..=max_attempts {
                let conn = match slot.ensure_connected().await {
                    Ok(c) => c,
                    Err(e) => {
                        last_err = format!("{e:#}");
                        warn!(segment = %p.message_id, attempt, max_attempts,
                              error = %last_err, "connection failed; will retry");
                        shared.total_retries.fetch_add(1, Ordering::Relaxed);
                        transient_attempts += 1;
                        if attempt < max_attempts {
                            shared.emit(ProgressEvent::ConnectionRetrying { conn: conn_id });
                            tokio::time::sleep(slot.retry_delay()).await;
                        }
                        continue;
                    }
                };
                let t_post = Instant::now();
                match conn.post_parts(&p.headers, &p.encoded.body).await {
                    Ok(returned_id) => {
                        // Some servers substitute their own Message-ID at
                        // accept time and echo it back in the 240 response
                        // instead of the one we sent — nyuu has handled this
                        // since 2016. Tracking our own ID after that would
                        // mean STAT (and the .nzb) reference an ID the
                        // server never actually stored anything under.
                        if let Some(server_id) = returned_id {
                            if server_id != p.message_id {
                                warn!(
                                    sent = %p.message_id,
                                    returned = %server_id,
                                    "server returned a different Message-ID than sent; adopting it"
                                );
                                p.message_id = server_id;
                            }
                        }
                        // Adaptive warm-up: compute pipeline depth from the
                        // ratio of post time (send + RTT) to encode time.
                        if is_adaptive && !warmup_done {
                            let post_us = t_post.elapsed().as_micros().max(1);
                            let enc_us = p.encode_time.as_micros().max(1);
                            let ratio = post_us.saturating_div(enc_us);
                            let depth = (ratio as usize).clamp(1, MAX_AUTO_PIPELINE_DEPTH);
                            effective_depth = depth;
                            warmup_done = true;
                            info!(
                                conn = conn_id,
                                depth,
                                post_ms = t_post.elapsed().as_millis(),
                                encode_us = enc_us,
                                "adaptive pipeline depth computed"
                            );
                        }
                        debug!(segment = %p.message_id, "posted");
                        posted = true;
                        break;
                    }
                    Err(e) => {
                        last_err = format!("{e:#}");
                        warn!(segment = %p.message_id, attempt, max_attempts,
                              error = %last_err, "post failed; rotating server");
                        shared.total_retries.fetch_add(1, Ordering::Relaxed);
                        transient_attempts += 1;
                        if attempt < max_attempts {
                            shared.emit(ProgressEvent::ConnectionRetrying { conn: conn_id });
                        }
                        slot.invalidate("post_err");
                    }
                }
                if attempt < max_attempts {
                    tokio::time::sleep(slot.retry_delay()).await;
                }
            }

            if posted && transient_attempts > 0 {
                shared.emit(ProgressEvent::PostRetryRecovered {
                    count: 1,
                    previously_failed: false,
                });
                shared.emit(ProgressEvent::ConnectionBusy {
                    conn: conn_id,
                    file: p.task.meta.real_name.clone(),
                });
            }
            let wire = p.headers.len() + p.encoded.body.len();
            commit_result(
                &shared,
                p.task,
                p.message_id,
                wire,
                posted,
                &last_err,
                p.date,
                slot.server_idx(),
            );
            shared.release_encode_buf(p.encoded.body);
        } else {
            // ── Pipelined path ───────────────────────────────────────────────
            // Send all articles back-to-back, flush once, then read all
            // responses. On any connection error the entire batch is retried.
            //
            // All conn usage is confined to the labeled block `'use_conn` so
            // that `slot.invalidate()` can be called after the block ends,
            // satisfying the borrow checker (conn borrows slot mutably).
            let n = pending.len();
            let mut pipeline_ok = false;
            let mut pipeline_retried = false;
            let mut pipe_results: Vec<Result<(), String>> = (0..n).map(|_| Ok(())).collect();

            'pipeline: for attempt in 1..=max_attempts {
                // `(needs_invalidate, error_message)` — conn is dropped when
                // the labeled block expression completes.
                let (needs_invalidate, pipe_err) = 'use_conn: {
                    let conn = match slot.ensure_connected().await {
                        Ok(c) => c,
                        Err(e) => {
                            warn!(attempt, max_attempts, error = %e,
                                  "connection failed during pipeline; will retry");
                            shared.total_retries.fetch_add(1, Ordering::Relaxed);
                            pipeline_retried = true;
                            if attempt < max_attempts {
                                shared.emit(ProgressEvent::ConnectionRetrying { conn: conn_id });
                                tokio::time::sleep(slot.retry_delay()).await;
                            }
                            continue 'pipeline;
                        }
                    };

                    // Enqueue all articles without flushing.
                    for p in &pending {
                        if let Err(e) = conn.enqueue_post(&p.headers, &p.encoded.body).await {
                            break 'use_conn (true, format!("{e:#}"));
                        }
                    }

                    // One flush covers all enqueued articles.
                    if let Err(e) = conn.flush_pipeline().await {
                        break 'use_conn (true, format!("{e:#}"));
                    }

                    // Read one (340, 240) pair per article. On error: record the
                    // failure index, break out of the for loop (dropping the
                    // iter_mut borrow), then mark remaining entries as failed.
                    let mut fail_at: Option<(usize, String)> = None;
                    for (i, result) in pipe_results.iter_mut().enumerate() {
                        match conn.read_post_response().await {
                            Ok(returned_id) => {
                                // See the sequential path above for why: some
                                // servers substitute their own Message-ID at
                                // accept time.
                                if let Some(server_id) = returned_id {
                                    if server_id != pending[i].message_id {
                                        warn!(
                                            sent = %pending[i].message_id,
                                            returned = %server_id,
                                            "server returned a different Message-ID than sent; adopting it"
                                        );
                                        pending[i].message_id = server_id;
                                    }
                                }
                                debug!(segment = %pending[i].message_id, "posted (pipelined)");
                                *result = Ok(());
                            }
                            Err(e) => {
                                *result = Err(format!("{e:#}"));
                                fail_at = Some((i + 1, format!("{e:#}")));
                                break;
                            }
                        }
                    }
                    // iter_mut borrow is dropped here; safe to index pipe_results.
                    if let Some((from, msg)) = fail_at {
                        for r in pipe_results[from..].iter_mut() {
                            // Remaining articles in the batch never received a
                            // response — the connection was lost after the first
                            // rejection. Use a distinct message so the log does
                            // not falsely repeat the first article's message-id.
                            *r = Err("pipeline interrupted after previous failure".into());
                        }
                        break 'use_conn (true, msg);
                    }

                    (false, String::new())
                }; // conn dropped; slot methods are safe to call again.

                if needs_invalidate {
                    warn!(attempt, max_attempts, error = %pipe_err,
                          "pipeline failed; rotating server");
                    shared.total_retries.fetch_add(1, Ordering::Relaxed);
                    pipeline_retried = true;
                    if attempt < max_attempts {
                        shared.emit(ProgressEvent::ConnectionRetrying { conn: conn_id });
                    }
                    slot.invalidate("post_err");
                    if attempt < max_attempts {
                        tokio::time::sleep(slot.retry_delay()).await;
                    }
                    continue;
                }

                pipeline_ok = true;
                break;
            }

            if pipeline_ok && pipeline_retried {
                shared.emit(ProgressEvent::PostRetryRecovered {
                    count: n as u64,
                    previously_failed: false,
                });
                if let Some(article) = pending.first() {
                    shared.emit(ProgressEvent::ConnectionBusy {
                        conn: conn_id,
                        file: article.task.meta.real_name.clone(),
                    });
                }
            }

            // The whole batch shares one connection/flush, so every article in
            // it — success or failure — was attempted against the same server.
            let batch_server_idx = slot.server_idx();
            for (p, result) in pending.into_iter().zip(pipe_results) {
                let posted = pipeline_ok && result.is_ok();
                let last_err = result.err().unwrap_or_else(|| "pipeline failed".into());
                let wire = p.headers.len() + p.encoded.body.len();
                commit_result(
                    &shared,
                    p.task,
                    p.message_id,
                    wire,
                    posted,
                    &last_err,
                    p.date,
                    batch_server_idx,
                );
                shared.release_encode_buf(p.encoded.body);
            }
        }
    }

    shared.emit(ProgressEvent::ConnectionIdle { conn: conn_id });
    slot
}

/// Encrypt every control line of a complete yEnc block in place, per the
/// control-lines standard v1.2 §4: lineIndex counts every physical line
/// (control and data) 1-based from the start of the block; only control
/// lines (starting `=y`) are FF1-encrypted; data lines and line endings are
/// preserved byte-for-byte. Line 1 additionally gets the 20-byte bootstrap
/// (16B raw Alphabet salt || 4B uint32_be(segmentIndex)) prepended after
/// encryption (§4 step f).
///
/// The `=yencryption` header line inserted before this call is itself a
/// control line and is FF1-encrypted with its own lineIndex, exactly as an
/// ordinary `=ybegin`/`=ypart`/`=yend` line.
pub(super) fn encrypt_control_lines(
    key: &yenc::encrypt::SessionKey,
    segment_index: u32,
    salt: &[u8; yenc::encrypt::SALT_LEN],
    body: Vec<u8>,
) -> Result<Vec<u8>, yenc::encrypt::EncryptionError> {
    use yenc::encrypt::{control_enc_key, control_tweak, encrypt_line1, ff1_encrypt_line};

    // Split preserving terminators (CRLF or LF — both accepted on the wire).
    let mut out: Vec<u8> = Vec::with_capacity(body.len() + 20);
    let mut line_index: u32 = 1;
    let mut search: usize = 0;
    while search < body.len() {
        let line_start = search;
        let term_len = {
            let nl = body[search..].iter().position(|&b| b == b'\n');
            match nl {
                Some(p) => {
                    let mut e = p + 1; // include \n
                    if e >= 2 && body[line_start + p - 1] == b'\r' {
                        e += 0; // \r already inside range; terminators stay as-is
                    }
                    e
                }
                None => body.len() - search,
            }
        };
        let content_end = line_start + term_len;
        let content = &body[line_start..content_end];
        // Trim trailing CR/LF for content inspection.
        let trimmed: &[u8] = {
            let mut t = content;
            if t.last() == Some(&b'\n') {
                t = &t[..t.len() - 1];
            }
            if t.last() == Some(&b'\r') {
                t = &t[..t.len() - 1];
            }
            t
        };
        let terminators = &content[trimmed.len()..];
        let encrypted_content = if line_index == 1 {
            encrypt_line1(key, segment_index, salt, trimmed)?
        } else if trimmed.starts_with(b"=y") {
            let enc_key = control_enc_key(key);
            let tweak = control_tweak(key, segment_index, line_index);
            ff1_encrypt_line(&enc_key, &tweak, trimmed)?
        } else {
            trimmed.to_vec()
        };
        out.extend_from_slice(&encrypted_content);
        out.extend_from_slice(terminators);
        search = content_end;
        line_index += 1;
    }
    Ok(out)
}

/// Repost-path counterpart of `prepare_ready`'s encrypt hook: insert the
/// `=yencryption` header into an already-yEnc-encoded block (physical line 2
/// for single-part, after `=ypart` for multi-part — control standard §3
/// placement rules), then FF1-encrypt the control lines including it.
pub(super) fn encrypt_article_for_repost(
    key: &yenc::encrypt::SessionKey,
    segment_index: u32,
    salt: &[u8; yenc::encrypt::SALT_LEN],
    tag: [u8; 16],
    total_parts: u32,
    body: Vec<u8>,
) -> Result<Vec<u8>, yenc::encrypt::EncryptionError> {
    let header_line = yenc::encrypt::build_yencryption_line(salt, segment_index, &tag)?;
    // yEnc bodies are binary-safe: split on bytes, never via UTF-8 lossy
    // conversion, which would corrupt any high (>0x7F) encoded byte.
    let insert_at = if total_parts > 1 { 2 } else { 1 };
    let mut out: Vec<u8> = Vec::with_capacity(body.len() + header_line.len() + 2);
    let mut line_no: usize = 0;
    let mut search = 0usize;
    let mut inserted = false;
    while search < body.len() {
        let nl = body[search..].iter().position(|&b| b == b'\n');
        let end = match nl {
            Some(p) => search + p + 1,
            None => body.len(),
        };
        if line_no == insert_at && !inserted {
            out.extend_from_slice(header_line.as_bytes());
            out.extend_from_slice(b"\r\n");
            inserted = true;
        }
        out.extend_from_slice(&body[search..end]);
        search = end;
        line_no += 1;
    }
    if !inserted {
        out.extend_from_slice(header_line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    encrypt_control_lines(key, segment_index, salt, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rate_limiter_zero_rate_never_sleeps() {
        let mut rl = RateLimiter::new(0);
        let start = Instant::now();
        rl.acquire(1_000_000).await;
        // Should return almost instantly (< 10 ms).
        assert!(start.elapsed() < Duration::from_millis(10));
    }

    #[tokio::test]
    async fn rate_limiter_large_bucket_does_not_sleep_for_small_request() {
        // 10 MiB/s bucket, request 1 KiB — tokens are available immediately.
        let mut rl = RateLimiter::new(10 * 1024 * 1024);
        let start = Instant::now();
        rl.acquire(1024).await;
        assert!(start.elapsed() < Duration::from_millis(10));
    }
}
