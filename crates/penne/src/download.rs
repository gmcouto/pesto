//! Draining a [`DownloadQueue`] against configured servers.
//!
//! Fetches each queued segment's article body and decodes it with
//! `pesto::yenc::decode_part` (Phase 3), trying servers in priority order
//! per segment — so a primary provider missing, or serving a truncated copy
//! of, a handful of articles doesn't fail a file a backup server has intact.
//!
//! **Per-segment streaming assembly (`ROADMAP.md` Phase 16):** each
//! decoded segment is written to its file's temp file
//! ([`crate::assemble::StreamingAssembly`]) the instant it's decoded, not
//! once every segment for that file has arrived. Phase 14 already moved
//! assembly from "wait for the whole queue" to "wait for one file's
//! segments"; for a release that's a single large file (a multi-GB video
//! split into thousands of segments, fetched in parallel), that was no
//! improvement — every decoded segment still piled up in memory until that
//! one file's last segment landed. Now nothing is held beyond one
//! in-flight segment's bytes per worker: [`DecodedPart`] is written and
//! dropped immediately, and only a few bytes of bookkeeping (its own
//! CRC-32 and length) survive until the file's last segment triggers
//! [`crate::assemble::StreamingAssembly::finish`]. `outcome.segments` is
//! now just the *set* of Message-IDs that were fetched (not their decoded
//! bytes) — see [`DownloadOutcome::segments`]'s own doc comment.
//!
//! **Concurrency (`ROADMAP.md` Phase 2's long-standing open item, closed in
//! Phase 9):** each server is drained by up to `server.connections` workers
//! running at once — real throughput, not one segment at a time. Priority
//! *tiers* (`ROADMAP.md` Phase 15's `level`+`group` item —
//! [`crate::config::ServerTier`]) are still tried strictly in order (every
//! member of tier 1 finishes its pass before tier 2 starts), since "missing
//! from this tier" is an expected, per-segment condition for a downloader,
//! not a failure to rotate away from the way `pesto::nntp::pool` does for
//! posting — a backup tier only gets asked about the segments the primary
//! didn't have. *Within* a tier, every member server's connections are
//! drained together as one combined worker pool sharing a single queue —
//! that's what pooling two equal-priority servers actually buys over
//! giving them each their own tier.
//!
//! Two resilience mechanisms live here (`ROADMAP.md` Phase 8):
//! - **Cache-first fetch:** before any network request, [`crate::cache`] is
//!   checked for a body already fetched in a previous, interrupted run of
//!   this same download. A cache hit skips the network entirely.
//! - **Retry with backoff:** a connection or fetch error against one server
//!   is retried up to `retries` times (each server's own `retry_delay`
//!   governs the pause) before moving on to the next configured server — a
//!   transient hiccup shouldn't immediately write off a server that
//!   otherwise has the article.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use pesto::config::ServerEntry;
use pesto::yenc::decode_part;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinSet;

use crate::assemble::{AssembleOutcome, StreamingAssembly};
use crate::cache;
use crate::client::DownloadClient;
use crate::config::ServerTier;
use crate::progress::{ProgressEvent, ProgressSender};
use crate::queue::{DownloadQueue, QueuedFile};

/// A segment that no configured server had.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingSegment {
    pub file_name: String,
    pub part: u32,
    pub message_id: String,
}

/// A segment that was fetched but could not be decoded as yEnc by any server
/// that had it (a truncated or otherwise corrupted transfer). Distinct from
/// [`MissingSegment`]: the article exists somewhere, but no copy retrieved
/// was structurally valid yEnc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorruptSegment {
    pub file_name: String,
    pub part: u32,
    pub message_id: String,
    /// The last decode error seen, from whichever server's copy was tried
    /// last.
    pub error: String,
}

/// Result of draining a [`DownloadQueue`] against a set of servers.
#[derive(Debug, Default)]
pub struct DownloadOutcome {
    /// Message-IDs of every segment that was successfully fetched and
    /// decoded. Only the identifier is kept, not the decoded bytes: those
    /// are written to their file's [`StreamingAssembly`] and dropped
    /// immediately (Phase 16's per-segment streaming — see the module doc
    /// comment) rather than held in memory until the whole file completes,
    /// the way an earlier version of this map did. Check
    /// [`AssembleOutcome`] (in [`Self::assembled`]) for whether a given
    /// file's content actually verified.
    pub segments: HashSet<String>,
    /// Segments no configured server had.
    pub missing: Vec<MissingSegment>,
    /// Segments fetched but not decodable from any server that had them.
    pub corrupt: Vec<CorruptSegment>,
    /// One assembly outcome per file, keyed by `.nzb` filename — written to
    /// disk incrementally as each file's segments resolved, not in one pass
    /// after every file was fetched. Always has one entry per file in the
    /// queue by the time this is returned.
    pub assembled: HashMap<String, AssembleOutcome>,
}

/// One segment still needing to be fetched, with just enough owned data
/// (no borrows) to move across worker tasks.
#[derive(Debug, Clone)]
struct WorkItem {
    file_name: String,
    part: u32,
    message_id: String,
}

/// Per-file completion tracking shared across the cache-hit prepass and
/// every server's worker pool, so a file can be assembled the instant its
/// own last segment resolves rather than after the whole queue finishes.
struct SharedState {
    files_by_name: HashMap<String, QueuedFile>,
    remaining: Mutex<HashMap<String, u32>>,
    /// One [`StreamingAssembly`] per file, built once up front (mirroring
    /// `files_by_name`/`remaining`) and fed segments as they're decoded.
    /// The inner `AsyncMutex` is per-*file* (not one lock over the whole
    /// map) so two different files finishing around the same time from
    /// different worker tasks are never serialized against each other —
    /// only concurrent writes to the *same* file's segments (which really
    /// can happen: nothing stops two workers from popping different
    /// segments of the same file off the shared per-tier queue at the same
    /// time) need to wait their turn. `Option` so the last segment's
    /// worker can `.take()` the assembly out to call
    /// [`StreamingAssembly::finish`] on an owned value — guaranteed to
    /// happen exactly once per file by the same `remaining`-hits-zero
    /// check that already gated the old batch [`assemble::assemble`] call.
    streams: HashMap<String, AsyncMutex<Option<StreamingAssembly>>>,
    /// Message-IDs of segments successfully fetched and decoded this run —
    /// see [`DownloadOutcome::segments`].
    fetched: Mutex<HashSet<String>>,
    assembled: Mutex<HashMap<String, AssembleOutcome>>,
}

/// Everything about a download that stays constant across every server
/// pass, bundled so `drain_one_server`/`worker_loop` don't have to take it
/// as a long list of separate parameters (only `is_last_server` actually
/// varies pass to pass, so it stays a separate argument).
struct PassContext {
    dest_dir: PathBuf,
    retries: u32,
    progress: Option<ProgressSender>,
    shared: Arc<SharedState>,
}

/// Fetch and decode every segment in `queue` from `tiers`, tried in
/// priority order. Within each tier, up to every member server's own
/// `connections` workers run concurrently, pooled together — see
/// [`ServerTier`]. A decode failure on one server's copy is not fatal: the
/// next tier is tried before giving up on the segment, since the failure
/// may be specific to that one transfer.
///
/// Each file is also written to disk ([`crate::assemble::assemble`]) the
/// instant every one of its segments has reached a terminal state —
/// fetched, or definitively unfetchable after the last configured tier —
/// rather than waiting for every other file in the queue too. `retries`
/// bounds how many times a connection/fetch error against one server is
/// retried (with that server's own `retry_delay` between attempts) before
/// moving to the next tier.
pub async fn download_queue(
    queue: &DownloadQueue,
    tiers: &[ServerTier],
    dest_dir: &Path,
    retries: u32,
    progress: Option<ProgressSender>,
) -> Result<DownloadOutcome> {
    anyhow::ensure!(!tiers.is_empty(), "no servers configured");

    for file in &queue.files {
        if let Some(ref enc) = file.encryption {
            if enc != "combined" {
                anyhow::bail!("unsupported encryption wire mode `{enc}` (expected `combined`)");
            }
        }
        if file.encrypted && file.password.is_none() {
            anyhow::bail!(
                "encrypted file `{}` has no password in NZB metadata",
                file.name
            );
        }
    }

    emit(&progress, || ProgressEvent::Started {
        files: queue
            .files
            .iter()
            .map(|f| crate::progress::FileEntry {
                name: f.name.clone(),
                segments: f.segments.len() as u32,
                bytes: f.segments.iter().map(|s| s.bytes).sum(),
            })
            .collect(),
    });

    let mut outcome = DownloadOutcome::default();

    let shared = Arc::new(SharedState {
        files_by_name: queue
            .files
            .iter()
            .map(|f| (f.name.clone(), f.clone()))
            .collect(),
        remaining: Mutex::new(
            queue
                .files
                .iter()
                .map(|f| (f.name.clone(), f.segments.len() as u32))
                .collect(),
        ),
        streams: queue
            .files
            .iter()
            .map(|f| {
                (
                    f.name.clone(),
                    AsyncMutex::new(Some(StreamingAssembly::new(f, dest_dir))),
                )
            })
            .collect(),
        fetched: Mutex::new(HashSet::new()),
        assembled: Mutex::new(HashMap::new()),
    });

    // Cache hits are resolved up front, sequentially — they're pure disk
    // reads, not worth spinning up a worker pool for — so no network
    // worker ever spends a slot on a segment already resumed from a
    // previous run.
    let mut pending: Vec<WorkItem> = Vec::new();
    for file in &queue.files {
        for seg in &file.segments {
            if let Some(cached) = cache::load(dest_dir, &seg.message_id) {
                match decode_article(&cached, Some(file)) {
                    Ok(decoded) => {
                        emit(&progress, || ProgressEvent::SegmentDownloaded {
                            file_name: file.name.clone(),
                            part: seg.part,
                            bytes: decoded.data.len() as u64,
                        });
                        resolve_segment(
                            &file.name,
                            &seg.message_id,
                            seg.part,
                            Some(decoded),
                            &shared,
                            &progress,
                        )
                        .await?;
                        continue;
                    }
                    Err(DecodeError::Hard(e)) => {
                        return Err(anyhow::anyhow!(
                            "unrecoverable error in cached segment {}: {e}",
                            seg.message_id
                        ));
                    }
                    Err(DecodeError::Corrupt(_)) => {
                        // Fall through to normal network fetch
                    }
                }
            }
            pending.push(WorkItem {
                file_name: file.name.clone(),
                part: seg.part,
                message_id: seg.message_id.clone(),
            });
        }
    }

    // The most recent decode error per still-outstanding Message-ID, so the
    // final missing-vs-corrupt classification (once every server has been
    // tried) can tell the two apart.
    let mut last_decode_err: HashMap<String, String> = HashMap::new();

    let ctx = Arc::new(PassContext {
        dest_dir: dest_dir.to_path_buf(),
        retries,
        progress,
        shared,
    });

    let last_tier_idx = tiers.len() - 1;
    for (idx, tier) in tiers.iter().enumerate() {
        if pending.is_empty() {
            break;
        }
        let is_last_tier = idx == last_tier_idx;
        let (fetched, leftover) = drain_one_tier(tier, pending, is_last_tier, &ctx).await?;

        for item in fetched {
            last_decode_err.remove(&item.message_id);
        }

        pending = Vec::with_capacity(leftover.len());
        for (item, decode_err) in leftover {
            if let Some(err) = decode_err {
                last_decode_err.insert(item.message_id.clone(), err);
            }
            pending.push(item);
        }
    }

    // Every item still here failed even the last configured server, so
    // `worker_loop` (told it was draining the last server) has already
    // emitted its `SegmentMissing`/`SegmentCorrupt` progress event for each,
    // and already called `resolve_segment` for it (so every file has by now
    // been assembled) — this just builds the precise final report from the
    // full cross-server `last_decode_err` history, which is more
    // authoritative than any single pass's own view (see that map's own doc
    // comment).
    for item in pending {
        match last_decode_err.remove(&item.message_id) {
            Some(error) => {
                outcome.corrupt.push(CorruptSegment {
                    file_name: item.file_name,
                    part: item.part,
                    message_id: item.message_id,
                    error,
                });
            }
            None => {
                outcome.missing.push(MissingSegment {
                    file_name: item.file_name,
                    part: item.part,
                    message_id: item.message_id,
                });
            }
        }
    }

    let ctx = Arc::try_unwrap(ctx)
        .unwrap_or_else(|_| panic!("every worker task joined before this point"));
    let shared = Arc::try_unwrap(ctx.shared)
        .unwrap_or_else(|_| panic!("every worker task joined before this point"));
    outcome.segments = shared.fetched.into_inner().expect("mutex not poisoned");
    outcome.assembled = shared.assembled.into_inner().expect("mutex not poisoned");

    Ok(outcome)
}

/// Record one segment's resolution — `Some(decoded)` on success, `None` on
/// a terminal failure (no more servers left to try). On success, the
/// segment is written to its file's [`StreamingAssembly`] immediately (and
/// `decoded` dropped right after — its bytes are never held beyond this
/// call). If this was the file's last unresolved segment,
/// [`StreamingAssembly::finish`] is called to decide that file's
/// [`AssembleOutcome`] — reporting `Incomplete` if anything's still
/// missing, exactly as the old batch [`assemble::assemble`] would have —
/// the only thing that changed is *when* each segment's bytes reach disk.
async fn resolve_segment(
    file_name: &str,
    message_id: &str,
    part: u32,
    decoded: Option<pesto::yenc::DecodedPart>,
    shared: &SharedState,
    progress: &Option<ProgressSender>,
) -> Result<()> {
    if let Some(decoded) = decoded {
        // Written and dropped immediately — its bytes never join any
        // queue-wide collection, unlike the batch-era `shared.segments`
        // map this replaced (Phase 16's per-segment streaming). `part` (the
        // queue's own numbering, not the decoded article's own claim) is
        // what keys `StreamingAssembly`'s bookkeeping — see
        // `write_segment`'s doc comment for why that distinction matters.
        let mut guard = shared.streams[file_name].lock().await;
        guard
            .as_mut()
            .expect("stream not yet finished for this file")
            .write_segment(part, &decoded)
            .await?;
        shared
            .fetched
            .lock()
            .expect("mutex not poisoned")
            .insert(message_id.to_string());
    }

    let now_zero = {
        let mut remaining = shared.remaining.lock().expect("mutex not poisoned");
        let count = remaining
            .get_mut(file_name)
            .expect("file present in remaining map");
        *count -= 1;
        *count == 0
    };
    if !now_zero {
        return Ok(());
    }

    // Exactly one `resolve_segment` call ever observes `now_zero == true`
    // for a given file, guaranteed by the atomic decrement-and-check above
    // (the same invariant the old batch assembler relied on) — so this
    // `.take()` can never race with another call finishing the same file.
    let assembly = {
        let mut guard = shared.streams[file_name].lock().await;
        guard
            .take()
            .expect("exactly one resolve_segment call observes now_zero, per the remaining-counter invariant")
    };
    let expected_parts: Vec<u32> = shared.files_by_name[file_name]
        .segments
        .iter()
        .map(|s| s.part)
        .collect();
    let result = assembly.finish(&expected_parts, progress.as_ref()).await?;
    shared
        .assembled
        .lock()
        .expect("mutex not poisoned")
        .insert(file_name.to_string(), result);
    Ok(())
}

fn emit(progress: &Option<ProgressSender>, event: impl FnOnce() -> ProgressEvent) {
    if let Some(tx) = progress {
        let _ = tx.send(event());
    }
}

/// Drain `pending` against every member of `tier`, each contributing its
/// own `connections` concurrent workers to one shared queue — see
/// [`ServerTier`]. Returns `(fetched, leftover)`: `fetched` lists every
/// item that was fetched and decoded (its `DecodedPart` already landed in
/// `shared.segments`, and — if it completed its file — that file has
/// already been assembled); `leftover` is everything nobody in this tier
/// resolved (missing, or fetched-but-undecodable — paired with the decode
/// error when that's why), for the next tier in priority order to try.
///
/// `progress` is threaded down into each worker so a `SegmentDownloaded`
/// event fires the instant *that item* is fetched and decoded — not
/// batched up and only emitted once this whole function returns. Every
/// worker (across every member server) pulls from one shared queue and
/// only stops once it's empty, so without per-item emission every worker's
/// task finishes within the same instant at the very end of the pass
/// regardless of queue size, making the progress panel sit still for the
/// whole fetch and then jump straight to 100% (found and fixed via the
/// identical bug in `penne::check::drain_one_tier` — see that module's
/// history).
///
/// `is_last_tier` mirrors `penne::check`'s fix too: a "missing"/"corrupt"
/// verdict is normally only final once every configured tier has had a
/// turn, but for the *last* one that's true the instant each item
/// resolves, so it emits per-item there too instead of leaving every
/// leftover item to pile up for one batch after the whole multi-tier check
/// returns — the difference between a mostly-missing release updating the
/// panel throughout the download or not moving until the end.
///
/// Returns the first I/O error hit while assembling a completed file, if
/// any — a real disk failure (out of space, permission revoked) is treated
/// as fatal for the whole run rather than silently dropped, matching how
/// `assemble()`'s own errors already propagated when called from
/// `bin/penne.rs` directly. Any workers still in flight when that happens
/// are aborted when the `JoinSet` is dropped.
async fn drain_one_tier(
    tier: &ServerTier,
    pending: Vec<WorkItem>,
    is_last_tier: bool,
    ctx: &Arc<PassContext>,
) -> Result<(Vec<WorkItem>, Vec<(WorkItem, Option<String>)>)> {
    let queue = Arc::new(Mutex::new(VecDeque::from(pending)));

    let mut workers = JoinSet::new();
    for server in &tier.members {
        let worker_count = server.connections.max(1);
        for _ in 0..worker_count {
            workers.spawn(worker_loop(
                queue.clone(),
                server.clone(),
                is_last_tier,
                ctx.clone(),
            ));
        }
    }

    let mut fetched = Vec::new();
    let mut leftover = Vec::new();
    while let Some(result) = workers.join_next().await {
        // A worker task can only fail by panicking, which would be a bug in
        // `worker_loop` itself, not a runtime condition to recover from;
        // any items that worker hadn't gotten to yet are simply still
        // sitting in `queue` and will be picked up by whichever worker
        // empties it next (or, if it panicked mid-item, that one item is
        // lost from this pass — acceptably rare against "never panics").
        if let Ok(inner) = result {
            let (f, l) = inner?;
            fetched.extend(f);
            leftover.extend(l);
        }
    }
    Ok((fetched, leftover))
}

/// One worker's whole pass over `queue`: pop an item, fetch+decode it
/// against `server` (retrying per [`fetch_with_retry`]), repeat until the
/// queue is empty. Keeps one connection open for the entire pass rather
/// than reconnecting per item.
///
/// Emits `SegmentDownloaded` as soon as each item is fetched and decoded.
/// A `SegmentMissing`/`SegmentCorrupt` event fires per-item too, but only
/// when `is_last_server` — classified from *this pass's own* outcome
/// (missing if the server never had it, corrupt if it had it but decoding
/// failed), a reasonable live approximation; the authoritative
/// classification `download_queue` ultimately reports still comes from its
/// own full cross-server `last_decode_err` history, unaffected by this.
///
/// Every segment that reaches a terminal state here — a successful decode,
/// or (only when `is_last_server`) a definitive failure — is handed to
/// [`resolve_segment`], which assembles that segment's file immediately
/// once it was the last one it was waiting on. This is what makes files
/// land on disk throughout the download instead of only once every server
/// has been fully drained.
async fn worker_loop(
    queue: Arc<Mutex<VecDeque<WorkItem>>>,
    server: ServerEntry,
    is_last_server: bool,
    ctx: Arc<PassContext>,
) -> Result<(Vec<WorkItem>, Vec<(WorkItem, Option<String>)>)> {
    let mut client: Option<DownloadClient> = None;
    let mut fetched = Vec::new();
    let mut leftover = Vec::new();

    loop {
        let item = {
            let mut q = queue.lock().expect("queue mutex poisoned");
            q.pop_front()
        };
        let Some(item) = item else { break };

        let body = match fetch_with_retry(&mut client, &server, &item.message_id, ctx.retries).await
        {
            Ok(Some(body)) => body,
            Ok(None) => {
                if is_last_server {
                    emit(&ctx.progress, || ProgressEvent::SegmentMissing {
                        file_name: item.file_name.clone(),
                        part: item.part,
                    });
                    resolve_segment(
                        &item.file_name,
                        &item.message_id,
                        item.part,
                        None,
                        &ctx.shared,
                        &ctx.progress,
                    )
                    .await?;
                }
                leftover.push((item, None));
                continue;
            }
            Err(_) => {
                // Exhausted retries against this server; the next server in
                // priority order gets a turn.
                if is_last_server {
                    emit(&ctx.progress, || ProgressEvent::SegmentMissing {
                        file_name: item.file_name.clone(),
                        part: item.part,
                    });
                    resolve_segment(
                        &item.file_name,
                        &item.message_id,
                        item.part,
                        None,
                        &ctx.shared,
                        &ctx.progress,
                    )
                    .await?;
                }
                leftover.push((item, None));
                continue;
            }
        };

        let queued_file = ctx.shared.files_by_name.get(&item.file_name);
        match decode_article(&body, queued_file) {
            Ok(decoded) => {
                // Cache the raw body, not the decoded form — see the module
                // docs on `crate::cache` for why.
                let _ = cache::store(&ctx.dest_dir, &item.message_id, &body);
                emit(&ctx.progress, || ProgressEvent::SegmentDownloaded {
                    file_name: item.file_name.clone(),
                    part: item.part,
                    bytes: decoded.data.len() as u64,
                });
                resolve_segment(
                    &item.file_name,
                    &item.message_id,
                    item.part,
                    Some(decoded),
                    &ctx.shared,
                    &ctx.progress,
                )
                .await?;
                fetched.push(item);
            }
            Err(DecodeError::Corrupt(err_msg)) => {
                if is_last_server {
                    emit(&ctx.progress, || ProgressEvent::SegmentCorrupt {
                        file_name: item.file_name.clone(),
                        part: item.part,
                        error: err_msg.clone(),
                    });
                    resolve_segment(
                        &item.file_name,
                        &item.message_id,
                        item.part,
                        None,
                        &ctx.shared,
                        &ctx.progress,
                    )
                    .await?;
                }
                leftover.push((item, Some(err_msg)));
            }
            Err(DecodeError::Hard(err_msg)) => {
                return Err(anyhow::anyhow!(
                    "unrecoverable error decoding {}: {}",
                    item.message_id,
                    err_msg
                ));
            }
        }
    }

    if let Some(c) = client {
        c.quit().await;
    }

    Ok((fetched, leftover))
}

/// Fetch `message_id` from `server` over `client` (this worker's own
/// persistent connection, connected lazily on first use), retrying a
/// connection or transport error up to `retries` times (sleeping
/// `server.retry_delay` seconds between attempts), reconnecting each time
/// since an error likely means the connection is now dead.
///
/// `Ok(None)` (the server explicitly doesn't have the article, `430`) is
/// never retried — that is a definitive answer, not a transient failure.
async fn fetch_with_retry(
    client: &mut Option<DownloadClient>,
    server: &ServerEntry,
    message_id: &str,
    retries: u32,
) -> Result<Option<Vec<u8>>> {
    let mut last_err = None;

    for attempt in 0..=retries {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(server.retry_delay)).await;
        }

        if client.is_none() {
            match DownloadClient::connect(server).await {
                Ok(c) => *client = Some(c),
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            }
        }

        let c = client.as_mut().expect("just connected above");
        match c.body(message_id).await {
            Ok(result) => return Ok(result),
            Err(e) => {
                // Connection likely dead; drop it so the next attempt
                // reconnects instead of reusing it.
                *client = None;
                last_err = Some(e);
            }
        }
    }

    Err(last_err.expect("loop always runs at least once and only exits early on Ok"))
}

#[derive(Debug)]
enum DecodeError {
    Corrupt(String),
    Hard(String),
}

fn split_lines(body: &[u8]) -> Vec<&[u8]> {
    let mut lines: Vec<&[u8]> = body
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .collect();
    while lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    lines
}

fn decode_article(
    body: &[u8],
    queued_file: Option<&QueuedFile>,
) -> Result<pesto::yenc::DecodedPart, DecodeError> {
    let lines = split_lines(body);
    if lines.is_empty() {
        return Err(DecodeError::Corrupt("empty article body".into()));
    }

    let file_flagged_encrypted = queued_file.is_some_and(|f| f.encrypted);
    let line1_is_plain_ybegin = lines[0].starts_with(b"=ybegin");

    let is_encrypted = file_flagged_encrypted
        || (!line1_is_plain_ybegin
            && lines[0].len() >= pesto::yenc::encrypt::BOOTSTRAP_LEN + 2
            && pesto::yenc::encrypt::extract_bootstrap(lines[0]).is_ok());

    if !is_encrypted {
        let decoded = decode_part(body).map_err(|e| DecodeError::Corrupt(e.to_string()))?;
        if !decoded.crc_matches() {
            return Err(DecodeError::Corrupt("wire CRC mismatch".into()));
        }
        return Ok(decoded);
    }

    // C1-09: Missing/truncated =yencryption on a flagged-encrypted file = provider corruption/failover
    if file_flagged_encrypted && line1_is_plain_ybegin {
        return Err(DecodeError::Corrupt(
            "missing encryption bootstrap on flagged encrypted file".into(),
        ));
    }

    let password = queued_file
        .and_then(|f| f.password.as_deref())
        .unwrap_or("");

    // 1. Extract 20-byte Line-1 bootstrap (salt bytes 0..15, index bytes 16..19)
    let bootstrap = pesto::yenc::encrypt::extract_bootstrap(lines[0])
        .map_err(|e| DecodeError::Corrupt(format!("invalid line 1 bootstrap: {e}")))?;

    // 2. Derive master key from password and bootstrap salt
    let master_key = pesto::yenc::encrypt::session_key_from(password.as_bytes(), &bootstrap.salt);

    // 3. FF1-decrypt Line 1
    let (decrypted_line1, bootstrap) =
        match pesto::yenc::encrypt::decrypt_line1(&master_key, lines[0]) {
            Ok(res) => res,
            Err(e) => {
                return Err(DecodeError::Corrupt(format!(
                    "failed to decrypt line 1: {e}"
                )));
            }
        };
    if !decrypted_line1.starts_with(b"=ybegin ") {
        return Err(DecodeError::Corrupt(
            "decrypted line 1 does not start with =ybegin".into(),
        ));
    }

    let is_multipart = decrypted_line1
        .as_slice()
        .split(|&b| b == b' ')
        .any(|token| token.starts_with(b"part="));

    let min_lines = if is_multipart { 4 } else { 3 };
    if lines.len() < min_lines {
        return Err(DecodeError::Corrupt(
            "article too short for encrypted yEnc structure".into(),
        ));
    }

    // 4. Decrypt subsequent header lines until data lines
    let decrypted_line2: Vec<u8>;
    let yenc_header_bytes: Vec<u8>;
    let data_start: usize;

    if is_multipart {
        decrypted_line2 = pesto::yenc::encrypt::decrypt_control_line(
            &master_key,
            bootstrap.segment_index,
            2,
            lines[1],
        )
        .map_err(|e| DecodeError::Corrupt(format!("failed to decrypt line 2: {e}")))?;

        if !decrypted_line2.starts_with(b"=ypart ") {
            return Err(DecodeError::Corrupt(
                "decrypted line 2 does not start with =ypart".into(),
            ));
        }

        let decrypted_line3 = pesto::yenc::encrypt::decrypt_control_line(
            &master_key,
            bootstrap.segment_index,
            3,
            lines[2],
        )
        .map_err(|e| DecodeError::Corrupt(format!("failed to decrypt line 3: {e}")))?;

        if !decrypted_line3.starts_with(b"=yencryption") {
            return Err(DecodeError::Corrupt(
                "decrypted line 3 does not start with =yencryption".into(),
            ));
        }
        yenc_header_bytes = decrypted_line3;
        data_start = 3;
    } else {
        decrypted_line2 = pesto::yenc::encrypt::decrypt_control_line(
            &master_key,
            bootstrap.segment_index,
            2,
            lines[1],
        )
        .map_err(|e| DecodeError::Corrupt(format!("failed to decrypt line 2: {e}")))?;

        if !decrypted_line2.starts_with(b"=yencryption") {
            return Err(DecodeError::Corrupt(
                "decrypted line 2 does not start with =yencryption".into(),
            ));
        }
        yenc_header_bytes = decrypted_line2.clone();
        data_start = 2;
    }

    // 5. Validate =yencryption five-token grammar immediately
    let yenc_str = std::str::from_utf8(&yenc_header_bytes)
        .map_err(|_| DecodeError::Hard("invalid UTF-8 in =yencryption line".into()))?;

    let header = match pesto::yenc::encrypt::parse_yencryption_line(yenc_str) {
        Ok(h) => h,
        Err(e) => match e {
            pesto::yenc::encrypt::EncryptionError::UnsupportedCipher
            | pesto::yenc::encrypt::EncryptionError::InvalidTokenCount
            | pesto::yenc::encrypt::EncryptionError::InvalidWhitespace
            | pesto::yenc::encrypt::EncryptionError::InvalidTagHex
            | pesto::yenc::encrypt::EncryptionError::InvalidIndexHex
            | pesto::yenc::encrypt::EncryptionError::InvalidSaltHex
            | pesto::yenc::encrypt::EncryptionError::UppercaseHex
            | pesto::yenc::encrypt::EncryptionError::InvalidSaltLength
            | pesto::yenc::encrypt::EncryptionError::InvalidTagLength
            | pesto::yenc::encrypt::EncryptionError::InvalidIndexLength => {
                return Err(DecodeError::Hard(format!(
                    "malformed =yencryption header: {e}"
                )));
            }
            _ => {
                return Err(DecodeError::Corrupt(format!(
                    "invalid =yencryption parameters: {e}"
                )));
            }
        },
    };

    // 6. Dual-bootstrap agreement check (salt + index byte-equal)
    if bootstrap.salt != header.salt || bootstrap.segment_index != header.segment_index {
        return Err(DecodeError::Corrupt(
            "dual-bootstrap agreement mismatch: salt or segment_index in line 1 differs from =yencryption".into(),
        ));
    }

    // 7. Decrypt footer line (=yend)
    let total_lines = lines.len() as u32;
    let decrypted_footer = pesto::yenc::encrypt::decrypt_control_line(
        &master_key,
        bootstrap.segment_index,
        total_lines,
        lines[lines.len() - 1],
    )
    .map_err(|e| DecodeError::Corrupt(format!("failed to decrypt footer line: {e}")))?;

    if !decrypted_footer.starts_with(b"=yend") {
        return Err(DecodeError::Corrupt(
            "decrypted footer line does not start with =yend".into(),
        ));
    }

    // 8. Reconstruct yEnc block WITHOUT =yencryption and yEnc-decode
    let mut reconstructed = Vec::new();
    reconstructed.extend_from_slice(&decrypted_line1);
    reconstructed.extend_from_slice(b"\r\n");
    if is_multipart {
        reconstructed.extend_from_slice(&decrypted_line2);
        reconstructed.extend_from_slice(b"\r\n");
    }
    for data_line in &lines[data_start..lines.len() - 1] {
        reconstructed.extend_from_slice(data_line);
        reconstructed.extend_from_slice(b"\r\n");
    }
    reconstructed.extend_from_slice(&decrypted_footer);
    reconstructed.extend_from_slice(b"\r\n");

    let mut decoded = decode_part(&reconstructed)
        .map_err(|e| DecodeError::Corrupt(format!("yEnc decode failed: {e}")))?;

    if !decoded.crc_matches() {
        return Err(DecodeError::Corrupt(
            "wire CRC mismatch over ciphertext".into(),
        ));
    }

    // 9. AEAD authenticate + decrypt
    let plaintext = pesto::yenc::encrypt::decrypt_body(
        &master_key,
        header.segment_index,
        &decoded.data,
        &header.tag,
    )
    .map_err(|e| DecodeError::Corrupt(format!("AEAD authentication failed: {e}")))?;

    // 10. Recompute CRC over plaintext and clear wire CRC
    let mut crc = pesto::yenc::Crc32::new();
    crc.update(&plaintext);
    decoded.part_crc32 = Some(crc.finalize());
    decoded.file_crc32 = None;
    decoded.data = plaintext;

    Ok(decoded)
}
