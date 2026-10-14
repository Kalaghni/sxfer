//! Agent messaging: sxfer as the channel between AI agents (or scripts) on machines that have
//! pinned each other. `sxfer serve` is the always-on receiver; `sxfer msg` sends and replies.
//!
//! MESSAGE  an A2A (Agent2Agent protocol) Message object, as JSON:
//!            {"kind":"message","messageId","role":"agent","contextId","parts":[...],
//!             "metadata":{"sxfer":{"intent","subject","hop","inReplyTo","replyPort",...}}}
//!          Parts are A2A text, data and file parts (file bytes inline, base64). sxfer routes a
//!          message and enforces its limits; what it means is up to the agents.
//! WIRE     kind "msg" of the LAN protocol (lan.rs), between pinned peers only and never with a
//!          code: the same ML-KEM-768 + SPAKE2 channel and ML-DSA-65 handshake as files. The
//!          sender names the peer it means; anyone else answering at that address is refused
//!          before a byte of the message is sent.
//! INBOX    <inbox>/<sender fingerprint, 16 hex>-<messageId>.json, written by the RECEIVER, so
//!          its `from` is what the handshake proved, never what the message claims. It's read
//!          back from disk before the signed receipt goes out. Handled messages move to
//!          <inbox>/done/. A messageId seen before from the same sender is acknowledged again but
//!          never stored or acted on twice, so retries are safe.
//! POLICY   pinned senders only, a hop limit (agents can't bounce replies forever), a per-sender
//!          rate limit and a size cap, all decided by the receiver.
//! OUTBOX   ~/.sxfer/outbox/<messageId>.json: what couldn't be delivered yet. `sxfer serve`
//!          retries it with backoff (30 s, doubling to 30 min) for a week; `sxfer msg flush` now.
//! HOOK     `sxfer serve --on-receive CMD` runs CMD for each new message with SXFER_* variables;
//!          exit 0 moves the message to done/.

use crate::abort;
use crate::common::*;
use crate::config;
use crate::identity::{self as id, Identity, SignedReceipt};
use crate::lan::{self, PeerInfo};
use base64::Engine;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Largest message, attachments included (base64 makes files a third bigger).
pub const MAX_MSG: u64 = 16 << 20;
/// Default hop limit: a reply to a reply to ... gives up after this many.
pub const MAX_HOPS: u32 = 8;
/// Default messages per sender per minute.
pub const RATE_PER_MIN: u32 = 30;
const RETRY_FIRST: u64 = 30;
const RETRY_MAX: u64 = 30 * 60;
const OUTBOX_TTL: u64 = 7 * 24 * 3600;
const DISCOVER_WAIT: Duration = Duration::from_millis(1500);
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn now_secs() -> u64 {
    now_iso().parse().unwrap_or(0)
}

pub fn new_id() -> String {
    random_hex(16)
}

/// messageIds become file names: 1-64 of letters, digits, '.', '_', '-', not starting with '.'.
pub fn check_id(id: &str) -> R<()> {
    let ok = !id.is_empty()
        && id.len() <= 64
        && !id.starts_with('.')
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !ok {
        abort!("bad message id {id:?}: 1-64 letters, digits, '.', '_' or '-'");
    }
    Ok(())
}

// ---------------------------------------------------------------- messages

/// What an agent wants to say; `build` turns it into an A2A message.
#[derive(Default, Clone)]
pub struct Draft {
    /// markdown, usually
    pub body: String,
    pub subject: Option<String>,
    /// handoff | request | result | note, or whatever the agents agree on (default note)
    pub intent: Option<String>,
    /// the A2A contextId; a new thread if None
    pub thread: Option<String>,
    pub in_reply_to: Option<String>,
    pub hop: u32,
    pub attach: Vec<PathBuf>,
    /// structured data for the receiving agent (an A2A data part)
    pub data: Option<Value>,
}

fn mime(name: &str) -> &'static str {
    let ext = name.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "md" | "markdown" => "text/markdown",
        "txt" | "log" => "text/plain",
        "json" => "application/json",
        "csv" => "text/csv",
        "html" | "htm" => "text/html",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
}

/// An A2A message from a draft, sent as `me`.
pub fn build(d: &Draft, me: &str) -> R<Value> {
    let mut parts = Vec::new();
    let body = d.body.trim_start_matches('\u{feff}');
    if !body.is_empty() {
        parts.push(json!({ "kind": "text", "text": body }));
    }
    if let Some(v) = &d.data {
        parts.push(json!({ "kind": "data", "data": v }));
    }
    for p in &d.attach {
        let bytes = fs::read(p).map_err(|e| Abort(format!("{}: {e}", p.display())))?;
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "attachment".into());
        parts.push(json!({
            "kind": "file",
            "file": { "name": name, "mimeType": mime(&name), "bytes": B64.encode(&bytes) }
        }));
    }
    if parts.is_empty() {
        abort!("nothing to send: give a message body, data or an attachment");
    }
    let mut sx = json!({
        "v": 1,
        "hop": d.hop,
        "from": me,
        "created": now_iso(),
        "intent": d.intent.as_deref().unwrap_or("note"),
    });
    if let Some(s) = &d.subject {
        sx["subject"] = json!(s);
    }
    if let Some(r) = &d.in_reply_to {
        sx["inReplyTo"] = json!(r);
    }
    if let Some(p) = serve_port() {
        sx["replyPort"] = json!(p);
    }
    let msg = json!({
        "kind": "message",
        "messageId": new_id(),
        "role": "agent",
        "contextId": d.thread.clone().unwrap_or_else(new_id),
        "parts": parts,
        "metadata": { "sxfer": sx }
    });
    if serde_json::to_vec(&msg).map_or(0, |b| b.len()) as u64 > MAX_MSG {
        abort!(
            "message too large (max {} MiB); send big files with `sxfer send` instead",
            MAX_MSG >> 20
        );
    }
    Ok(msg)
}

/// An A2A message written by something else: filled in where sxfer needs it, then checked.
pub fn adopt(mut v: Value) -> R<Value> {
    if !v.is_object() {
        abort!("an A2A message is a JSON object");
    }
    for (k, default) in [("kind", json!("message")), ("role", json!("agent"))] {
        if v.get(k).is_none() {
            v[k] = default;
        }
    }
    if v["messageId"].as_str().is_none() {
        v["messageId"] = json!(new_id());
    }
    if !v["metadata"].is_object() {
        v["metadata"] = json!({});
    }
    if !v["metadata"]["sxfer"].is_object() {
        v["metadata"]["sxfer"] = json!({ "v": 1, "hop": 0 });
    }
    if v["metadata"]["sxfer"].get("replyPort").is_none() {
        if let Some(p) = serve_port() {
            v["metadata"]["sxfer"]["replyPort"] = json!(p);
        }
    }
    check(&v, u32::MAX)?;
    Ok(v)
}

/// The routing fields sxfer reads from a message.
#[derive(Debug, Clone, PartialEq)]
pub struct Meta {
    pub id: String,
    pub thread: Option<String>,
    pub intent: String,
    pub subject: Option<String>,
    pub hop: u32,
    pub in_reply_to: Option<String>,
    pub reply_port: Option<u16>,
}

fn clip(v: &Value) -> String {
    let s = v.to_string();
    match s.char_indices().nth(80) {
        Some((i, _)) => format!("{}...", &s[..i]),
        None => s,
    }
}

/// Is this an A2A message sxfer can carry, within `max_hops`?
pub fn check(v: &Value, max_hops: u32) -> R<Meta> {
    if v["kind"] != "message" {
        abort!("not an A2A message (its kind must be \"message\")");
    }
    let Some(id) = v["messageId"].as_str() else {
        abort!("the message has no messageId")
    };
    check_id(id)?;
    let Some(parts) = v["parts"].as_array().filter(|p| !p.is_empty()) else {
        abort!("the message has no parts")
    };
    for p in parts {
        match p["kind"].as_str() {
            Some("text") if p["text"].is_string() => {}
            Some("data") if p.get("data").is_some() => {}
            Some("file") if p["file"].is_object() => {}
            _ => abort!("unsupported message part: {}", clip(p)),
        }
    }
    let sx = &v["metadata"]["sxfer"];
    let hop = sx["hop"].as_u64().unwrap_or(0);
    if hop > u64::from(max_hops) {
        abort!(
            "hop limit reached ({hop} > {max_hops}): this thread has been passed on too many times"
        );
    }
    let s = |k: &str| sx[k].as_str().map(str::to_string);
    Ok(Meta {
        id: id.into(),
        thread: v["contextId"].as_str().map(str::to_string),
        intent: s("intent").unwrap_or_else(|| "note".into()),
        subject: s("subject"),
        hop: hop as u32,
        in_reply_to: s("inReplyTo"),
        reply_port: sx["replyPort"].as_u64().and_then(|p| u16::try_from(p).ok()),
    })
}

// ---------------------------------------------------------------- inbox

/// A machine's mailbox, and the receiver's limits on what goes in it.
pub struct Inbox {
    pub dir: PathBuf,
    pub max_hops: u32,
    /// messages per sender per minute
    pub rate: u32,
    /// one store at a time: a message arriving twice at once is stored once
    write: Mutex<()>,
    recent: Mutex<HashMap<String, VecDeque<Instant>>>,
}

/// A stored message, with what the receiver verified about it.
#[derive(Debug, Clone)]
pub struct Entry {
    pub path: PathBuf,
    pub v: Value,
    pub done: bool,
}

impl Entry {
    fn load(path: &Path, done: bool) -> R<Entry> {
        let b = fs::read(path).map_err(|e| Abort(format!("{}: {e}", path.display())))?;
        let v: Value = serde_json::from_slice(&b)
            .map_err(|e| Abort(format!("{} is not an inbox entry: {e}", path.display())))?;
        Ok(Entry {
            path: path.to_path_buf(),
            v,
            done,
        })
    }

    pub fn id(&self) -> &str {
        self.v["id"].as_str().unwrap_or("")
    }

    fn received(&self) -> u64 {
        self.v["received"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }

    /// The routing fields, without the message body.
    pub fn summary(&self) -> Value {
        let v = &self.v;
        json!({
            "id": self.id(),
            "from": v["from"]["name"],
            "from_fingerprint": v["from"]["fingerprint"],
            "intent": v["intent"],
            "subject": v["subject"],
            "thread": v["thread"],
            "in_reply_to": v["in_reply_to"],
            "hop": v["hop"],
            "received": v["received"],
            "done": self.done,
            "path": self.path.display().to_string()
        })
    }
}

impl Inbox {
    pub fn default_dir() -> PathBuf {
        sxfer_dir().join("inbox")
    }

    /// Open (creating) an inbox with the default limits.
    pub fn open(dir: &Path) -> R<Inbox> {
        for d in [dir.to_path_buf(), dir.join("done"), dir.join("logs")] {
            private_dir(&d)?;
        }
        Ok(Inbox {
            dir: dir.to_path_buf(),
            max_hops: MAX_HOPS,
            rate: RATE_PER_MIN,
            write: Mutex::new(()),
            recent: Mutex::new(HashMap::new()),
        })
    }

    fn file_name(fp: &str, id: &str) -> String {
        format!("{}-{id}.json", fp.get(..16).unwrap_or(fp))
    }

    /// Where an earlier delivery of this message from this sender is, if there was one.
    pub fn find_delivered(&self, fp: &str, id: &str) -> Option<PathBuf> {
        let name = Self::file_name(fp, id);
        [self.dir.join(&name), self.dir.join("done").join(&name)]
            .into_iter()
            .find(|p| p.exists())
    }

    /// The rate limit: at most `rate` messages from one sender in any minute.
    pub fn admit(&self, fp: &str) -> R<()> {
        let mut recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
        let q = recent.entry(fp.to_string()).or_default();
        let now = Instant::now();
        while q
            .front()
            .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(60))
        {
            q.pop_front();
        }
        if q.len() >= self.rate as usize {
            abort!(
                "rate limit: over {} messages a minute from this sender; retry later",
                self.rate
            );
        }
        q.push_back(now);
        Ok(())
    }

    /// Check and store a received message: Ok((entry, already there)). `from` and `addr` are
    /// what the handshake and the TCP connection showed.
    pub fn store(
        &self,
        from: &PeerInfo,
        addr: SocketAddr,
        id: &str,
        raw: &[u8],
    ) -> R<(PathBuf, bool)> {
        let msg: Value =
            serde_json::from_slice(raw).map_err(|e| Abort(format!("message is not JSON: {e}")))?;
        let meta = check(&msg, self.max_hops)?;
        if meta.id != id {
            abort!("messageId {} doesn't match the transfer's ({id})", meta.id);
        }
        let reply = meta
            .reply_port
            .map(|p| SocketAddr::new(addr.ip(), p).to_string());
        let entry = json!({
            "sxfer_inbox": 1,
            "id": id,
            "received": now_iso(),
            "from": {
                "name": from.name,
                "fingerprint": from.fingerprint,
                "short": id::short_fp(&from.fingerprint),
                "pinned": from.known,
                "verified": "ML-DSA-65 handshake signature",
                "address": addr.ip().to_string(),
                "reply_to": reply
            },
            "thread": meta.thread,
            "intent": meta.intent,
            "subject": meta.subject,
            "hop": meta.hop,
            "in_reply_to": meta.in_reply_to,
            "bytes": raw.len(),
            "sha256": sha256_bytes(raw),
            "message": msg
        });
        let text = serde_json::to_vec_pretty(&entry).expect("serializable");
        let _turn = self.write.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = self.find_delivered(&from.fingerprint, id) {
            return Ok((p, true)); // the same message on two connections at once
        }
        let dest = self.dir.join(Self::file_name(&from.fingerprint, id));
        let part = self.dir.join(format!(".{}.part", random_hex(8)));
        let written: R<()> = (|| {
            let mut f = create_new_private(&part)?;
            f.write_all(&text)?;
            f.sync_all()?;
            drop(f);
            // read back from disk before anyone is told it arrived
            if fs::read(&part)? != text {
                abort!("inbox entry failed verification");
            }
            rename_no_clobber(&part, &dest)
        })();
        if let Err(e) = written {
            let _ = fs::remove_file(&part);
            return Err(e);
        }
        Ok((dest, false))
    }

    /// Messages, oldest first: pending ones, and with `include_done` handled ones too.
    pub fn list(&self, include_done: bool) -> R<Vec<Entry>> {
        let mut dirs = vec![(self.dir.clone(), false)];
        if include_done {
            dirs.push((self.dir.join("done"), true));
        }
        let mut out = Vec::new();
        for (d, done) in dirs {
            let Ok(rd) = fs::read_dir(&d) else { continue };
            for e in rd.flatten() {
                let p = e.path();
                let name = e.file_name().to_string_lossy().into_owned();
                if !name.ends_with(".json") || name.starts_with('.') || !p.is_file() {
                    continue;
                }
                match Entry::load(&p, done) {
                    Ok(entry) => out.push(entry),
                    Err(err) => say(&format!("skipping {err}")),
                }
            }
        }
        out.sort_by(|a, b| (a.received(), &a.path).cmp(&(b.received(), &b.path)));
        Ok(out)
    }

    /// A message by its id, or an unambiguous start of it.
    pub fn find(&self, which: &str) -> R<Entry> {
        let which = which.trim();
        if which.is_empty() {
            abort!("which message? (see `sxfer inbox list`)");
        }
        let all = self.list(true)?;
        if let Some(e) = all.iter().find(|e| e.id() == which) {
            return Ok(e.clone());
        }
        let hits: Vec<&Entry> = all.iter().filter(|e| e.id().starts_with(which)).collect();
        match hits.as_slice() {
            [e] => Ok((*e).clone()),
            [] => abort!("no message {which} in {}", self.dir.display()),
            _ => abort!(
                "{which} matches {} messages; give more of the id",
                hits.len()
            ),
        }
    }

    /// Move a message to done/.
    pub fn mark_done(&self, e: &Entry) -> R<PathBuf> {
        if e.done {
            return Ok(e.path.clone());
        }
        let name = e.path.file_name().expect("entries are files");
        let dest = self.dir.join("done").join(name);
        rename_no_clobber(&e.path, &dest)?;
        Ok(dest)
    }

    /// The oldest pending message not in `skip`, waiting up to `timeout` (None: forever).
    pub fn wait(&self, timeout: Option<Duration>, skip: &HashSet<PathBuf>) -> R<Option<Entry>> {
        let deadline = timeout.map(|t| Instant::now() + t);
        loop {
            if let Some(e) = self
                .list(false)?
                .into_iter()
                .find(|e| !skip.contains(&e.path))
            {
                return Ok(Some(e));
            }
            if deadline.is_some_and(|d| Instant::now() >= d) {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

fn decoded_len(b64: &str) -> usize {
    let pad = b64.bytes().rev().take_while(|&c| c == b'=').count();
    (b64.len() / 4 * 3).saturating_sub(pad)
}

/// A message for reading, by a person or an agent: the verified sender first, then the parts.
/// File parts show their name and size; `save_attachments` writes them out.
pub fn render(e: &Entry) -> String {
    let v = &e.v;
    let f = &v["from"];
    let txt = |x: &Value| x.as_str().unwrap_or("").to_string();
    let mut s = String::new();
    let mut line = |k: &str, val: String| s.push_str(&format!("{k:<11}{val}\n"));
    line(
        "message",
        format!("{}{}", e.id(), if e.done { "  (done)" } else { "" }),
    );
    line(
        "from",
        format!(
            "{} [{}]  verified by its ML-DSA-65 key{}",
            txt(&f["name"]),
            txt(&f["short"]),
            if f["pinned"] == true { ", pinned" } else { "" }
        ),
    );
    if let Some(x) = v["subject"].as_str() {
        line("subject", x.to_string());
    }
    line(
        "intent",
        format!(
            "{}   (hop {})",
            txt(&v["intent"]),
            v["hop"].as_u64().unwrap_or(0)
        ),
    );
    if let Some(x) = v["thread"].as_str() {
        line("thread", x.to_string());
    }
    if let Some(x) = v["in_reply_to"].as_str() {
        line("reply to", x.to_string());
    }
    let ago = now_secs().saturating_sub(e.received());
    line(
        "received",
        format!("{} (unix seconds, {} ago)", txt(&v["received"]), span(ago)),
    );
    s.push('\n');
    let empty = vec![];
    for p in v["message"]["parts"].as_array().unwrap_or(&empty) {
        match p["kind"].as_str() {
            Some("text") => {
                s.push_str(p["text"].as_str().unwrap_or(""));
                s.push_str("\n\n");
            }
            Some("data") => {
                let pretty = serde_json::to_string_pretty(&p["data"]).unwrap_or_default();
                s.push_str(&format!("```json\n{pretty}\n```\n\n"));
            }
            Some("file") => {
                let file = &p["file"];
                let size = file["bytes"]
                    .as_str()
                    .map(|b| format!("{} bytes", decoded_len(b)))
                    .unwrap_or_else(|| format!("at {}", txt(&file["uri"])));
                s.push_str(&format!(
                    "[attachment: {} ({size}, {}) - `sxfer inbox save {}` writes it out]\n\n",
                    txt(&file["name"]),
                    txt(&file["mimeType"]),
                    e.id()
                ));
            }
            _ => {}
        }
    }
    s.trim_end().to_string() + "\n"
}

/// Write a message's file parts into `dir` (never over an existing file).
pub fn save_attachments(e: &Entry, dir: &Path) -> R<Vec<PathBuf>> {
    let mut out = Vec::new();
    let empty = vec![];
    for p in e.v["message"]["parts"].as_array().unwrap_or(&empty) {
        if p["kind"] != "file" {
            continue;
        }
        let file = &p["file"];
        let Some(b64) = file["bytes"].as_str() else {
            say(&format!(
                "skipping {}: only a link ({})",
                file["name"], file["uri"]
            ));
            continue;
        };
        let bytes = B64
            .decode(b64)
            .map_err(|e| Abort(format!("attachment isn't valid base64: {e}")))?;
        let name = lan::safe_name(file["name"].as_str().unwrap_or("attachment"))?;
        let dest = (0..1000)
            .map(|n| match n {
                0 => dir.join(&name),
                _ => dir.join(format!("{n}-{name}")),
            })
            .find(|p| !p.exists())
            .ok_or_else(|| Abort(format!("too many copies of {name} in {}", dir.display())))?;
        let mut f = create_new_private(&dest)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        out.push(dest);
    }
    Ok(out)
}

// ---------------------------------------------------------------- sending

/// Transient: worth another try later (the outbox keeps it). Anything else is final.
pub fn retryable(e: &Abort) -> bool {
    [
        "cannot connect",
        "connection lost",
        "closed the connection",
        "not the listener you meant",
        "not the peer you addressed",
        "no address for",
        "rate limit",
        "no receipt",
        "timed out",
    ]
    .iter()
    .any(|k| e.0.contains(k))
}

/// The peer's `sxfer serve` found over mDNS, matched by its pinned key.
fn discovered(fp: &str) -> Vec<SocketAddr> {
    let nets = config::networks().unwrap_or_default();
    lan::discover(DISCOVER_WAIT)
        .unwrap_or_default()
        .into_iter()
        .filter(|f| f.msg && f.version == "2" && f.fingerprint.as_deref() == Some(fp))
        .flat_map(|f| f.all_addrs(&nets))
        .collect()
}

/// Deliver an A2A message to the pinned `peer`: at its set address, then `hint` (where its last
/// message said to reply), then (with `mdns`) wherever it advertises. Each address must prove
/// it holds the peer's pinned key before the message goes out.
pub fn deliver(
    me: &Identity,
    peer: &id::Peer,
    msg: &Value,
    hint: Option<&str>,
    mdns: bool,
) -> R<lan::Sent> {
    let Some(mid) = msg["messageId"].as_str() else {
        abort!("the message has no messageId")
    };
    let payload = lan::Payload::Message {
        id: mid.to_string(),
        bytes: serde_json::to_vec(msg).expect("serializable"),
    };
    let sc = ShredCfg {
        keep: true,
        ask: false,
        passes: 1,
        asker: None,
    };
    let opts = lan::SendOpts {
        auth: lan::Auth::Trusted,
        me,
        remember: false,
        expect_fp: Some(peer.fingerprint.clone()),
    };
    let mut tried: Vec<SocketAddr> = Vec::new();
    let mut last = None;
    for round in 0..2 {
        let addrs: Vec<SocketAddr> = match round {
            0 => [peer.addr.as_deref(), hint]
                .into_iter()
                .flatten()
                .filter_map(|a| lan::resolve_to(a).ok())
                .collect(),
            _ if mdns => discovered(&peer.fingerprint),
            _ => vec![],
        };
        for a in addrs {
            if tried.contains(&a) {
                continue;
            }
            tried.push(a);
            match lan::send_core(a, &payload, &sc, &opts) {
                Ok(s) => return Ok(s),
                Err(e) if retryable(&e) => last = Some(e),
                Err(e) => return Err(e),
            }
        }
    }
    Err(last.unwrap_or_else(|| {
        Abort(format!(
            "no address for {}: its `sxfer serve` wasn't found over mDNS, and none is set (`sxfer trust addr {} <host:port>`)",
            peer.name, peer.name
        ))
    }))
}

pub enum Outcome {
    Delivered {
        id: String,
        peer: PeerInfo,
        /// the receiver already had it (a retry)
        already: bool,
        receipt: SignedReceipt,
    },
    /// not reachable now; `sxfer serve` / `sxfer msg flush` keep trying
    Queued {
        id: String,
        path: PathBuf,
        why: String,
    },
}

/// Deliver now, or with `queue`, leave it in the outbox when the peer can't be reached.
pub fn send(
    me: &Identity,
    peer: &id::Peer,
    msg: &Value,
    hint: Option<&str>,
    queue: bool,
    mdns: bool,
) -> R<Outcome> {
    let mid = msg["messageId"].as_str().unwrap_or_default().to_string();
    match deliver(me, peer, msg, hint, mdns) {
        Ok(s) => Ok(Outcome::Delivered {
            id: mid,
            peer: s.listener,
            already: s.already,
            receipt: s.receipt,
        }),
        Err(e) if queue && retryable(&e) => {
            let path = enqueue(peer, msg, hint, &e.0)?;
            Ok(Outcome::Queued {
                id: mid,
                path,
                why: e.0,
            })
        }
        Err(e) => Err(e),
    }
}

/// A reply to an inbox entry: back to its verified sender, same thread, one hop further.
pub fn reply_to(e: &Entry, mut d: Draft) -> R<(id::Peer, Draft, Option<String>)> {
    let fp = e.v["from"]["fingerprint"].as_str().unwrap_or("");
    let peer = id::find_peer(fp)
        .map_err(|_| Abort(format!("{} is no longer pinned here", e.v["from"]["name"])))?;
    d.thread = e.v["thread"].as_str().map(str::to_string).or(d.thread);
    d.in_reply_to = Some(e.id().to_string());
    d.hop = e.v["hop"].as_u64().unwrap_or(0) as u32 + 1;
    if d.intent.is_none() {
        d.intent = Some("result".into());
    }
    if d.subject.is_none() {
        d.subject = e.v["subject"].as_str().map(|s| {
            if s.starts_with("Re: ") {
                s.to_string()
            } else {
                format!("Re: {s}")
            }
        });
    }
    let hint = e.v["from"]["reply_to"].as_str().map(str::to_string);
    Ok((peer, d, hint))
}

/// Pinned peers, and whether their `sxfer serve` answers over mDNS right now.
pub fn peers_status(mdns: bool) -> Vec<Value> {
    let found = if mdns {
        lan::discover(DISCOVER_WAIT).unwrap_or_default()
    } else {
        vec![]
    };
    id::peers()
        .iter()
        .map(|p| {
            let at: Vec<String> = found
                .iter()
                .filter(|f| f.msg && f.fingerprint.as_deref() == Some(p.fingerprint.as_str()))
                .flat_map(|f| f.all_addrs(&[]))
                .map(|a| a.to_string())
                .collect();
            json!({
                "name": p.name,
                "fingerprint": p.fingerprint,
                "short": id::short_fp(&p.fingerprint),
                "address": p.addr,
                "serving": !at.is_empty(),
                "advertised_at": at
            })
        })
        .collect()
}

// ---------------------------------------------------------------- outbox

fn outbox_dir() -> PathBuf {
    sxfer_dir().join("outbox")
}

fn backoff(attempts: u64) -> u64 {
    (RETRY_FIRST << attempts.saturating_sub(1).min(10)).min(RETRY_MAX)
}

fn write_json(p: &Path, v: &Value) -> R<()> {
    let tmp = p.with_extension(format!("{}.tmp", random_hex(4)));
    fs::write(&tmp, serde_json::to_vec_pretty(v).expect("serializable"))?;
    fs::rename(&tmp, p)?;
    Ok(())
}

/// Keep a message that couldn't be delivered yet.
pub fn enqueue(peer: &id::Peer, msg: &Value, hint: Option<&str>, why: &str) -> R<PathBuf> {
    let d = outbox_dir();
    private_dir(&d)?;
    let mid = msg["messageId"].as_str().unwrap_or("message");
    check_id(mid)?;
    let p = d.join(format!("{mid}.json"));
    let now = now_secs();
    write_json(
        &p,
        &json!({
            "to": peer.name,
            "fingerprint": peer.fingerprint,
            "hint": hint,
            "queued": now,
            "attempts": 1,
            "next": now + RETRY_FIRST,
            "last_error": why,
            "message": msg
        }),
    )?;
    Ok(p)
}

/// What's waiting in the outbox.
pub fn queued() -> Vec<Value> {
    let Ok(rd) = fs::read_dir(outbox_dir()) else {
        return vec![];
    };
    let mut out: Vec<Value> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .filter_map(|p| fs::read(&p).ok())
        .filter_map(|b| serde_json::from_slice::<Value>(&b).ok())
        .map(|v| {
            json!({
                "id": v["message"]["messageId"],
                "to": v["to"],
                "queued": v["queued"],
                "attempts": v["attempts"],
                "next_try": v["next"],
                "last_error": v["last_error"]
            })
        })
        .collect();
    out.sort_by_key(|v| v["queued"].as_u64().unwrap_or(0));
    out
}

/// One outbox message after a flush.
pub struct Flushed {
    pub id: String,
    pub to: String,
    /// delivered; or why not
    pub result: R<()>,
    /// moved to outbox/failed: no more tries
    pub gave_up: bool,
}

/// Retry the messages that are due (all of them with `all`).
pub fn flush(me: &Identity, all: bool, mdns: bool) -> R<Vec<Flushed>> {
    let d = outbox_dir();
    let Ok(rd) = fs::read_dir(&d) else {
        return Ok(vec![]);
    };
    let now = now_secs();
    let mut out = Vec::new();
    for p in rd.flatten().map(|e| e.path()) {
        if p.extension().is_none_or(|x| x != "json") {
            continue;
        }
        let Some(mut item) = fs::read(&p)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        else {
            continue;
        };
        if !all && item["next"].as_u64().unwrap_or(0) > now {
            continue;
        }
        let mid = item["message"]["messageId"]
            .as_str()
            .unwrap_or("?")
            .to_string();
        let to = item["to"].as_str().unwrap_or("?").to_string();
        let fp = item["fingerprint"].as_str().unwrap_or("");
        let r = id::find_peer(fp)
            .map_err(|_| Abort(format!("{to} is no longer pinned")))
            .and_then(|peer| deliver(me, &peer, &item["message"], item["hint"].as_str(), mdns));
        let expired = now.saturating_sub(item["queued"].as_u64().unwrap_or(now)) > OUTBOX_TTL;
        let (result, gave_up) = match r {
            Ok(_) => {
                fs::remove_file(&p)?;
                (Ok(()), false)
            }
            Err(e) if retryable(&e) && !expired => {
                let attempts = item["attempts"].as_u64().unwrap_or(1) + 1;
                item["attempts"] = json!(attempts);
                item["next"] = json!(now + backoff(attempts));
                item["last_error"] = json!(e.0);
                write_json(&p, &item)?;
                (Err(e), false)
            }
            Err(e) => {
                item["last_error"] = json!(e.0);
                let failed = d.join("failed");
                private_dir(&failed)?;
                write_json(&failed.join(p.file_name().expect("a file")), &item)?;
                fs::remove_file(&p)?;
                (Err(e), true)
            }
        };
        out.push(Flushed {
            id: mid,
            to,
            result,
            gave_up,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------- serve state + hook

fn state_path() -> PathBuf {
    sxfer_dir().join("serve.json")
}

/// Remember where `sxfer serve` listens, so messages sent from here say where to reply.
pub fn save_serve_state(port: u16, inbox: &Path) -> R<()> {
    private_dir(&sxfer_dir())?;
    write_json(
        &state_path(),
        &json!({ "port": port, "inbox": inbox.display().to_string(), "started": now_iso() }),
    )
}

fn serve_state() -> Option<Value> {
    serde_json::from_slice(&fs::read(state_path()).ok()?).ok()
}

/// The port `sxfer serve` last listened on here.
pub fn serve_port() -> Option<u16> {
    serve_state()?["port"]
        .as_u64()
        .and_then(|p| u16::try_from(p).ok())
}

/// The inbox to read: $SXFER_INBOX (set for --on-receive commands), else the one `sxfer serve`
/// last used here, else ~/.sxfer/inbox.
pub fn current_inbox() -> PathBuf {
    if let Some(d) = std::env::var_os("SXFER_INBOX") {
        return PathBuf::from(d);
    }
    serve_state()
        .and_then(|v| v["inbox"].as_str().map(PathBuf::from))
        .unwrap_or_else(Inbox::default_dir)
}

fn shell(cmd: &str) -> Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let mut c = Command::new("cmd");
        c.arg("/C").raw_arg(cmd);
        c
    }
    #[cfg(not(windows))]
    {
        let mut c = Command::new("sh");
        c.arg("-c").arg(cmd);
        c
    }
}

/// Run `cmd` for a new message, with SXFER_* variables and its output in <inbox>/logs/.
/// Exit 0 moves the message to done/ (unless the command already did): Ok(exit 0?).
pub fn run_hook(cmd: &str, inbox: &Inbox, e: &Entry) -> R<bool> {
    let stem = e
        .path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let log_path = inbox.dir.join("logs").join(format!("{stem}.log"));
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    let v = &e.v;
    let s = |x: &Value| x.as_str().unwrap_or("").to_string();
    let status = shell(cmd)
        .env("SXFER_MSG", &e.path)
        .env("SXFER_MSG_ID", e.id())
        .env("SXFER_FROM", s(&v["from"]["name"]))
        .env("SXFER_FROM_FP", s(&v["from"]["fingerprint"]))
        .env("SXFER_THREAD", s(&v["thread"]))
        .env("SXFER_INTENT", s(&v["intent"]))
        .env("SXFER_SUBJECT", s(&v["subject"]))
        .env("SXFER_HOP", v["hop"].as_u64().unwrap_or(0).to_string())
        .env("SXFER_INBOX", &inbox.dir)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .status()
        .map_err(|err| Abort(format!("cannot run the --on-receive command: {err}")))?;
    if !status.success() {
        return Ok(false);
    }
    if e.path.exists() {
        inbox.mark_done(e)?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::testing::{home, PINNING};
    use crate::lan::{serve_core, ListenCfg, Received};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc};

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sxfer-test-{tag}-{}", random_hex(4)));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn ident(role: &str) -> Identity {
        home();
        Identity::from_seed(&id::new_seed(), &format!("{role}-{}", random_hex(4)))
    }

    fn peer_info(me: &Identity) -> PeerInfo {
        PeerInfo {
            name: me.name.clone(),
            fingerprint: me.fingerprint(),
            known: true,
        }
    }

    fn draft(body: &str) -> Draft {
        Draft {
            body: body.into(),
            subject: Some("status".into()),
            intent: Some("handoff".into()),
            ..Draft::default()
        }
    }

    const FROM: &str = "10.0.0.7:40000";

    /// A running `sxfer serve` (pinned peers only, messages only) on 127.0.0.1.
    struct Served {
        port: u16,
        stop: Arc<AtomicBool>,
        events: mpsc::Receiver<R<Received>>,
        inbox: Arc<Inbox>,
    }

    impl Drop for Served {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
        }
    }

    impl Served {
        fn peer(&self, me: &Identity) -> id::Peer {
            id::Peer {
                name: me.name.clone(),
                fingerprint: me.fingerprint(),
                added: "0".into(),
                addr: Some(format!("127.0.0.1:{}", self.port)),
            }
        }
    }

    fn serve(me: Identity, inbox: Inbox) -> Served {
        let inbox = Arc::new(inbox);
        let stop = Arc::new(AtomicBool::new(false));
        let mut cfg = ListenCfg::new(
            "127.0.0.1:0".parse().unwrap(),
            tmpdir("files"),
            Arc::new(me),
        );
        cfg.advertise = false;
        cfg.accept_text = false;
        cfg.accept_files = false;
        cfg.trusted = true;
        cfg.pinned_only = true;
        cfg.inbox = Some(Arc::clone(&inbox));
        cfg.stop = Some(Arc::clone(&stop));
        let (port_tx, port_rx) = mpsc::channel();
        let (ev_tx, events) = mpsc::channel();
        let ev_tx = Mutex::new(ev_tx);
        spawn_big(move || {
            serve_core(
                Arc::new(cfg),
                &mut |p| port_tx.send(p).unwrap(),
                Arc::new(move |_, r| {
                    let _ = ev_tx.lock().unwrap().send(r);
                }),
            )
        });
        Served {
            port: port_rx.recv().unwrap(),
            stop,
            events,
            inbox,
        }
    }

    fn pin_both(a: &Identity, b: &Identity) {
        id::pin(&a.name, &a.fingerprint()).unwrap();
        id::pin(&b.name, &b.fingerprint()).unwrap();
    }

    /// Run `f` on a big stack (ML-DSA keys), as the binaries do.
    fn big<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        with_big_stack(f)
    }

    #[test]
    fn ids_are_safe_file_names() {
        for ok in ["a", "0123abcd", "task-7.v2_final", &"x".repeat(64)] {
            assert!(check_id(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            ".hidden",
            "../x",
            "a/b",
            "a\\b",
            "with space",
            &"x".repeat(65),
        ] {
            assert!(check_id(bad).is_err(), "{bad:?}");
        }
        assert_eq!(new_id().len(), 32);
    }

    #[test]
    fn built_messages_are_a2a_and_check_out() {
        home();
        let dir = tmpdir("att");
        let att = dir.join("notes.md");
        fs::write(&att, b"# attached").unwrap();
        let mut d = draft("hello **agent**");
        d.attach = vec![att];
        d.data = Some(json!({ "ticket": 42 }));
        let m = build(&d, "laptop").unwrap();
        assert_eq!(m["kind"], "message");
        assert_eq!(m["role"], "agent");
        assert_eq!(m["parts"][0]["kind"], "text");
        assert_eq!(m["parts"][1]["data"]["ticket"], 42);
        assert_eq!(m["parts"][2]["file"]["mimeType"], "text/markdown");
        let meta = check(&m, MAX_HOPS).unwrap();
        assert_eq!(meta.intent, "handoff");
        assert_eq!(meta.subject.as_deref(), Some("status"));
        assert_eq!(meta.hop, 0);
        assert!(build(&Draft::default(), "x").is_err(), "empty message");
    }

    #[test]
    fn checks_refuse_what_isnt_a_message() {
        let ok = json!({ "kind": "message", "messageId": "m1", "parts": [{ "kind": "text", "text": "hi" }] });
        assert!(check(&ok, 0).is_ok());
        let mut hop = ok.clone();
        hop["metadata"] = json!({ "sxfer": { "hop": 9 } });
        let e = check(&hop, 8).unwrap_err();
        assert!(e.0.contains("hop limit"), "{e}");
        for bad in [
            json!({ "kind": "task", "messageId": "m1", "parts": [{ "kind": "text", "text": "hi" }] }),
            json!({ "kind": "message", "parts": [{ "kind": "text", "text": "hi" }] }),
            json!({ "kind": "message", "messageId": "m1", "parts": [] }),
            json!({ "kind": "message", "messageId": "m1", "parts": [{ "kind": "video" }] }),
            json!({ "kind": "message", "messageId": "../m1", "parts": [{ "kind": "text", "text": "hi" }] }),
        ] {
            assert!(check(&bad, 8).is_err(), "{bad}");
        }
        let adopted = adopt(json!({ "parts": [{ "kind": "text", "text": "hi" }] })).unwrap();
        assert_eq!(adopted["kind"], "message");
        assert!(check_id(adopted["messageId"].as_str().unwrap()).is_ok());
    }

    #[test]
    fn inbox_stores_once_lists_finds_and_files_away() {
        let me = ident("sender");
        let inbox = Inbox::open(&tmpdir("inbox")).unwrap();
        let m = build(&draft("first"), &me.name).unwrap();
        let mid = m["messageId"].as_str().unwrap();
        let raw = serde_json::to_vec(&m).unwrap();
        let from = FROM.parse().unwrap();
        let (p, already) = inbox.store(&peer_info(&me), from, mid, &raw).unwrap();
        assert!(!already && p.exists());
        let (p2, already) = inbox.store(&peer_info(&me), from, mid, &raw).unwrap();
        assert!(already && p2 == p, "stored once");
        assert!(inbox.find_delivered(&me.fingerprint(), mid).is_some());
        let e = inbox.find(&mid[..8]).unwrap();
        assert_eq!(e.v["from"]["fingerprint"], me.fingerprint());
        assert_eq!(e.v["from"]["address"], "10.0.0.7");
        let text = render(&e);
        assert!(
            text.contains("verified by its ML-DSA-65 key") && text.contains("first"),
            "{text}"
        );
        assert!(
            inbox
                .store(&peer_info(&me), from, "other-id", &raw)
                .is_err(),
            "id mismatch"
        );
        inbox.mark_done(&e).unwrap();
        assert!(inbox.list(false).unwrap().is_empty());
        assert_eq!(inbox.list(true).unwrap().len(), 1);
        assert!(
            inbox.find_delivered(&me.fingerprint(), mid).is_some(),
            "done still dedups"
        );
        assert!(inbox
            .wait(Some(Duration::from_millis(300)), &HashSet::new())
            .unwrap()
            .is_none());
    }

    #[test]
    fn rate_limit_is_per_sender() {
        let mut inbox = Inbox::open(&tmpdir("inbox")).unwrap();
        inbox.rate = 2;
        assert!(inbox.admit("aa").is_ok() && inbox.admit("aa").is_ok());
        let e = inbox.admit("aa").unwrap_err();
        assert!(retryable(&e), "{e}");
        assert!(
            inbox.admit("bb").is_ok(),
            "another sender has its own budget"
        );
    }

    #[test]
    fn attachments_come_back_byte_for_byte() {
        let me = ident("sender");
        let src = tmpdir("src");
        let data: Vec<u8> = (0..=255u8).cycle().take(70_000).collect();
        fs::write(src.join("blob.bin"), &data).unwrap();
        let mut d = draft("see attached");
        d.attach = vec![src.join("blob.bin")];
        let m = build(&d, &me.name).unwrap();
        let inbox = Inbox::open(&tmpdir("inbox")).unwrap();
        let raw = serde_json::to_vec(&m).unwrap();
        let mid = m["messageId"].as_str().unwrap();
        inbox
            .store(&peer_info(&me), FROM.parse().unwrap(), mid, &raw)
            .unwrap();
        let e = inbox.find(mid).unwrap();
        assert!(render(&e).contains("blob.bin (70000 bytes"));
        let out = tmpdir("out");
        let saved = save_attachments(&e, &out).unwrap();
        assert_eq!(fs::read(&saved[0]).unwrap(), data);
        let again = save_attachments(&e, &out).unwrap();
        assert_ne!(again[0], saved[0], "never overwrites");
    }

    #[test]
    fn backoff_doubles_to_a_cap() {
        assert_eq!(backoff(1), 30);
        assert_eq!(backoff(2), 60);
        assert_eq!(backoff(4), 240);
        assert_eq!(backoff(50), RETRY_MAX);
    }

    #[test]
    fn messages_flow_between_pinned_peers_and_replies_find_their_way_back() {
        big(|| {
            let _turn = PINNING.lock().unwrap_or_else(|e| e.into_inner());
            let (a, b) = (seeded("agent-a"), seeded("agent-b"));
            pin_both(&a, &b);
            let a_srv = serve(clone_id(&a), Inbox::open(&tmpdir("inbox-a")).unwrap());
            let b_srv = serve(clone_id(&b), Inbox::open(&tmpdir("inbox-b")).unwrap());

            // A -> B
            let mut m = build(&draft("please review PR 7"), &a.name).unwrap();
            m["metadata"]["sxfer"]["replyPort"] = json!(a_srv.port);
            let sent = send(&a, &b_srv.peer(&b), &m, None, false, false).unwrap();
            let Outcome::Delivered {
                peer,
                already,
                receipt,
                ..
            } = sent
            else {
                panic!("expected delivery")
            };
            assert!(!already && peer.fingerprint == b.fingerprint());
            assert_eq!(receipt.open().unwrap().kind, "msg");
            assert!(matches!(
                b_srv.events.recv().unwrap(),
                Ok(Received::Message { already: false, .. })
            ));
            let e = b_srv.inbox.find(m["messageId"].as_str().unwrap()).unwrap();
            assert_eq!(
                e.v["from"]["fingerprint"],
                a.fingerprint(),
                "from = the handshake"
            );
            assert_eq!(e.v["subject"], "status");

            // the same message again: acknowledged, not stored twice
            let again = send(&a, &b_srv.peer(&b), &m, None, false, false).unwrap();
            assert!(matches!(again, Outcome::Delivered { already: true, .. }));
            assert_eq!(b_srv.inbox.list(true).unwrap().len(), 1);

            // B replies: to A's verified key, at the port A's message named
            let (to, d, hint) = reply_to(
                &e,
                Draft {
                    body: "LGTM".into(),
                    ..Draft::default()
                },
            )
            .unwrap();
            assert_eq!(to.fingerprint, a.fingerprint());
            assert_eq!(hint, Some(format!("127.0.0.1:{}", a_srv.port)));
            let r = build(&d, &b.name).unwrap();
            let back = send(&b, &to, &r, hint.as_deref(), false, false);
            assert!(matches!(back.unwrap(), Outcome::Delivered { .. }));
            let got = a_srv.inbox.find(r["messageId"].as_str().unwrap()).unwrap();
            assert_eq!(got.v["in_reply_to"], m["messageId"]);
            assert_eq!(got.v["thread"], m["contextId"], "same thread");
            assert_eq!(got.v["hop"], 1);
            assert_eq!(got.v["subject"], "Re: status");
            assert_eq!(got.v["intent"], "result");
        })
    }

    /// Identities don't implement Clone (they hold a secret key); rebuild one from its seed file.
    fn clone_id(me: &Identity) -> Identity {
        SEEDS.with(|s| {
            let seed = s.borrow()[&me.fingerprint()];
            Identity::from_seed(&seed, &me.name)
        })
    }

    thread_local! {
        static SEEDS: std::cell::RefCell<HashMap<String, [u8; 32]>> = Default::default();
    }

    #[test]
    fn strangers_wrong_peers_hop_limits_and_files_are_refused() {
        big(|| {
            let _turn = PINNING.lock().unwrap_or_else(|e| e.into_inner());
            let (a, b) = (seeded("agent-a"), seeded("agent-b"));
            pin_both(&a, &b);
            let b_srv = serve(clone_id(&b), Inbox::open(&tmpdir("inbox-b")).unwrap());
            let m = build(&draft("hi"), &a.name).unwrap();

            // a sender B never pinned
            let stranger = seeded("stranger");
            let e = send(&stranger, &b_srv.peer(&b), &m, None, false, false)
                .err()
                .unwrap();
            assert!(e.0.contains("pinned"), "{e}");

            // someone else at the address we think is C's: refused before anything is sent
            let c = seeded("agent-c");
            id::pin(&c.name, &c.fingerprint()).unwrap();
            let wrong = id::Peer {
                name: c.name.clone(),
                fingerprint: c.fingerprint(),
                added: "0".into(),
                addr: Some(format!("127.0.0.1:{}", b_srv.port)),
            };
            let e = send(&a, &wrong, &m, None, false, false).err().unwrap();
            assert!(e.0.contains("not the peer you addressed"), "{e}");

            // an agent loop: refused at the receiver
            let mut d = draft("again");
            d.hop = MAX_HOPS + 1;
            let looped = build(&d, &a.name).unwrap();
            let e = send(&a, &b_srv.peer(&b), &looped, None, false, false)
                .err()
                .unwrap();
            assert!(e.0.contains("hop limit"), "{e}");
            assert!(!retryable(&e));

            // a file, to a messages-only serve
            let src = tmpdir("src").join("f.txt");
            fs::write(&src, b"f").unwrap();
            let o = lan::SendOpts {
                auth: lan::Auth::Trusted,
                me: &a,
                remember: false,
                expect_fp: None,
            };
            let sc = ShredCfg {
                keep: false,
                ask: false,
                passes: 1,
                asker: None,
            };
            let addr = format!("127.0.0.1:{}", b_srv.port).parse().unwrap();
            let e = lan::send_core(addr, &lan::Payload::File(src.clone()), &sc, &o)
                .err()
                .unwrap();
            assert!(e.0.contains("messages only"), "{e}");
            assert!(src.exists());
            assert!(b_srv.inbox.list(true).unwrap().is_empty());
        })
    }

    #[test]
    fn unreachable_peers_queue_and_flush_delivers_later() {
        big(|| {
            let _turn = PINNING.lock().unwrap_or_else(|e| e.into_inner());
            let (a, b) = (seeded("agent-a"), seeded("agent-b"));
            pin_both(&a, &b);
            // nothing listens on port 1
            let mut peer = id::find_peer(&b.name).unwrap();
            peer.addr = Some("127.0.0.1:1".into());
            let m = build(&draft("when you're back"), &a.name).unwrap();
            let mid = m["messageId"].as_str().unwrap().to_string();
            let out = send(&a, &peer, &m, None, true, false).unwrap();
            let Outcome::Queued { path, .. } = out else {
                panic!("expected queued")
            };
            assert!(path.exists());
            assert!(queued().iter().any(|q| q["id"] == mid.as_str()));
            assert!(
                send(&a, &peer, &m, None, false, false).is_err(),
                "no queue: an error"
            );

            // B comes online at an address the pin now knows
            let b_srv = serve(clone_id(&b), Inbox::open(&tmpdir("inbox-b")).unwrap());
            id::set_addr(&b.name, Some(&format!("127.0.0.1:{}", b_srv.port))).unwrap();
            let flushed = flush(&a, true, false).unwrap();
            let mine = flushed.iter().find(|f| f.id == mid).expect("flushed");
            assert!(mine.result.is_ok(), "{:?}", mine.result.as_ref().err());
            assert!(!path.exists(), "delivered: out of the outbox");
            assert!(b_srv.inbox.find(&mid).is_ok());
        })
    }

    #[test]
    fn hook_gets_the_message_and_success_files_it_away() {
        let me = ident("sender");
        let inbox = Inbox::open(&tmpdir("inbox")).unwrap();
        let m = build(&draft("run me"), &me.name).unwrap();
        let mid = m["messageId"].as_str().unwrap();
        let raw = serde_json::to_vec(&m).unwrap();
        inbox
            .store(&peer_info(&me), FROM.parse().unwrap(), mid, &raw)
            .unwrap();
        let e = inbox.find(mid).unwrap();
        let out = tmpdir("hook").join("seen.txt");
        let cmd = if cfg!(windows) {
            format!("echo %SXFER_MSG_ID% %SXFER_INTENT%> \"{}\"", out.display())
        } else {
            format!("echo \"$SXFER_MSG_ID $SXFER_INTENT\" > '{}'", out.display())
        };
        assert!(run_hook(&cmd, &inbox, &e).unwrap());
        let seen = fs::read_to_string(&out).unwrap();
        assert_eq!(seen.trim(), format!("{mid} handoff"));
        assert!(inbox.list(false).unwrap().is_empty(), "exit 0: done");

        let m2 = build(&draft("fail me"), &me.name).unwrap();
        let mid2 = m2["messageId"].as_str().unwrap();
        let raw2 = serde_json::to_vec(&m2).unwrap();
        inbox
            .store(&peer_info(&me), FROM.parse().unwrap(), mid2, &raw2)
            .unwrap();
        let e2 = inbox.find(mid2).unwrap();
        assert!(!run_hook("exit 3", &inbox, &e2).unwrap());
        assert_eq!(inbox.list(false).unwrap().len(), 1, "failed: still pending");
    }

    /// An identity whose seed is kept, so `clone_id` can make another handle to it.
    fn seeded(role: &str) -> Identity {
        home();
        let seed = id::new_seed();
        let me = Identity::from_seed(&seed, &format!("{role}-{}", random_hex(4)));
        SEEDS.with(|s| s.borrow_mut().insert(me.fingerprint(), seed));
        me
    }
}
