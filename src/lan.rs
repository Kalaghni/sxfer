//! Direct LAN transfer, no SSH: `sxfer listen` on the receiver, `sxfer send` on the sender.
//!
//! DISCOVERY  Bonjour / mDNS DNS-SD. The listener binds a random free TCP port and advertises
//!            `_sxfer._tcp.local.` (TXT: id, name); the sender browses for it and only connects to
//!            listeners whose address is inside its configured networks (an allowlist).
//! HANDSHAKE  TCP, protocol v2 (sxfer 0.7+). Two key agreements in one round trip:
//!            - SPAKE2 (Ed25519 group) keyed by the listener's one-time code: the code never
//!              crosses the wire, an eavesdropper can't test guesses offline, and an active attacker
//!              gets one guess per connection (the listener allows 3, then closes).
//!            - ML-KEM-768 (FIPS 203), ephemeral: the sender sends an encapsulation key, the listener
//!              a ciphertext. Recording the traffic now and breaking SPAKE2's elliptic curve with a
//!              quantum computer later isn't enough: the session key needs this secret too.
//!            Without a code (both sides pinned, `listen --trusted`) SPAKE2 runs with a fixed
//!            password and authentication rests on the signatures below.
//! CHANNEL    HKDF-SHA256(salt = transcript hash, spake key || ML-KEM key) -> one ChaCha20-Poly1305
//!            key per direction, counter nonces. A wrong code shows up as the first frame failing
//!            to authenticate.
//! IDENTITY   First thing inside the channel, each side sends HELLO: its name and ML-DSA-65 key
//!            (FIPS 204), signed over the transcript. Pinned peers are checked like ssh host keys.
//! TRANSFER   header {kind, name, size, sha256} -> ACCEPT/REJECT -> data frames -> END.
//!            The listener writes <name>.sxfer-part, fsyncs, re-reads it FROM DISK, checks size +
//!            sha256, commits with a no-clobber rename and replies with a RECEIPT it signs with
//!            ML-DSA-65 (bound to this session's transcript). The sender verifies it; only then does the
//!            sender (re-hashing its source first, and asking first unless confirmation is off)
//!            shred, and tells the listener whether it did (DONE).
//!            Secrets (kind "text") are shown on the listener's screen and never written to disk.
//!            Agent messages (kind "msg", `sxfer serve` only) go into its inbox: see mesh.rs.
//! RECEIPTS   on the destination only (the listener). The sender keeps no record.
//! SERVE      `serve_core` keeps accepting, one thread per connection, for `sxfer serve`.

use crate::abort;
use crate::common::*;
use crate::identity::{self as id, SignedReceipt};
use crate::mesh;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use ipnet::IpNet;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use ml_kem::{Decapsulate, Encapsulate, EncapsulationKey768, Kem, KeyExport, MlKem768};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity as SpakeId, Password, Spake2};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const SERVICE: &str = "_sxfer._tcp.local.";
const MAGIC: &[u8] = b"SXFER2";
/// what sxfer 0.6 and older send: told to upgrade rather than "not an sxfer sender"
const OLD_MAGIC: &[u8] = b"SXFER1";
/// the one-time code authenticates the pairing (SPAKE2); both sides then sign the transcript
const MODE_CODE: u8 = 0;
/// no code: both sides must be pinned peers, authenticated by their transcript signatures alone
const MODE_TRUSTED: u8 = 1;
/// SPAKE2's password in MODE_TRUSTED, where it's plain (unauthenticated) key agreement
const NO_CODE: &[u8] = b"sxfer/2/no-code";
/// ML-KEM-768 encapsulation key and ciphertext sizes
const EK_LEN: usize = 1184;
const CT_LEN: usize = 1088;
const ID_SEND: &[u8] = b"sxfer-send";
const ID_LISTEN: &[u8] = b"sxfer-listen";
const MAX_FRAME: usize = 4 << 20;
const MAX_TEXT: u64 = 64 * 1024;
const MAX_BAD_CODES: u32 = 3;
const IO_TIMEOUT: Duration = Duration::from_secs(120);
/// How long the listener waits for DONE after its receipt: the sender may be answering the shred prompt.
const DONE_TIMEOUT: Duration = Duration::from_secs(600);
/// Messages have nothing to shred, so DONE follows the receipt at once.
const MSG_DONE_TIMEOUT: Duration = Duration::from_secs(10);
/// Transfers `serve_core` handles at once; more connections are closed straight away.
const MAX_CONNS: usize = 16;

const T_HELLO: u8 = 0x05;
const T_HEADER: u8 = 1;
const T_DATA: u8 = 2;
const T_END: u8 = 3;
const T_ACCEPT: u8 = 0x10;
const T_REJECT: u8 = 0x11;
const T_RECEIPT: u8 = 0x20;
const T_FAIL: u8 = 0x21;
const T_DONE: u8 = 0x30;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Header {
    kind: String, // "file" | "text"
    name: String,
    size: u64,
    sha256: String,
    from: String,
}

/// Who is on the other end: a name and ML-DSA-65 public key, signed over the session transcript.
#[derive(Serialize, Deserialize, Debug)]
struct Hello {
    name: String,
    pk: String,
    sig: String,
}

impl Hello {
    fn new(me: &id::Identity, ctx: &[u8], transcript: &[u8; 32]) -> R<Hello> {
        let sig = me.sign(ctx, &hello_msg(transcript, me.public_key(), &me.name))?;
        Ok(Hello {
            name: me.name.clone(),
            pk: hex(me.public_key()),
            sig: hex(&sig),
        })
    }

    /// The peer's fingerprint, once its signature over this session's transcript checks out.
    fn verify(&self, ctx: &[u8], transcript: &[u8; 32]) -> R<String> {
        let pk = unhex(&self.pk).ok_or_else(|| Abort("malformed peer key".into()))?;
        let sig = unhex(&self.sig).ok_or_else(|| Abort("malformed peer signature".into()))?;
        if !id::verify(&pk, ctx, &hello_msg(transcript, &pk, &self.name), &sig) {
            abort!("the peer's handshake signature is INVALID");
        }
        Ok(id::fingerprint(&pk))
    }
}

/// The public key has a fixed length, so this concatenation is unambiguous.
fn hello_msg(transcript: &[u8; 32], pk: &[u8], name: &str) -> Vec<u8> {
    [transcript.as_slice(), pk, name.as_bytes()].concat()
}

/// A peer that proved it holds the key it presented.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub name: String,
    pub fingerprint: String,
    /// pinned in ~/.sxfer/known_peers.json
    pub known: bool,
}

impl PeerInfo {
    pub fn describe(&self) -> String {
        format!(
            "{} [{}{}]",
            self.name,
            id::short_fp(&self.fingerprint),
            if self.known { ", pinned" } else { "" }
        )
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Done {
    shredded: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct Reason {
    reason: String,
}

// ---------------------------------------------------------------- framing + secure channel

fn write_frame(s: &mut TcpStream, b: &[u8]) -> io::Result<()> {
    s.write_all(&(b.len() as u32).to_be_bytes())?;
    s.write_all(b)?;
    s.flush()
}

fn read_frame(s: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut l = [0u8; 4];
    s.read_exact(&mut l)?;
    let n = u32::from_be_bytes(l) as usize;
    if n > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut v = vec![0u8; n];
    s.read_exact(&mut v)?;
    Ok(v)
}

fn nonce(c: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&c.to_be_bytes());
    Nonce::clone_from_slice(&n)
}

struct Chan {
    s: TcpStream,
    tx: ChaCha20Poly1305,
    rx: ChaCha20Poly1305,
    ntx: u64,
    nrx: u64,
}

/// Raised when the very first encrypted frame doesn't authenticate: the two sides hold different keys.
const BAD_CODE: &str = "wrong code";

impl Chan {
    /// Hybrid: the keys depend on both the SPAKE2 key (the code) and the ML-KEM-768 key.
    fn new(
        s: TcpStream,
        spake_key: &[u8],
        kem_key: &[u8],
        transcript: &[u8; 32],
        sender: bool,
    ) -> Chan {
        let ikm = [spake_key, kem_key].concat();
        let hk = Hkdf::<Sha256>::new(Some(transcript), &ikm);
        let mut okm = [0u8; 64];
        hk.expand(b"sxfer-lan-v2 chacha20poly1305 send|listen", &mut okm)
            .expect("64 bytes is a valid HKDF length");
        let s2l = ChaCha20Poly1305::new(Key::from_slice(&okm[..32]));
        let l2s = ChaCha20Poly1305::new(Key::from_slice(&okm[32..]));
        let (tx, rx) = if sender { (s2l, l2s) } else { (l2s, s2l) };
        Chan {
            s,
            tx,
            rx,
            ntx: 0,
            nrx: 0,
        }
    }

    fn send(&mut self, t: u8, body: &[u8]) -> R<()> {
        let mut pt = Vec::with_capacity(body.len() + 1);
        pt.push(t);
        pt.extend_from_slice(body);
        let ct = self
            .tx
            .encrypt(&nonce(self.ntx), pt.as_slice())
            .map_err(|_| Abort("encrypt failed".into()))?;
        self.ntx += 1;
        write_frame(&mut self.s, &ct).map_err(|e| Abort(format!("connection lost: {e}")))
    }

    fn send_json<T: Serialize>(&mut self, t: u8, v: &T) -> R<()> {
        self.send(t, &serde_json::to_vec(v).expect("serializable"))
    }

    fn recv(&mut self) -> R<(u8, Vec<u8>)> {
        let ct = read_frame(&mut self.s).map_err(|e| Abort(format!("connection lost: {e}")))?;
        let mut pt = self
            .rx
            .decrypt(&nonce(self.nrx), ct.as_slice())
            .map_err(|_| {
                Abort(if self.nrx == 0 {
                    BAD_CODE.into()
                } else {
                    "message failed authentication".into()
                })
            })?;
        self.nrx += 1;
        if pt.is_empty() {
            abort!("empty message");
        }
        let t = pt.remove(0);
        Ok((t, pt))
    }
}

fn parse_json<T: for<'de> Deserialize<'de>>(b: &[u8], what: &str) -> R<T> {
    serde_json::from_slice(b).map_err(|e| Abort(format!("bad {what}: {e}")))
}

/// SHA-256 over both handshake messages; everything signed or derived later is bound to it.
fn transcript(first: &[u8], second: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"sxfer/2/transcript");
    for part in [first, second] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    h.finalize().into()
}

/// Check a peer whose signature verified against the pinned peers: Ok(the name it's pinned as).
fn vet(name: &str, fp: &str, mode: u8, role: &str) -> R<Option<String>> {
    match id::check_peer(name, fp) {
        id::Known::Yes(pinned) => Ok(Some(pinned)),
        id::Known::Changed { pinned_fp } => abort!(
            "KEY CHANGED: the {role} says it is {name}, but {name} is pinned to {} and this key is {}. \
If {name} was reinstalled, run `sxfer trust remove {name}` and pair once with a code; \
otherwise something may be impersonating it.",
            id::short_fp(&pinned_fp),
            id::short_fp(fp)
        ),
        id::Known::New if mode == MODE_TRUSTED => abort!(
            "the {role} {name} [{}] isn't a pinned peer, so it needs the one-time code",
            id::short_fp(fp)
        ),
        id::Known::New => Ok(None),
    }
}

/// A verified peer, named as the user pinned it (a name it claims only counts until then).
fn peer_info(claimed: &str, fp: String, pinned: Option<String>) -> PeerInfo {
    PeerInfo {
        known: pinned.is_some(),
        name: pinned.unwrap_or_else(|| claimed.to_string()),
        fingerprint: fp,
    }
}

fn remember(peer: &PeerInfo) {
    match id::pin(&peer.name, &peer.fingerprint) {
        Ok(true) => say(&format!(
            "pinned {} [{}]: next time it can pair without a code",
            peer.name,
            id::short_fp(&peer.fingerprint)
        )),
        Ok(false) => {}
        Err(e) => say(&format!("could not pin {}: {e}", peer.name)),
    }
}

pub fn normalize_code(code: &str) -> String {
    code.chars().filter(|c| c.is_ascii_digit()).collect()
}

pub fn new_code() -> String {
    let n: u32 = rand::rngs::OsRng.gen_range(0..1_000_000);
    format!("{:03}-{:03}", n / 1000, n % 1000)
}

// ---------------------------------------------------------------- listener

pub enum Received {
    File {
        path: PathBuf,
        already: bool,
        shredded: Option<bool>,
        sender: PeerInfo,
    },
    Text {
        sender: PeerInfo,
        text: String,
    },
    /// An agent message, stored in the inbox
    Message {
        entry: PathBuf,
        id: String,
        /// a repeat of a message already in the inbox: acknowledged, not stored again
        already: bool,
        sender: PeerInfo,
    },
}

pub struct ListenCfg {
    pub bind: SocketAddr,
    pub dir: PathBuf,
    /// advertise over mDNS (off in the tests)
    pub advertise: bool,
    /// take secrets as well as files (the MCP server takes files only)
    pub accept_text: bool,
    /// set it to close the listener while it waits for a sender
    pub stop: Option<Arc<AtomicBool>>,
    /// this machine's identity: signs the handshake and receipts
    pub me: Arc<id::Identity>,
    /// also accept pinned senders without the code
    pub trusted: bool,
    /// pin a new sender after a successful transfer with the code
    pub remember: bool,
    /// take files (`sxfer serve` without --files takes messages only)
    pub accept_files: bool,
    /// refuse senders that aren't pinned, code or not (`sxfer serve`)
    pub pinned_only: bool,
    /// take agent messages into this inbox (`sxfer serve`)
    pub inbox: Option<Arc<mesh::Inbox>>,
}

impl ListenCfg {
    /// A listener for files and secrets, as `sxfer listen` runs it.
    pub fn new(bind: SocketAddr, dir: PathBuf, me: Arc<id::Identity>) -> ListenCfg {
        ListenCfg {
            bind,
            dir,
            advertise: true,
            accept_text: true,
            stop: None,
            me,
            trusted: false,
            remember: false,
            accept_files: true,
            pinned_only: false,
            inbox: None,
        }
    }
}

/// An mDNS advertisement; dropping it sends the "goodbye" and stops the responder.
struct Advert {
    daemon: ServiceDaemon,
    fullname: String,
}

impl Drop for Advert {
    fn drop(&mut self) {
        if let Ok(rx) = self.daemon.unregister(&self.fullname) {
            let _ = rx.recv_timeout(Duration::from_millis(500));
        }
        let _ = self.daemon.shutdown();
    }
}

fn mdns_err(e: mdns_sd::Error) -> Abort {
    Abort(format!("mDNS: {e}"))
}

fn advertise(port: u16, cfg: &ListenCfg) -> R<Advert> {
    let daemon = ServiceDaemon::new().map_err(mdns_err)?;
    let id = random_hex(4);
    let name = host_name();
    let fp = cfg.me.fingerprint();
    let trusted = if cfg.trusted { "1" } else { "0" };
    let msg = if cfg.inbox.is_some() { "1" } else { "0" };
    let props: HashMap<String, String> = [
        ("id", id.as_str()),
        ("name", name.as_str()),
        ("v", "2"),
        ("fp", fp.as_str()),
        ("trusted", trusted),
        ("msg", msg),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    // our own host label, so we never collide with the OS's own mDNS hostname
    let info = ServiceInfo::new(
        SERVICE,
        &format!("{name}-{id}"),
        &format!("sxfer-{id}.local."),
        "",
        port,
        props,
    )
    .map_err(mdns_err)?
    .enable_addr_auto();
    let fullname = info.get_fullname().to_string();
    daemon.register(info).map_err(mdns_err)?;
    Ok(Advert { daemon, fullname })
}

/// Bind, advertise (dropping the Advert withdraws it) and report the port to `ready`.
fn open(cfg: &ListenCfg, ready: &mut dyn FnMut(u16)) -> R<(TcpListener, Option<Advert>)> {
    let tcp = TcpListener::bind(cfg.bind)
        .map_err(|e| Abort(format!("cannot listen on {}: {e}", cfg.bind)))?;
    let port = tcp.local_addr()?.port();
    let advert = if cfg.advertise {
        match advertise(port, cfg) {
            Ok(a) => Some(a),
            Err(e) => {
                say(&format!(
                    "{e}; not discoverable - senders must use --to <ip>:{port}"
                ));
                None
            }
        }
    } else {
        None
    };
    ready(port);
    if cfg.stop.is_some() {
        tcp.set_nonblocking(true)?; // poll, so the stop flag is noticed
    }
    Ok((tcp, advert))
}

/// The next connection, or None once `cfg.stop` is set.
fn next_conn(tcp: &TcpListener, cfg: &ListenCfg) -> Option<(TcpStream, SocketAddr)> {
    loop {
        match tcp.accept() {
            Ok((stream, peer)) => {
                let _ = stream.set_nonblocking(false); // inherited from the listener on some platforms
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                return Some((stream, peer));
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if cfg.stop.as_ref().is_some_and(|s| s.load(Ordering::Relaxed)) {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => say(&format!("accept failed: {e}")),
        }
    }
}

/// Wait for one successful transfer with `code`. `ready` is called with the bound TCP port.
pub fn listen_core(cfg: &ListenCfg, code: &str, ready: &mut dyn FnMut(u16)) -> R<Received> {
    let (tcp, _advert) = open(cfg, ready)?;
    let code = normalize_code(code);
    let mut bad = 0;
    let result = loop {
        let Some((stream, peer)) = next_conn(&tcp, cfg) else {
            break Err(Abort("listener stopped".into()));
        };
        match handle(stream, &code, cfg, peer) {
            Ok(r) => break Ok(r),
            Err(e) if e.0 == BAD_CODE => {
                bad += 1;
                say(&format!("{peer}: wrong code ({bad}/{MAX_BAD_CODES})"));
                if bad >= MAX_BAD_CODES {
                    break Err(Abort(format!("{MAX_BAD_CODES} wrong codes; listener closed (start a new one for a fresh code)")));
                }
            }
            Err(e) => say(&format!("{peer}: {e} (still listening)")),
        }
    };
    result
}

/// What `serve_core` reports for each connection: who connected and how it went.
pub type OnTransfer = dyn Fn(SocketAddr, R<Received>) + Send + Sync;

/// Keep accepting until `cfg.stop` is set, each connection on its own thread, and hand every
/// outcome to `on_transfer`. There's no code to guess here, so wrong ones never close it; use
/// it with `pinned_only` (and `trusted`), as `sxfer serve` does.
pub fn serve_core(
    cfg: Arc<ListenCfg>,
    ready: &mut dyn FnMut(u16),
    on_transfer: Arc<OnTransfer>,
) -> R<()> {
    let (tcp, _advert) = open(&cfg, ready)?;
    // unguessable and never shown: the code path can't succeed, so only pinned peers get in
    let code = Arc::new(random_hex(32));
    let busy = Arc::new(AtomicUsize::new(0));
    while let Some((stream, peer)) = next_conn(&tcp, &cfg) {
        if busy.load(Ordering::SeqCst) >= MAX_CONNS {
            say(&format!("{peer}: too many transfers at once; closed"));
            continue;
        }
        busy.fetch_add(1, Ordering::SeqCst);
        let (cfg, code, busy, report) = (
            Arc::clone(&cfg),
            Arc::clone(&code),
            Arc::clone(&busy),
            Arc::clone(&on_transfer),
        );
        spawn_big(move || {
            let r = handle(stream, &code, &cfg, peer);
            busy.fetch_sub(1, Ordering::SeqCst);
            report(peer, r);
        });
    }
    Ok(())
}

fn handle(mut s: TcpStream, code: &str, cfg: &ListenCfg, peer_addr: SocketAddr) -> R<Received> {
    let dir = &cfg.dir;
    let first = read_frame(&mut s)?;
    if first.starts_with(OLD_MAGIC) {
        abort!("the sender runs sxfer 0.6 or older; both sides need 0.7+");
    }
    let Some(rest) = first.strip_prefix(MAGIC) else {
        abort!("not an sxfer sender")
    };
    let Some((&mode, rest)) = rest.split_first() else {
        abort!("bad handshake")
    };
    if rest.len() <= EK_LEN {
        abort!("bad handshake");
    }
    let (msg_a, ek) = rest.split_at(rest.len() - EK_LEN);
    let password = match mode {
        MODE_CODE => code.as_bytes(),
        MODE_TRUSTED => NO_CODE,
        _ => abort!("bad handshake"),
    };
    let (st, msg_b) = Spake2::<Ed25519Group>::start_b(
        &Password::new(password),
        &SpakeId::new(ID_SEND),
        &SpakeId::new(ID_LISTEN),
    );
    let ek = ml_kem::Key::<EncapsulationKey768>::try_from(ek)
        .ok()
        .and_then(|k| EncapsulationKey768::new(&k).ok())
        .ok_or_else(|| Abort("bad handshake (ML-KEM key)".into()))?;
    let (ct, kem_key) = ek.encapsulate();
    let second = [msg_b.as_slice(), ct.as_slice()].concat();
    write_frame(&mut s, &second)?;
    let spake_key = st
        .finish(msg_a)
        .map_err(|_| Abort("bad handshake".into()))?;
    let t = transcript(&first, &second);
    let mut ch = Chan::new(s, &spake_key, &kem_key, &t, false);

    let (ty, body) = ch.recv()?; // BAD_CODE surfaces here
    if ty != T_HELLO {
        abort!("protocol error: expected hello");
    }
    let hello: Hello = parse_json(&body, "hello")?;
    let checked = hello.verify(id::CTX_SENDER, &t).and_then(|fp| {
        if mode == MODE_TRUSTED && !cfg.trusted {
            abort!("this listener needs its one-time code (start it with --trusted to skip that for pinned peers)");
        }
        let pinned = vet(&hello.name, &fp, mode, "sender")?;
        if cfg.pinned_only && pinned.is_none() {
            abort!(
                "{} [{}] isn't pinned here, and this listener only takes pinned peers (`sxfer trust add` on it)",
                hello.name,
                id::short_fp(&fp)
            );
        }
        Ok(peer_info(&hello.name, fp, pinned))
    });
    let sender = match checked {
        Ok(p) => p,
        Err(e) => {
            let reason = e.0.clone();
            let _ = ch.send_json(T_REJECT, &Reason { reason });
            return Err(e);
        }
    };
    ch.send_json(T_HELLO, &Hello::new(&cfg.me, id::CTX_LISTENER, &t)?)?;
    say(&format!("paired with {}", sender.describe()));

    let (t2, body) = ch.recv()?;
    if t2 != T_HEADER {
        abort!("protocol error: expected header");
    }
    let h: Header = parse_json(&body, "header")?;

    let sign_receipt = |path: Option<String>, already: bool| {
        let body = id::ReceiptBody {
            v: 2,
            time: now_iso(),
            listener: cfg.me.name.clone(),
            listener_pk: hex(cfg.me.public_key()),
            sender: sender.name.clone(),
            sender_fp: sender.fingerprint.clone(),
            kind: h.kind.clone(),
            name: h.name.clone(),
            path,
            size: h.size,
            sha256: h.sha256.clone(),
            already,
            session: hex(&t),
        };
        SignedReceipt::sign(&cfg.me, &body)
    };

    if h.kind == "text" {
        if !cfg.accept_text {
            ch.send_json(
                T_REJECT,
                &Reason {
                    reason: "this listener takes files only, not secrets".into(),
                },
            )?;
            abort!("rejected a secret (files only)");
        }
        if h.size > MAX_TEXT {
            ch.send_json(
                T_REJECT,
                &Reason {
                    reason: format!("secret too large (max {MAX_TEXT} bytes)"),
                },
            )?;
            abort!("rejected oversized secret");
        }
        ch.send(T_ACCEPT, b"{}")?;
        let data = recv_all_mem(&mut ch, h.size)?;
        if data.len() as u64 != h.size || sha256_bytes(&data) != h.sha256 {
            ch.send_json(
                T_FAIL,
                &Reason {
                    reason: "secret corrupted in transit".into(),
                },
            )?;
            abort!("secret failed verification");
        }
        ch.send_json(T_RECEIPT, &sign_receipt(None, false)?)?;
        let _ = ch.recv(); // DONE (nothing to log for secrets)
        let text = String::from_utf8_lossy(&data).into_owned();
        if cfg.remember && !sender.known {
            remember(&sender);
        }
        return Ok(Received::Text { sender, text });
    }
    if h.kind == "msg" {
        return receive_message(ch, cfg, &h, sender.clone(), peer_addr, &sign_receipt);
    }
    if h.kind != "file" {
        abort!("unknown kind {:?}", h.kind);
    }
    if !cfg.accept_files {
        ch.send_json(
            T_REJECT,
            &Reason {
                reason: "this listener takes agent messages only (start `sxfer serve` with --files to take files)".into(),
            },
        )?;
        abort!("rejected a file (messages only)");
    }

    let name = safe_name(&h.name)?;
    let dest = dir.join(&name);
    let mut already = false;
    if dest.exists() {
        if sha256_file(&dest)? == (h.sha256.clone(), h.size) {
            already = true; // an earlier run delivered it but the sender never saw the receipt
        } else {
            ch.send_json(
                T_REJECT,
                &Reason {
                    reason: format!("{} already exists here (different content)", dest.display()),
                },
            )?;
            abort!("rejected {name}: exists with different content");
        }
    }
    if !already {
        ch.send(T_ACCEPT, b"{}")?;
        let part = PathBuf::from(format!("{}.sxfer-part", dest.display()));
        let _ = fs::remove_file(&part);
        let got: R<()> = (|| {
            let mut f = create_new_private(&part)?;
            let t0 = Instant::now();
            let mut n = 0u64;
            loop {
                let (t, b) = ch.recv()?;
                match t {
                    T_DATA => {
                        n += b.len() as u64;
                        if n > h.size {
                            abort!("sender sent more than announced");
                        }
                        f.write_all(&b)?;
                    }
                    T_END => break,
                    _ => abort!("protocol error during data"),
                }
            }
            f.sync_all()?;
            drop(f);
            let (ph, pn) = sha256_file(&part)?; // re-read from disk
            if ph != h.sha256 || pn != h.size {
                abort!(
                    "received copy failed verification ({pn} bytes, sha256 {}...)",
                    &ph[..16]
                );
            }
            say(&format!(
                "received {} bytes from {} ({:.1} MB/s), verified from disk",
                pn,
                h.from,
                pn as f64 / t0.elapsed().as_secs_f64().max(0.001) / 1e6
            ));
            rename_no_clobber(&part, &dest)?;
            if sha256_file(&dest)? != (h.sha256.clone(), h.size) {
                abort!("committed file mismatch");
            }
            Ok(())
        })();
        if let Err(e) = got {
            let _ = fs::remove_file(&part);
            let _ = ch.send_json(
                T_FAIL,
                &Reason {
                    reason: e.0.clone(),
                },
            );
            return Err(e);
        }
    }
    let shown = fs::canonicalize(&dest).unwrap_or(dest.clone());
    let signed = sign_receipt(Some(shown.to_string_lossy().into_owned()), already)?;
    ch.send_json(T_RECEIPT, &signed)?;
    let _ = ch.s.set_read_timeout(Some(DONE_TIMEOUT));
    let shredded = match ch.recv() {
        Ok((T_DONE, b)) => parse_json::<Done>(&b, "done").ok().map(|d| d.shredded),
        _ => None,
    };
    receipt_local(
        &json!({"time": now_iso(), "op": "lan", "from": h.from, "name": h.name,
        "dest": shown.to_string_lossy(), "bytes": h.size, "sha256": h.sha256, "shredded": shredded,
        "sender_fp": sender.fingerprint, "signed_receipt": signed}),
    )?;
    if cfg.remember && !sender.known {
        remember(&sender);
    }
    Ok(Received::File {
        path: shown,
        already,
        shredded,
        sender,
    })
}

/// The rest of a "msg" transfer: policy first (before a byte of it is accepted), then the body,
/// stored in the inbox and read back from disk before the receipt is signed.
fn receive_message(
    mut ch: Chan,
    cfg: &ListenCfg,
    h: &Header,
    sender: PeerInfo,
    peer_addr: SocketAddr,
    sign_receipt: &dyn Fn(Option<String>, bool) -> R<SignedReceipt>,
) -> R<Received> {
    let refuse = |ch: &mut Chan, reason: String| -> R<Received> {
        let _ = ch.send_json(
            T_REJECT,
            &Reason {
                reason: reason.clone(),
            },
        );
        Err(Abort(format!(
            "refused a message from {}: {reason}",
            sender.describe()
        )))
    };
    let Some(inbox) = &cfg.inbox else {
        return refuse(
            &mut ch,
            "this listener doesn't take agent messages (the receiver runs `sxfer serve` for that)"
                .into(),
        );
    };
    if let Err(e) = mesh::check_id(&h.name) {
        return refuse(&mut ch, e.0);
    }
    if h.size > mesh::MAX_MSG {
        return refuse(
            &mut ch,
            format!("message too large (max {} MiB)", mesh::MAX_MSG >> 20),
        );
    }
    if let Some(entry) = inbox.find_delivered(&sender.fingerprint, &h.name) {
        // a retry whose receipt got lost: acknowledge again, but store and trigger nothing
        let signed = sign_receipt(Some(entry.to_string_lossy().into_owned()), true)?;
        ch.send_json(T_RECEIPT, &signed)?;
        let _ = ch.s.set_read_timeout(Some(MSG_DONE_TIMEOUT));
        let _ = ch.recv(); // DONE
        return Ok(Received::Message {
            entry,
            id: h.name.clone(),
            already: true,
            sender,
        });
    }
    if let Err(e) = inbox.admit(&sender.fingerprint) {
        return refuse(&mut ch, e.0);
    }
    ch.send(T_ACCEPT, b"{}")?;
    let data = recv_all_mem(&mut ch, h.size)?;
    let stored = if data.len() as u64 != h.size || sha256_bytes(&data) != h.sha256 {
        Err(Abort("message corrupted in transit".into()))
    } else {
        inbox.store(&sender, peer_addr, &h.name, &data)
    };
    let (entry, already) = match stored {
        Ok(x) => x,
        Err(e) => {
            let _ = ch.send_json(
                T_FAIL,
                &Reason {
                    reason: e.0.clone(),
                },
            );
            return Err(e);
        }
    };
    let signed = sign_receipt(Some(entry.to_string_lossy().into_owned()), already)?;
    ch.send_json(T_RECEIPT, &signed)?;
    let _ = ch.s.set_read_timeout(Some(MSG_DONE_TIMEOUT));
    let _ = ch.recv(); // DONE
    if !already {
        receipt_local(
            &json!({"time": now_iso(), "op": "msg", "from": sender.name, "id": h.name,
            "entry": entry.to_string_lossy(), "bytes": h.size, "sha256": h.sha256,
            "sender_fp": sender.fingerprint, "signed_receipt": signed}),
        )?;
    }
    Ok(Received::Message {
        entry,
        id: h.name.clone(),
        already,
        sender,
    })
}

fn recv_all_mem(ch: &mut Chan, size: u64) -> R<Vec<u8>> {
    let mut v = Vec::new();
    loop {
        let (t, b) = ch.recv()?;
        match t {
            T_DATA => {
                v.extend_from_slice(&b);
                if v.len() as u64 > size {
                    abort!("sender sent more than announced");
                }
            }
            T_END => return Ok(v),
            _ => abort!("protocol error during data"),
        }
    }
}

/// Only a plain file name: no directories, no traversal, no control characters.
pub(crate) fn safe_name(n: &str) -> R<String> {
    let base = n.rsplit(['/', '\\']).next().unwrap_or("");
    if base.is_empty()
        || base == "."
        || base == ".."
        || base.chars().any(|c| c.is_control())
        || base.contains(':')
    {
        abort!("refusing unsafe file name {n:?}");
    }
    Ok(base.to_string())
}

// ---------------------------------------------------------------- sender

pub enum Payload {
    File(PathBuf),
    Text(String),
    /// an agent message (A2A JSON) for a `sxfer serve` inbox; `id` is its messageId
    Message {
        id: String,
        bytes: Vec<u8>,
    },
}

pub struct Sent {
    pub dest_path: Option<String>,
    pub already: bool,
    pub shredded: bool,
    pub listener: PeerInfo,
    /// the listener's ML-DSA-65 signed receipt, already verified
    pub receipt: SignedReceipt,
}

/// How the sender proves it's allowed in.
pub enum Auth {
    /// the listener's one-time code
    Code(String),
    /// no code: both sides pinned, and the listener started with --trusted
    Trusted,
}

pub struct SendOpts<'a> {
    pub auth: Auth,
    pub me: &'a id::Identity,
    /// pin the listener after a successful transfer with the code
    pub remember: bool,
    /// only this listener (fingerprint): anyone else is refused before anything is sent
    pub expect_fp: Option<String>,
}

pub fn send_core(addr: SocketAddr, payload: &Payload, sc: &ShredCfg, o: &SendOpts) -> R<Sent> {
    let (name, kind, h0, n0) = match payload {
        Payload::File(p) => {
            if !p.is_file() {
                abort!("not a regular file: {}", p.display());
            }
            let (h, n) = sha256_file(p)?;
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            say(&format!(
                "1/6 hashed   {}  {n} bytes  sha256 {}...",
                p.display(),
                &h[..16]
            ));
            (name, "file", h, n)
        }
        Payload::Text(t) => (
            String::new(),
            "text",
            sha256_bytes(t.as_bytes()),
            t.len() as u64,
        ),
        Payload::Message { id, bytes } => {
            mesh::check_id(id)?;
            if bytes.len() as u64 > mesh::MAX_MSG {
                abort!("message too large (max {} MiB)", mesh::MAX_MSG >> 20);
            }
            (id.clone(), "msg", sha256_bytes(bytes), bytes.len() as u64)
        }
    };

    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        .map_err(|e| Abort(format!("cannot connect to {addr}: {e}")))?;
    let _ = s.set_read_timeout(Some(IO_TIMEOUT));
    let _ = s.set_write_timeout(Some(IO_TIMEOUT));
    let (mode, password) = match &o.auth {
        Auth::Code(c) => (MODE_CODE, normalize_code(c).into_bytes()),
        Auth::Trusted => (MODE_TRUSTED, NO_CODE.to_vec()),
    };
    let (st, msg_a) = Spake2::<Ed25519Group>::start_a(
        &Password::new(&password),
        &SpakeId::new(ID_SEND),
        &SpakeId::new(ID_LISTEN),
    );
    let (dk, ek) = MlKem768::generate_keypair();
    let first = [MAGIC, &[mode], &msg_a, ek.to_bytes().as_slice()].concat();
    write_frame(&mut s, &first)?;
    let second = read_frame(&mut s).map_err(|e| {
        Abort(format!(
            "listener closed the connection: {e} (both sides need sxfer 0.7+)"
        ))
    })?;
    if second.len() <= CT_LEN {
        abort!("bad handshake");
    }
    let (msg_b, ct) = second.split_at(second.len() - CT_LEN);
    let kem_key = dk
        .decapsulate_slice(ct)
        .map_err(|_| Abort("bad handshake (ML-KEM ciphertext)".into()))?;
    let spake_key = st
        .finish(msg_b)
        .map_err(|_| Abort("bad handshake".into()))?;
    let tr = transcript(&first, &second);
    let mut ch = Chan::new(s, &spake_key, &kem_key, &tr, true);

    ch.send_json(T_HELLO, &Hello::new(o.me, id::CTX_SENDER, &tr)?)?;
    let (t, b) = ch.recv().map_err(|e| {
        if e.0 == BAD_CODE || e.0.starts_with("connection lost") {
            Abort("wrong code (the listener rejected it), or not the listener you meant".into())
        } else {
            e
        }
    })?;
    let hello: Hello = match t {
        T_HELLO => parse_json(&b, "hello")?,
        T_REJECT => abort!(
            "listener refused: {}",
            parse_json::<Reason>(&b, "reason")?.reason
        ),
        _ => abort!("protocol error: expected hello"),
    };
    let fp = hello.verify(id::CTX_LISTENER, &tr)?;
    if let Some(want) = &o.expect_fp {
        if &fp != want {
            abort!(
                "{addr} is {} [{}], not the peer you addressed [{}]; nothing was sent",
                hello.name,
                id::short_fp(&fp),
                id::short_fp(want)
            );
        }
    }
    let pinned = vet(&hello.name, &fp, mode, "listener")?;
    let listener = peer_info(&hello.name, fp, pinned);
    say(&format!("paired with {}", listener.describe()));

    ch.send_json(
        T_HEADER,
        &Header {
            kind: kind.into(),
            name,
            size: n0,
            sha256: h0.clone(),
            from: host_name(),
        },
    )?;
    let (t, b) = ch.recv()?;
    let rcpt: SignedReceipt = match t {
        T_REJECT => abort!(
            "listener refused: {}",
            parse_json::<Reason>(&b, "reason")?.reason
        ),
        T_RECEIPT => parse_json(&b, "receipt")?, // destination already holds this exact file
        T_ACCEPT => {
            let t0 = Instant::now();
            match payload {
                Payload::File(p) => {
                    let mut f = File::open(p)?;
                    let mut buf = vec![0u8; CHUNK];
                    loop {
                        let k = f.read(&mut buf)?;
                        if k == 0 {
                            break;
                        }
                        ch.send(T_DATA, &buf[..k])?;
                    }
                }
                Payload::Text(tx) => ch.send(T_DATA, tx.as_bytes())?,
                Payload::Message { bytes, .. } => {
                    for chunk in bytes.chunks(CHUNK) {
                        ch.send(T_DATA, chunk)?;
                    }
                }
            }
            ch.send(T_END, &[])?;
            if kind == "file" {
                say(&format!(
                    "2/6 sent     -> {addr}  ({:.1} MB/s)",
                    n0 as f64 / t0.elapsed().as_secs_f64().max(0.001) / 1e6
                ));
            }
            let (t, b) = ch
                .recv()
                .map_err(|e| Abort(format!("{e}; no receipt, source kept")))?;
            match t {
                T_RECEIPT => parse_json(&b, "receipt")?,
                T_FAIL => abort!(
                    "listener reported: {}; source kept",
                    parse_json::<Reason>(&b, "reason")?.reason
                ),
                _ => abort!("protocol error: expected receipt"),
            }
        }
        _ => abort!("protocol error: unexpected reply"),
    };
    let body = check_receipt(&rcpt, &listener, o.me, &tr, &h0, n0)?;

    let mut shredded = false;
    if let Payload::File(p) = payload {
        if (sha256_file(p)?) != (h0.clone(), n0) {
            abort!("source changed during transfer; source kept (the listener has the earlier version)");
        }
        let where_ = body.path.clone().unwrap_or_default();
        if body.already {
            say(&format!("2-4/6 listener already holds this exact file at {where_} (earlier run); skipping to shred"));
        } else {
            say("3/6 verified listener's copy (re-read from its disk) matches");
            say(&format!(
                "4/6 committed {where_}  (receipt signed by {}, ML-DSA-65, verified)",
                listener.describe()
            ));
        }
        let question = format!("Receipt confirmed. Shred local {}?", p.display());
        if sc.keep {
            say("5/6 --keep: source left in place");
        } else if sc.confirm(&question) {
            shred_local(p, sc.passes)?;
            shredded = true;
            say(&format!(
                "5/6 shredded  {}  ({} random passes + zeros, renamed, unlinked)",
                p.display(),
                sc.passes
            ));
        } else {
            say("5/6 not shredded (declined)");
        }
    }
    let _ = ch.send_json(T_DONE, &Done { shredded });
    if kind == "file" {
        say("6/6 receipt  logged on the listener (nothing logged here)");
    }
    if o.remember && !listener.known {
        remember(&listener);
    }
    Ok(Sent {
        dest_path: body.path,
        already: body.already,
        shredded,
        listener,
        receipt: rcpt,
    })
}

/// A receipt only counts if the listener we paired with signed it, for this session, about what
/// we sent. Everything is read from the signed body.
fn check_receipt(
    r: &SignedReceipt,
    listener: &PeerInfo,
    me: &id::Identity,
    tr: &[u8; 32],
    sha256: &str,
    size: u64,
) -> R<id::ReceiptBody> {
    let body = r.open().map_err(|e| Abort(format!("{e}; source kept")))?;
    if body.listener_fp() != listener.fingerprint {
        abort!("receipt signed by another key than the listener's; source kept");
    }
    if body.session != hex(tr) || body.sender_fp != me.fingerprint() {
        abort!("receipt is for another session; source kept");
    }
    if body.sha256 != sha256 || body.size != size {
        abort!(
            "RECEIPT MISMATCH: listener has {}/{}, we sent {sha256}/{size}; source kept",
            body.sha256,
            body.size
        );
    }
    Ok(body)
}

// ---------------------------------------------------------------- discovery

#[derive(Debug, Clone)]
pub struct Found {
    pub addrs: Vec<IpAddr>,
    pub port: u16,
    pub name: String,
    pub id: String,
    /// protocol version it speaks ("2" for sxfer 0.7+)
    pub version: String,
    /// its identity fingerprint, as advertised (verified only once paired)
    pub fingerprint: Option<String>,
    /// started with --trusted: pinned senders may skip the code
    pub trusted: bool,
    /// `sxfer serve`: takes agent messages
    pub msg: bool,
}

impl Found {
    /// Pair without a code: it accepts pinned senders and we have pinned the key it advertises.
    pub fn trusted_and_pinned(&self) -> bool {
        self.trusted
            && self
                .fingerprint
                .as_deref()
                .is_some_and(|fp| matches!(id::check_peer(&self.name, fp), id::Known::Yes(_)))
    }
}

impl Found {
    /// The first advertised address inside one of `nets` (IPv4 preferred).
    pub fn addr_in(&self, nets: &[IpNet]) -> Option<SocketAddr> {
        let mut a: Vec<&IpAddr> = self
            .addrs
            .iter()
            .filter(|ip| nets.iter().any(|n| n.contains(*ip)))
            .collect();
        a.sort_by_key(|ip| !ip.is_ipv4());
        a.first().map(|ip| SocketAddr::new(**ip, self.port))
    }

    /// Every advertised address, those inside `nets` first, then IPv4 before IPv6. For a peer
    /// whose key is checked on connect (`SendOpts::expect_fp`), where the allowlist isn't the guard.
    pub fn all_addrs(&self, nets: &[IpNet]) -> Vec<SocketAddr> {
        let mut a: Vec<&IpAddr> = self.addrs.iter().collect();
        a.sort_by_key(|ip| (!nets.iter().any(|n| n.contains(*ip)), !ip.is_ipv4()));
        a.into_iter()
            .map(|ip| SocketAddr::new(*ip, self.port))
            .collect()
    }
}

/// Browse mDNS for `_sxfer._tcp` listeners for `wait`.
pub fn discover(wait: Duration) -> R<Vec<Found>> {
    let daemon = ServiceDaemon::new().map_err(mdns_err)?;
    let rx = daemon.browse(SERVICE).map_err(mdns_err)?;
    let deadline = Instant::now() + wait;
    let mut found: Vec<Found> = Vec::new();
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match rx.recv_timeout(left) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                let id = info
                    .get_property_val_str("id")
                    .unwrap_or_default()
                    .to_string();
                let addrs: Vec<IpAddr> = info
                    .get_addresses()
                    .iter()
                    .map(|a| a.to_ip_addr())
                    .collect();
                if let Some(f) = found.iter_mut().find(|f| f.id == id) {
                    for a in addrs {
                        if !f.addrs.contains(&a) {
                            f.addrs.push(a);
                        }
                    }
                } else {
                    let prop = |k: &str| info.get_property_val_str(k).map(str::to_string);
                    found.push(Found {
                        addrs,
                        port: info.get_port(),
                        name: prop("name").unwrap_or_else(|| "?".into()),
                        id,
                        version: prop("v").unwrap_or_default(),
                        fingerprint: prop("fp"),
                        trusted: prop("trusted").as_deref() == Some("1"),
                        msg: prop("msg").as_deref() == Some("1"),
                    });
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let _ = daemon.stop_browse(SERVICE);
    let _ = daemon.shutdown();
    Ok(found)
}

/// `--to` takes host:port (the listener prints its port); there is no default port.
pub fn resolve_to(to: &str) -> R<SocketAddr> {
    if let Ok(a) = to.parse::<SocketAddr>() {
        return Ok(a);
    }
    if to.parse::<IpAddr>().is_ok() || !to.contains(':') {
        abort!("--to needs host:port, e.g. 192.168.2.50:51234 (the listener shows its port)");
    }
    to.to_socket_addrs()
        .map_err(|e| Abort(format!("cannot resolve {to}: {e}")))?
        .next()
        .ok_or_else(|| Abort(format!("cannot resolve {to}")))
}

/// Best guess at this machine's LAN address (no packets are sent).
pub fn primary_ip() -> Option<IpAddr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    s.local_addr().ok().map(|a| a.ip())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sxfer-test-{tag}-{}", random_hex(4)));
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn sc() -> ShredCfg {
        ShredCfg {
            keep: false,
            ask: false,
            passes: 1,
            asker: None,
        }
    }

    use crate::common::testing::{home as test_home, PINNING};

    /// A fresh identity with a unique name, so tests sharing the trust store don't collide.
    fn ident(role: &str) -> id::Identity {
        test_home();
        id::Identity::from_seed(&id::new_seed(), &format!("{role}-{}", random_hex(4)))
    }

    fn listen_cfg(dir: PathBuf, me: id::Identity) -> ListenCfg {
        test_home();
        let mut cfg = ListenCfg::new("127.0.0.1:0".parse().unwrap(), dir, Arc::new(me));
        cfg.advertise = false;
        cfg
    }

    fn spawn_listener(
        cfg: ListenCfg,
        code: &'static str,
    ) -> (u16, std::thread::JoinHandle<R<Received>>) {
        let (tx, rx) = mpsc::channel();
        let h = std::thread::spawn(move || listen_core(&cfg, code, &mut |p| tx.send(p).unwrap()));
        (rx.recv().unwrap(), h)
    }

    fn start_listener(
        dir: PathBuf,
        code: &'static str,
    ) -> (u16, std::thread::JoinHandle<R<Received>>) {
        spawn_listener(listen_cfg(dir, ident("listener")), code)
    }

    fn send_as(me: &id::Identity, addr: SocketAddr, auth: Auth, payload: &Payload) -> R<Sent> {
        let o = SendOpts {
            auth,
            me,
            remember: false,
            expect_fp: None,
        };
        send_core(addr, payload, &sc(), &o)
    }

    fn send(addr: SocketAddr, code: &str, payload: &Payload) -> R<Sent> {
        send_as(&ident("sender"), addr, Auth::Code(code.into()), payload)
    }

    fn local(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    #[test]
    fn receipt_is_signed_by_the_listener_and_bound_to_the_session() {
        let (src_dir, dst_dir) = (tmpdir("src"), tmpdir("dst"));
        let src = src_dir.join("signed.txt");
        fs::write(&src, b"signed").unwrap();
        let (listener, sender) = (ident("listener"), ident("sender"));
        let listener_fp = listener.fingerprint();
        let (port, h) = spawn_listener(listen_cfg(dst_dir, listener), "654-321");
        let auth = Auth::Code("654-321".into());
        let sent = send_as(&sender, local(port), auth, &Payload::File(src.clone())).unwrap();
        assert_eq!(sent.listener.fingerprint, listener_fp);
        assert!(!sent.listener.known);
        let body = sent.receipt.open().unwrap();
        assert_eq!(body.listener_fp(), listener_fp);
        assert_eq!(body.sender_fp, sender.fingerprint());
        assert_eq!((body.size, body.kind.as_str()), (6, "file"));
        match h.join().unwrap().unwrap() {
            Received::File { sender: s, .. } => assert_eq!(s.fingerprint, sender.fingerprint()),
            _ => panic!("expected a file"),
        }
    }

    #[test]
    fn pinned_peers_pair_without_a_code_on_a_trusted_listener() {
        let _turn = PINNING.lock().unwrap_or_else(|e| e.into_inner());
        let (src_dir, dst_dir) = (tmpdir("src"), tmpdir("dst"));
        let src = src_dir.join("t.txt");
        fs::write(&src, b"trusted").unwrap();
        let (listener, sender) = (ident("listener"), ident("sender"));
        let mut cfg = listen_cfg(dst_dir, listener);
        cfg.trusted = true;
        id::pin(&cfg.me.name, &cfg.me.fingerprint()).unwrap();
        // pinned under the user's own name for it, not the one it claims
        let alias = format!("my-{}", sender.name);
        id::pin(&alias, &sender.fingerprint()).unwrap();
        let (port, h) = spawn_listener(cfg, "999-000");
        let sent = send_as(
            &sender,
            local(port),
            Auth::Trusted,
            &Payload::File(src.clone()),
        );
        let sent = sent.unwrap();
        assert!(sent.listener.known && sent.shredded && !src.exists());
        match h.join().unwrap().unwrap() {
            Received::File { sender: s, .. } => assert_eq!(s.name, alias),
            _ => panic!("expected a file"),
        }
    }

    #[test]
    fn no_code_is_refused_for_unpinned_senders_and_untrusted_listeners() {
        let src_dir = tmpdir("src");
        let src = src_dir.join("u.txt");
        fs::write(&src, b"u").unwrap();
        let mut cfg = listen_cfg(tmpdir("dst"), ident("listener"));
        cfg.trusted = true;
        let stranger = ident("stranger");
        let (port, _h) = spawn_listener(cfg, "121-212");
        let e = send_as(
            &stranger,
            local(port),
            Auth::Trusted,
            &Payload::File(src.clone()),
        );
        let e = e.err().unwrap();
        assert!(e.0.contains("isn't a pinned peer"), "{e}");
        assert!(src.exists());

        let (port, _h) = start_listener(tmpdir("dst"), "343-434"); // not --trusted
        let e = send_as(
            &stranger,
            local(port),
            Auth::Trusted,
            &Payload::File(src.clone()),
        );
        let e = e.err().unwrap();
        assert!(e.0.contains("needs its one-time code"), "{e}");
        assert!(src.exists());
    }

    #[test]
    fn changed_key_is_refused_even_with_the_code() {
        let _turn = PINNING.lock().unwrap_or_else(|e| e.into_inner());
        let src_dir = tmpdir("src");
        let src = src_dir.join("k.txt");
        fs::write(&src, b"k").unwrap();
        let real = ident("laptop");
        id::pin(&real.name, &real.fingerprint()).unwrap();
        let impostor = id::Identity::from_seed(&id::new_seed(), &real.name);
        let (port, _h) = start_listener(tmpdir("dst"), "565-656");
        let auth = Auth::Code("565-656".into());
        let e = send_as(&impostor, local(port), auth, &Payload::File(src.clone()));
        let e = e.err().unwrap();
        assert!(e.0.contains("KEY CHANGED"), "{e}");
        assert!(src.exists());
    }

    #[test]
    fn remember_pins_the_sender_after_a_code_transfer() {
        let _turn = PINNING.lock().unwrap_or_else(|e| e.into_inner());
        let src_dir = tmpdir("src");
        let src = src_dir.join("r.txt");
        fs::write(&src, b"r").unwrap();
        let sender = ident("sender");
        let mut cfg = listen_cfg(tmpdir("dst"), ident("listener"));
        cfg.remember = true;
        let (port, h) = spawn_listener(cfg, "787-878");
        let auth = Auth::Code("787-878".into());
        send_as(&sender, local(port), auth, &Payload::File(src)).unwrap();
        assert!(h.join().unwrap().is_ok());
        let pinned = id::check_peer(&sender.name, &sender.fingerprint());
        assert_eq!(pinned, id::Known::Yes(sender.name.clone()));
    }

    #[test]
    fn file_roundtrip_shreds_source() {
        let (src_dir, dst_dir) = (tmpdir("src"), tmpdir("dst"));
        let src = src_dir.join("data.bin");
        let mut data = vec![0u8; 3 * CHUNK + 123];
        rand::rngs::OsRng.fill(&mut data[..]);
        fs::write(&src, &data).unwrap();
        let (port, h) = start_listener(dst_dir.clone(), "123-456");
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let sent = send(addr, "123456", &Payload::File(src.clone())).unwrap();
        assert!(sent.shredded && !sent.already);
        assert!(!src.exists(), "source must be shredded");
        assert_eq!(fs::read(dst_dir.join("data.bin")).unwrap(), data);
        assert!(!dst_dir.join("data.bin.sxfer-part").exists());
        assert!(matches!(
            h.join().unwrap().unwrap(),
            Received::File {
                shredded: Some(true),
                ..
            }
        ));
    }

    #[test]
    fn wrong_code_keeps_source_then_right_code_works() {
        let (src_dir, dst_dir) = (tmpdir("src"), tmpdir("dst"));
        let src = src_dir.join("a.txt");
        fs::write(&src, b"hello").unwrap();
        let (port, h) = start_listener(dst_dir.clone(), "111-222");
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let e = send(addr, "999-999", &Payload::File(src.clone()))
            .err()
            .unwrap();
        assert!(e.0.contains("wrong code"), "{e}");
        assert!(src.exists());
        assert!(!dst_dir.join("a.txt").exists());
        send(addr, "111-222", &Payload::File(src.clone())).unwrap();
        assert!(!src.exists());
        assert!(h.join().unwrap().is_ok());
    }

    #[test]
    fn three_wrong_codes_close_the_listener() {
        let (port, h) = start_listener(tmpdir("dst"), "000-001");
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        for _ in 0..3 {
            assert!(send(addr, "123-123", &Payload::Text("x".into())).is_err());
        }
        assert!(h.join().unwrap().err().unwrap().0.contains("wrong codes"));
    }

    #[test]
    fn files_only_listener_refuses_secrets_and_can_be_stopped() {
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let (dir, flag) = (tmpdir("dst"), stop.clone());
        let h = std::thread::spawn(move || {
            let mut cfg = listen_cfg(dir, ident("listener"));
            cfg.accept_text = false;
            cfg.stop = Some(flag);
            listen_core(&cfg, "321-321", &mut |p| tx.send(p).unwrap())
        });
        let port = rx.recv().unwrap();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let e = send(addr, "321-321", &Payload::Text("hunter2".into()))
            .err()
            .unwrap();
        assert!(e.0.contains("files only"), "{e}");
        stop.store(true, Ordering::Relaxed);
        assert!(h.join().unwrap().err().unwrap().0.contains("stopped"));
    }

    #[test]
    fn secret_text_is_delivered_not_written() {
        let dst = tmpdir("dst");
        let (port, h) = start_listener(dst.clone(), "555-555");
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        send(addr, "555555", &Payload::Text("hunter2 OTP 482913".into())).unwrap();
        match h.join().unwrap().unwrap() {
            Received::Text { text, .. } => assert_eq!(text, "hunter2 OTP 482913"),
            _ => panic!("expected text"),
        }
        assert_eq!(
            fs::read_dir(&dst).unwrap().count(),
            0,
            "secrets must not touch the disk"
        );
    }

    #[test]
    fn existing_identical_file_counts_as_delivered() {
        let (src_dir, dst_dir) = (tmpdir("src"), tmpdir("dst"));
        let src = src_dir.join("same.txt");
        fs::write(&src, b"same").unwrap();
        fs::write(dst_dir.join("same.txt"), b"same").unwrap();
        let (port, h) = start_listener(dst_dir, "222-333");
        let sent = send(
            format!("127.0.0.1:{port}").parse().unwrap(),
            "222-333",
            &Payload::File(src.clone()),
        )
        .unwrap();
        assert!(sent.already && sent.shredded && !src.exists());
        assert!(h.join().unwrap().is_ok());
    }

    #[test]
    fn existing_different_file_is_refused_and_source_kept() {
        let (src_dir, dst_dir) = (tmpdir("src"), tmpdir("dst"));
        let src = src_dir.join("x.txt");
        fs::write(&src, b"new").unwrap();
        fs::write(dst_dir.join("x.txt"), b"old").unwrap();
        let (port, _h) = start_listener(dst_dir.clone(), "444-444");
        let e = send(
            format!("127.0.0.1:{port}").parse().unwrap(),
            "444-444",
            &Payload::File(src.clone()),
        )
        .err()
        .unwrap();
        assert!(e.0.contains("refused"), "{e}");
        assert!(src.exists());
        assert_eq!(fs::read(dst_dir.join("x.txt")).unwrap(), b"old");
    }

    /// Real multicast on this machine's interfaces: run with `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn mdns_discovery_finds_listener() {
        std::env::set_var("SXFER_HOME", std::env::temp_dir().join("sxfer-test-home"));
        let (tx, rx) = mpsc::channel();
        let dir = tmpdir("dst");
        std::thread::spawn(move || {
            let cfg = ListenCfg::new(
                "0.0.0.0:0".parse().unwrap(),
                dir,
                Arc::new(ident("listener")),
            );
            listen_core(&cfg, "777-777", &mut |p| tx.send(p).unwrap())
        });
        let port = rx.recv().unwrap();
        let found = discover(Duration::from_secs(3)).unwrap();
        let me = found.iter().find(|f| f.port == port);
        assert!(
            me.is_some(),
            "listener on port {port} not found in {found:?}"
        );
        assert!(!me.unwrap().addrs.is_empty());
    }

    #[test]
    fn allowlist_picks_address_inside_configured_networks() {
        let f = Found {
            addrs: vec![
                "fe80::1".parse().unwrap(),
                "172.17.0.1".parse().unwrap(),
                "192.168.2.50".parse().unwrap(),
            ],
            port: 50123,
            name: "x".into(),
            id: "1".into(),
            version: "2".into(),
            fingerprint: None,
            trusted: false,
            msg: false,
        };
        let lan: Vec<IpNet> = vec!["192.168.2.0/24".parse().unwrap()];
        assert_eq!(f.addr_in(&lan), Some("192.168.2.50:50123".parse().unwrap()));
        let other: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        assert_eq!(f.addr_in(&other), None);
    }

    #[test]
    fn unsafe_names_are_refused() {
        for n in ["", "..", "../../etc/passwd", "C:evil", "a\nb"] {
            let r = safe_name(n);
            assert!(
                r.is_err() || !r.as_ref().unwrap().contains(".."),
                "{n:?} -> {r:?}"
            );
        }
        assert_eq!(safe_name("../../etc/passwd").unwrap(), "passwd");
        assert_eq!(safe_name("dir\\file.txt").unwrap(), "file.txt");
    }
}
