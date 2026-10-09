//! Direct LAN transfer, no SSH: `sxfer listen` on the receiver, `sxfer send` on the sender.
//!
//! DISCOVERY  sender sends a UDP probe "SXFER1?" to every host in its configured networks (plus
//!            each network's broadcast address); listeners answer "SXFER1!" + {name, port, id}.
//! HANDSHAKE  TCP. SPAKE2 (Ed25519 group) keyed by the listener's one-time code: the code never
//!            crosses the wire, an eavesdropper can't test guesses offline, and an active attacker
//!            gets one guess per connection (the listener allows 3, then closes).
//! CHANNEL    HKDF-SHA256(spake key) -> one ChaCha20-Poly1305 key per direction, counter nonces.
//!            A wrong code shows up as the first frame failing to authenticate.
//! TRANSFER   header {kind, name, size, sha256} -> ACCEPT/REJECT -> data frames -> END.
//!            The listener writes <name>.sxfer-part, fsyncs, re-reads it FROM DISK, checks size +
//!            sha256, commits with a no-clobber rename and replies RECEIPT. Only then does the
//!            sender (re-hashing its source first) shred, and tells the listener it did (DONE).
//!            Secrets (kind "text") are shown on the listener's screen and never written to disk.
//! RECEIPTS   on the destination only (the listener). The sender keeps no record.

use crate::abort;
use crate::common::*;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use ipnet::IpNet;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const PORT: u16 = 47331;
const MAGIC: &[u8] = b"SXFER1";
const PROBE: &[u8] = b"SXFER1?";
const ANSWER: &[u8] = b"SXFER1!";
const ID_SEND: &[u8] = b"sxfer-send";
const ID_LISTEN: &[u8] = b"sxfer-listen";
const MAX_FRAME: usize = 4 << 20;
const MAX_TEXT: u64 = 64 * 1024;
const MAX_HOSTS_PER_NET: usize = 4096;
const MAX_BAD_CODES: u32 = 3;
const IO_TIMEOUT: Duration = Duration::from_secs(120);

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

#[derive(Serialize, Deserialize, Debug)]
struct Receipt {
    sha256: String,
    size: u64,
    path: Option<String>,
    already: bool,
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
    fn new(s: TcpStream, spake_key: &[u8], sender: bool) -> Chan {
        let hk = Hkdf::<Sha256>::new(Some(b"sxfer-lan-v1"), spake_key);
        let mut okm = [0u8; 64];
        hk.expand(b"chacha20poly1305 send|listen", &mut okm)
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
    },
    Text {
        from: String,
        text: String,
    },
}

pub struct ListenCfg {
    pub bind: SocketAddr,
    pub dir: PathBuf,
}

/// Answer discovery probes until `stop` is set.
fn spawn_responder(udp: UdpSocket, name: String, port: u16, id: String, stop: Arc<AtomicBool>) {
    std::thread::spawn(move || {
        let _ = udp.set_read_timeout(Some(Duration::from_millis(300)));
        let mut buf = [0u8; 64];
        let answer = [
            ANSWER,
            json!({"name": name, "port": port, "id": id})
                .to_string()
                .as_bytes(),
        ]
        .concat();
        while !stop.load(Ordering::Relaxed) {
            if let Ok((n, from)) = udp.recv_from(&mut buf) {
                if &buf[..n] == PROBE {
                    let _ = udp.send_to(&answer, from);
                }
            }
        }
    });
}

/// Wait for one successful transfer with `code`. `ready` is called with the bound TCP port.
pub fn listen_core(cfg: &ListenCfg, code: &str, ready: &mut dyn FnMut(u16)) -> R<Received> {
    let tcp = TcpListener::bind(cfg.bind)
        .map_err(|e| Abort(format!("cannot listen on {}: {e}", cfg.bind)))?;
    let port = tcp.local_addr()?.port();
    let stop = Arc::new(AtomicBool::new(false));
    match UdpSocket::bind(SocketAddr::new(cfg.bind.ip(), port)) {
        Ok(udp) => spawn_responder(udp, host_name(), port, random_hex(4), stop.clone()),
        Err(e) => say(&format!(
            "discovery disabled (UDP {port}: {e}); senders must use --to"
        )),
    }
    ready(port);
    let code = normalize_code(code);
    let mut bad = 0;
    let result = loop {
        let (stream, peer) = match tcp.accept() {
            Ok(x) => x,
            Err(e) => {
                say(&format!("accept failed: {e}"));
                continue;
            }
        };
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        match handle(stream, &code, &cfg.dir) {
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
    stop.store(true, Ordering::Relaxed);
    result
}

fn handle(mut s: TcpStream, code: &str, dir: &Path) -> R<Received> {
    let first = read_frame(&mut s)?;
    let Some(msg_a) = first.strip_prefix(MAGIC) else {
        abort!("not an sxfer sender")
    };
    let (st, msg_b) = Spake2::<Ed25519Group>::start_b(
        &Password::new(code.as_bytes()),
        &Identity::new(ID_SEND),
        &Identity::new(ID_LISTEN),
    );
    write_frame(&mut s, &msg_b)?;
    let key = st
        .finish(msg_a)
        .map_err(|_| Abort("bad handshake".into()))?;
    let mut ch = Chan::new(s, &key, false);

    let (t, body) = ch.recv()?; // BAD_CODE surfaces here
    if t != T_HEADER {
        abort!("protocol error: expected header");
    }
    let h: Header = parse_json(&body, "header")?;

    if h.kind == "text" {
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
        ch.send_json(
            T_RECEIPT,
            &Receipt {
                sha256: h.sha256.clone(),
                size: h.size,
                path: None,
                already: false,
            },
        )?;
        let _ = ch.recv(); // DONE (nothing to log for secrets)
        let text = String::from_utf8_lossy(&data).into_owned();
        return Ok(Received::Text { from: h.from, text });
    }
    if h.kind != "file" {
        abort!("unknown kind {:?}", h.kind);
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
    ch.send_json(
        T_RECEIPT,
        &Receipt {
            sha256: h.sha256.clone(),
            size: h.size,
            path: Some(shown.to_string_lossy().into_owned()),
            already,
        },
    )?;
    let shredded = match ch.recv() {
        Ok((T_DONE, b)) => parse_json::<Done>(&b, "done").ok().map(|d| d.shredded),
        _ => None,
    };
    receipt_local(
        &json!({"time": now_iso(), "op": "lan", "from": h.from, "name": h.name,
        "dest": shown.to_string_lossy(), "bytes": h.size, "sha256": h.sha256, "shredded": shredded}),
    )?;
    Ok(Received::File {
        path: shown,
        already,
        shredded,
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
fn safe_name(n: &str) -> R<String> {
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
}

pub struct Sent {
    #[allow(dead_code)] // read by the tests and handy for callers
    pub dest_path: Option<String>,
    #[allow(dead_code)]
    pub already: bool,
    pub shredded: bool,
}

pub fn send_core(addr: SocketAddr, code: &str, payload: &Payload, sc: &ShredCfg) -> R<Sent> {
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
    };

    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        .map_err(|e| Abort(format!("cannot connect to {addr}: {e}")))?;
    let _ = s.set_read_timeout(Some(IO_TIMEOUT));
    let _ = s.set_write_timeout(Some(IO_TIMEOUT));
    let (st, msg_a) = Spake2::<Ed25519Group>::start_a(
        &Password::new(normalize_code(code).as_bytes()),
        &Identity::new(ID_SEND),
        &Identity::new(ID_LISTEN),
    );
    write_frame(&mut s, &[MAGIC, &msg_a].concat())?;
    let msg_b =
        read_frame(&mut s).map_err(|e| Abort(format!("listener closed the connection: {e}")))?;
    let key = st
        .finish(&msg_b)
        .map_err(|_| Abort("bad handshake".into()))?;
    let mut ch = Chan::new(s, &key, true);

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
    let (t, b) = ch.recv().map_err(|e| {
        if e.0 == BAD_CODE || e.0.starts_with("connection lost") {
            Abort("wrong code (the listener rejected it), or not the listener you meant".into())
        } else {
            e
        }
    })?;
    let rcpt: Receipt = match t {
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
    if rcpt.sha256 != h0 || rcpt.size != n0 {
        abort!(
            "RECEIPT MISMATCH: listener has {}/{}, we sent {h0}/{n0}; source kept",
            rcpt.sha256,
            rcpt.size
        );
    }

    let mut shredded = false;
    if let Payload::File(p) = payload {
        if (sha256_file(p)?) != (h0.clone(), n0) {
            abort!("source changed during transfer; source kept (the listener has the earlier version)");
        }
        let where_ = rcpt.path.clone().unwrap_or_default();
        if rcpt.already {
            say(&format!("2-4/6 listener already holds this exact file at {where_} (earlier run); skipping to shred"));
        } else {
            say("3/6 verified listener's copy (re-read from its disk) matches");
            say(&format!("4/6 committed {where_}  (receipt confirmed)"));
        }
        if sc.keep {
            say("5/6 --keep: source left in place");
        } else if confirm(
            &format!("Receipt confirmed. Shred local {}?", p.display()),
            sc.ask,
        ) {
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
    Ok(Sent {
        dest_path: rcpt.path,
        already: rcpt.already,
        shredded,
    })
}

// ---------------------------------------------------------------- discovery

#[derive(Debug, Clone)]
pub struct Found {
    pub addr: SocketAddr,
    pub name: String,
    pub id: String,
}

pub fn discover(nets: &[IpNet], port: u16, wait: Duration) -> R<Vec<Found>> {
    let udp = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))?;
    let _ = udp.set_broadcast(true);
    for net in nets {
        let IpNet::V4(n4) = net else {
            say(&format!(
                "skipping {net}: IPv6 discovery isn't supported (use --to)"
            ));
            continue;
        };
        let mut targets: Vec<IpAddr> = if n4.prefix_len() >= 31 {
            vec![IpAddr::V4(n4.addr())]
        } else {
            n4.hosts().take(MAX_HOSTS_PER_NET).map(IpAddr::V4).collect()
        };
        if n4.prefix_len() < 31 {
            targets.push(IpAddr::V4(n4.broadcast()));
        }
        if (1u64 << (32 - n4.prefix_len() as u32)) > MAX_HOSTS_PER_NET as u64 + 2 {
            say(&format!(
                "{net} is large; probing its first {MAX_HOSTS_PER_NET} hosts plus broadcast"
            ));
        }
        for ip in targets {
            let _ = udp.send_to(PROBE, SocketAddr::new(ip, port));
        }
    }
    let deadline = Instant::now() + wait;
    let mut found: Vec<Found> = Vec::new();
    let mut buf = [0u8; 512];
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        if left.is_zero() {
            break;
        }
        let _ = udp.set_read_timeout(Some(left));
        match udp.recv_from(&mut buf) {
            Ok((n, from)) => {
                if let Some(js) = buf[..n].strip_prefix(ANSWER) {
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(js) {
                        let id = v["id"].as_str().unwrap_or("").to_string();
                        if found.iter().any(|f| f.id == id) {
                            continue; // same listener answering on another address
                        }
                        let p = v["port"].as_u64().unwrap_or(port as u64) as u16;
                        found.push(Found {
                            addr: SocketAddr::new(from.ip(), p),
                            name: v["name"].as_str().unwrap_or("?").to_string(),
                            id,
                        });
                    }
                }
            }
            // Windows reports ICMP "port unreachable" from earlier probes as a reset here; ignore it
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
            Err(_) => break,
        }
    }
    Ok(found)
}

pub fn resolve_to(to: &str, port: u16) -> R<SocketAddr> {
    let with_port = if to.parse::<IpAddr>().is_ok() || !to.contains(':') {
        format!("{to}:{port}")
    } else {
        to.to_string()
    };
    let with_port = if let Ok(IpAddr::V6(v6)) = to.parse::<IpAddr>() {
        format!("[{v6}]:{port}")
    } else {
        with_port
    };
    with_port
        .to_socket_addrs()
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
        }
    }

    fn start_listener(
        dir: PathBuf,
        code: &'static str,
    ) -> (u16, std::thread::JoinHandle<R<Received>>) {
        std::env::set_var("SXFER_HOME", std::env::temp_dir().join("sxfer-test-home"));
        let (tx, rx) = mpsc::channel();
        let h = std::thread::spawn(move || {
            let cfg = ListenCfg {
                bind: "127.0.0.1:0".parse().unwrap(),
                dir,
            };
            listen_core(&cfg, code, &mut |p| tx.send(p).unwrap())
        });
        (rx.recv().unwrap(), h)
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
        let sent = send_core(addr, "123456", &Payload::File(src.clone()), &sc()).unwrap();
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
        let e = send_core(addr, "999-999", &Payload::File(src.clone()), &sc())
            .err()
            .unwrap();
        assert!(e.0.contains("wrong code"), "{e}");
        assert!(src.exists());
        assert!(!dst_dir.join("a.txt").exists());
        send_core(addr, "111-222", &Payload::File(src.clone()), &sc()).unwrap();
        assert!(!src.exists());
        assert!(h.join().unwrap().is_ok());
    }

    #[test]
    fn three_wrong_codes_close_the_listener() {
        let (port, h) = start_listener(tmpdir("dst"), "000-001");
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        for _ in 0..3 {
            assert!(send_core(addr, "123-123", &Payload::Text("x".into()), &sc()).is_err());
        }
        assert!(h.join().unwrap().err().unwrap().0.contains("wrong codes"));
    }

    #[test]
    fn secret_text_is_delivered_not_written() {
        let dst = tmpdir("dst");
        let (port, h) = start_listener(dst.clone(), "555-555");
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        send_core(
            addr,
            "555555",
            &Payload::Text("hunter2 OTP 482913".into()),
            &sc(),
        )
        .unwrap();
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
        let sent = send_core(
            format!("127.0.0.1:{port}").parse().unwrap(),
            "222-333",
            &Payload::File(src.clone()),
            &sc(),
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
        let e = send_core(
            format!("127.0.0.1:{port}").parse().unwrap(),
            "444-444",
            &Payload::File(src.clone()),
            &sc(),
        )
        .err()
        .unwrap();
        assert!(e.0.contains("refused"), "{e}");
        assert!(src.exists());
        assert_eq!(fs::read(dst_dir.join("x.txt")).unwrap(), b"old");
    }

    #[test]
    fn discovery_finds_listener() {
        let (port, _h) = start_listener(tmpdir("dst"), "777-777");
        let found = discover(
            &["127.0.0.1/32".parse().unwrap()],
            port,
            Duration::from_millis(800),
        )
        .unwrap();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].addr.port(), port);
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
