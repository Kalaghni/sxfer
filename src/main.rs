//! sxfer - move a file or a secret between machines: encrypted transfer, proven receipt, then
//! shred the source. Two transports:
//!   LAN  `sxfer listen` / `sxfer send`  direct TCP, paired by a one-time code (SPAKE2) plus
//!                                       ML-KEM-768; peers and receipts signed with ML-DSA-65
//!   SSH  `sxfer push` / `sxfer pull`    over your ssh client and its config
//! and agent messaging between pinned machines on top of LAN: `sxfer serve` keeps an inbox,
//! `sxfer msg` sends and replies, `sxfer inbox` reads (see mesh.rs).
//!
//! SHRED CAVEAT: overwriting is reliable on spinning disks. On SSDs, copy-on-write or journaling
//! filesystems, cloud-synced folders, snapshots and backups, old copies can survive. Full-disk
//! encryption (BitLocker / FileVault / LUKS) is what really protects deleted data there.

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::fs;
use std::io::{IsTerminal, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;
use sxfer::common::*;
use sxfer::identity::{self as id, Identity, Known, SignedReceipt};
use sxfer::mesh::{self, Inbox};
use sxfer::{config, lan, ssh};

#[derive(Parser)]
#[command(
    name = "sxfer",
    version,
    about = "Move a file or a secret between machines: encrypted, proven receipt, then shred the source."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone)]
struct ShredOpts {
    /// Verify and commit, but don't shred the source
    #[arg(long)]
    keep: bool,
    /// Shred without asking this time (overrides `sxfer config confirm on`, the default)
    #[arg(long, short = 'y', conflicts_with = "ask")]
    yes: bool,
    /// Ask before shredding this time (overrides `sxfer config confirm off`)
    #[arg(long)]
    ask: bool,
    /// Random overwrite passes before the final zero pass
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u32).range(1..))]
    passes: u32,
}

impl ShredOpts {
    fn cfg(&self) -> ShredCfg {
        ShredCfg {
            keep: self.keep,
            ask: resolve_ask(self.yes, self.ask, config::load().confirm_shred()),
            passes: self.passes,
            asker: None,
        }
    }
}

/// A flag decides for this run; otherwise the configured setting (default: ask).
fn resolve_ask(yes: bool, ask: bool, configured: bool) -> bool {
    !yes && (ask || configured)
}

#[derive(Clone, Copy, ValueEnum)]
enum Toggle {
    On,
    Off,
}

#[derive(Subcommand)]
enum Cmd {
    /// Receive over the LAN: shows a one-time code and waits for `sxfer send`
    Listen {
        /// Where received files are saved
        #[arg(long, default_value = ".")]
        dir: PathBuf,
        /// Also accept pinned senders without the code (see `sxfer trust`)
        #[arg(long)]
        trusted: bool,
        /// After a transfer with the code, pin the sender so it can skip the code next time
        #[arg(long)]
        remember: bool,
    },
    /// Send a file over the LAN - or, with no FILE, a secret you type (shown once on the listener, never saved)
    Send {
        file: Option<PathBuf>,
        /// Listener as host:port, as printed by `sxfer listen` (skips mDNS discovery)
        #[arg(long)]
        to: Option<String>,
        /// One-time code (otherwise you're asked, unless the listener is pinned and --trusted)
        #[arg(long, conflicts_with = "no_code")]
        code: Option<String>,
        /// Pair without a code: the listener must be pinned and started with --trusted
        #[arg(long)]
        no_code: bool,
        /// After a transfer with the code, pin the listener so you can skip the code next time
        #[arg(long)]
        remember: bool,
        /// Save the listener's signed receipt here (check it with `sxfer receipt verify`)
        #[arg(long)]
        receipt: Option<PathBuf>,
        #[command(flatten)]
        shred: ShredOpts,
    },
    /// Networks `send` will connect to (an allowlist), and whether shredding asks first
    Config {
        #[command(subcommand)]
        action: ConfigCmd,
    },
    /// Over SSH: copy a local file to host:path, verify, shred the local copy
    Push {
        src: PathBuf,
        /// host:path (any ssh alias works)
        dest: String,
        #[command(flatten)]
        shred: ShredOpts,
    },
    /// Over SSH: copy host:file here, verify, shred the remote copy
    Pull {
        /// host:file
        src: String,
        dest: PathBuf,
        #[command(flatten)]
        shred: ShredOpts,
    },
    /// This machine's post-quantum identity (ML-DSA-65): its name and fingerprint
    Id,
    /// Pinned peers: machines that may pair without a code, and whose key changes are refused
    Trust {
        #[command(subcommand)]
        action: TrustCmd,
    },
    /// Signed receipts from listeners
    Receipt {
        #[command(subcommand)]
        action: ReceiptCmd,
    },
    /// ML-DSA-65 signatures over files, e.g. release checksums (OpenSSL 3.5+ can verify them too)
    Sig {
        #[command(subcommand)]
        action: SigCmd,
    },
    /// Keep an inbox open for agent messages from pinned peers (runs until stopped)
    Serve(ServeArgs),
    /// Send agent messages to pinned peers, reply to them, and see what's queued
    Msg {
        #[command(subcommand)]
        action: MsgCmd,
    },
    /// Read the messages `sxfer serve` received
    Inbox {
        #[command(subcommand)]
        action: InboxCmd,
    },
}

#[derive(Args)]
struct ServeArgs {
    /// Where messages are kept (default ~/.sxfer/inbox)
    #[arg(long)]
    inbox: Option<PathBuf>,
    /// Also take files from pinned peers (`sxfer send --no-code`), saved here
    #[arg(long)]
    files: Option<PathBuf>,
    /// TCP port (default: the one used last time, else any free port)
    #[arg(long)]
    port: Option<u16>,
    /// Listen on this address only, e.g. a VPN interface's (default: all)
    #[arg(long, default_value = "0.0.0.0")]
    bind: std::net::IpAddr,
    /// Don't advertise over mDNS (peers then need `sxfer trust addr`)
    #[arg(long)]
    no_mdns: bool,
    /// Run this for each new message, with SXFER_MSG_ID, SXFER_FROM, SXFER_INTENT, ... set.
    /// Exit 0 moves the message to done/
    #[arg(long, value_name = "COMMAND")]
    on_receive: Option<String>,
    /// How many --on-receive commands may run at once
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=32))]
    jobs: u32,
    /// Also run --on-receive for messages already waiting when serve starts
    #[arg(long, requires = "on_receive")]
    replay: bool,
    /// Refuse messages passed on more than this many times (stops agents replying forever)
    #[arg(long, default_value_t = mesh::MAX_HOPS)]
    max_hops: u32,
    /// Messages accepted per sender per minute
    #[arg(long, default_value_t = mesh::RATE_PER_MIN, value_parser = clap::value_parser!(u32).range(1..))]
    rate: u32,
}

/// What goes into a message, for send and reply.
#[derive(Args)]
struct Compose {
    /// The message body (markdown); `-` or no file reads stdin when it's piped
    file: Option<PathBuf>,
    #[arg(long, short)]
    subject: Option<String>,
    /// handoff, request, result, note, or anything your agents agree on
    #[arg(long, short)]
    intent: Option<String>,
    /// Attach a file (repeatable; up to 16 MiB in all - use `sxfer send` for big ones)
    #[arg(long, short)]
    attach: Vec<PathBuf>,
    /// Structured data for the receiving agent, as JSON
    #[arg(long)]
    data: Option<String>,
    /// Fail rather than queue when the peer can't be reached
    #[arg(long)]
    no_queue: bool,
    /// Print the result as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand)]
enum MsgCmd {
    /// Send a message to a pinned peer's `sxfer serve`
    Send {
        /// Pinned peer name or fingerprint
        peer: String,
        #[command(flatten)]
        c: Compose,
        /// Thread (A2A contextId) to continue; a new one otherwise
        #[arg(long)]
        thread: Option<String>,
        /// The file is a complete A2A Message (JSON); send it as is
        #[arg(long)]
        a2a: bool,
        /// Hand the file over: shred it once the peer has verifiably received it
        #[arg(long = "move", conflicts_with_all = ["a2a"])]
        move_: bool,
        /// With --move, shred without asking
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Reply to a message in the inbox: same thread, back to its sender
    Reply {
        /// Message id (or its start), as `sxfer inbox list` shows
        id: String,
        #[command(flatten)]
        c: Compose,
        /// Also move the original to done/
        #[arg(long)]
        done: bool,
    },
    /// Pinned peers and whether their `sxfer serve` answers on this network
    Peers {
        #[arg(long)]
        json: bool,
    },
    /// Messages waiting to be delivered
    Outbox {
        #[arg(long)]
        json: bool,
    },
    /// Try to deliver everything in the outbox now
    Flush,
}

#[derive(Subcommand)]
enum InboxCmd {
    /// Messages waiting to be handled (--all: handled ones too)
    List {
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
    },
    /// Show a message: its verified sender, then its content
    Read {
        id: String,
        /// The whole entry, A2A message included, as JSON
        #[arg(long)]
        json: bool,
    },
    /// Wait for a message to handle, then show it (exit 2 on timeout)
    Wait {
        /// Give up after this many seconds (default: wait forever)
        #[arg(long)]
        timeout: Option<u64>,
        /// Ignore messages already waiting
        #[arg(long)]
        new: bool,
        #[arg(long)]
        json: bool,
    },
    /// Mark messages handled (moves them to done/)
    Done {
        #[arg(required = true)]
        ids: Vec<String>,
    },
    /// Write a message's attachments into a folder
    Save {
        id: String,
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Add a network or single address, e.g. 192.168.2.0/24 or 192.168.2.50
    Add { net: String },
    /// Remove a network
    Remove { net: String },
    /// Show configured networks and the shred-confirmation setting
    List,
    /// Ask before shredding (on, the default) or shred once receipt is confirmed (off). No value: show it
    Confirm { state: Option<Toggle> },
}

#[derive(Subcommand)]
enum TrustCmd {
    /// Show pinned peers
    List,
    /// Pin a peer by the fingerprint `sxfer id` shows on it (compare it in person or by phone)
    Add { name: String, fingerprint: String },
    /// Unpin a peer, by name or fingerprint
    Remove { peer: String },
    /// Where a peer's `sxfer serve` listens (host:port), for networks mDNS doesn't cross (VPNs)
    Addr {
        peer: String,
        /// host:port; leave out to show it
        addr: Option<String>,
        /// Forget the address (use mDNS again)
        #[arg(long, conflicts_with = "addr")]
        clear: bool,
    },
}

#[derive(Subcommand)]
enum ReceiptCmd {
    /// Check a receipt saved with `send --receipt`: the signature, who signed it, and optionally the file
    Verify {
        receipt: PathBuf,
        /// Also check that this file is the one the receipt is about (SHA-256 and size)
        #[arg(long)]
        file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum SigCmd {
    /// Make a signing key (secret seed, mode 600) and write its public key to <KEY>.pub.pem
    Keygen { key: PathBuf },
    /// Sign FILE with KEY into FILE.sig (raw ML-DSA-65 signature, empty context)
    Sign {
        file: PathBuf,
        #[arg(long)]
        key: PathBuf,
    },
    /// Verify FILE against its signature and an SPKI PEM public key
    Verify {
        file: PathBuf,
        /// Signature file (default: FILE.sig)
        #[arg(long)]
        sig: Option<PathBuf>,
        #[arg(long)]
        pubkey: PathBuf,
    },
}

fn main() {
    with_big_stack(run)
}

fn run() {
    let cli = Cli::parse();
    let r = match cli.cmd {
        Cmd::Listen {
            dir,
            trusted,
            remember,
        } => listen(dir, trusted, remember),
        Cmd::Send {
            file,
            to,
            code,
            no_code,
            remember,
            receipt,
            shred,
        } => send(SendArgs {
            file,
            to,
            code,
            no_code,
            remember,
            receipt,
            sc: shred.cfg(),
        }),
        Cmd::Config { action } => match action {
            ConfigCmd::Add { net } => config::add(&net),
            ConfigCmd::Remove { net } => config::remove(&net),
            ConfigCmd::List => {
                config::list();
                Ok(())
            }
            ConfigCmd::Confirm { state } => config::confirm(state.map(|t| matches!(t, Toggle::On))),
        },
        Cmd::Push { src, dest, shred } => ssh::push(&src, &dest, &shred.cfg()).map(|_| ()),
        Cmd::Pull { src, dest, shred } => ssh::pull(&src, &dest, &shred.cfg()).map(|_| ()),
        Cmd::Id => show_id(),
        Cmd::Trust { action } => trust(action),
        Cmd::Receipt {
            action: ReceiptCmd::Verify { receipt, file },
        } => verify_receipt(&receipt, file.as_deref()),
        Cmd::Sig { action } => sig(action),
        Cmd::Serve(a) => serve(a),
        Cmd::Msg { action } => msg(action),
        Cmd::Inbox { action } => inbox(action),
    };
    if let Err(e) = r {
        say(&format!("ABORTED: {e}"));
        std::process::exit(1);
    }
}

fn listen(dir: PathBuf, trusted: bool, remember: bool) -> R<()> {
    if !dir.is_dir() {
        sxfer::abort!("no such directory: {}", dir.display());
    }
    let me = Arc::new(Identity::load_or_create()?);
    let code = lan::new_code();
    let shown_dir = std::fs::canonicalize(&dir).unwrap_or(dir.clone());
    // any free port; mDNS tells senders which
    let mut cfg = lan::ListenCfg::new(SocketAddr::from(([0, 0, 0, 0], 0)), dir, Arc::clone(&me));
    cfg.trusted = trusted;
    cfg.remember = remember;
    let got = lan::listen_core(&cfg, &code, &mut |p| {
        let ip = lan::primary_ip()
            .map(|i| i.to_string())
            .unwrap_or_else(|| "this machine".into());
        say(&format!(
            "listening on {ip}:{p} as {} [{}], advertised over mDNS  (files -> {})",
            me.name,
            id::short_fp(&me.fingerprint()),
            shown_dir.display()
        ));
        eprintln!();
        eprintln!("    one-time code:  {code}");
        eprintln!();
        say("give the sender this code; it works once (3 wrong tries closes the listener). Ctrl+C to cancel.");
        if trusted {
            say("--trusted: pinned senders may also connect without the code");
        }
    })?;
    match got {
        lan::Received::File {
            path,
            already,
            shredded,
            sender,
        } => {
            say(&format!(
                "{} {}  (from {}, which {})",
                if already { "already had" } else { "received" },
                path.display(),
                sender.describe(),
                match shredded {
                    Some(true) => "shredded its copy",
                    Some(false) => "kept its copy",
                    None => "didn't confirm its shred",
                }
            ));
            say(&format!(
                "signed receipt logged in {}",
                sxfer_dir().join("receipts.jsonl").display()
            ));
        }
        lan::Received::Text { sender, text } => {
            let from = sender.describe();
            println!("----- secret from {from} (shown once, not saved) -----");
            println!("{text}");
            println!("{}", "-".repeat(40 + from.len()));
        }
        // `listen` has no inbox, so it refuses messages before this could happen
        lan::Received::Message { .. } => {}
    }
    Ok(())
}

struct SendArgs {
    file: Option<PathBuf>,
    to: Option<String>,
    code: Option<String>,
    no_code: bool,
    remember: bool,
    receipt: Option<PathBuf>,
    sc: ShredCfg,
}

fn send(a: SendArgs) -> R<()> {
    let payload = match a.file {
        Some(p) => {
            cloud_warning(&p);
            lan::Payload::File(p)
        }
        None => {
            let t = if std::io::stdin().is_terminal() {
                rpassword::prompt_password("sxfer: secret to send (hidden): ")
                    .map_err(|e| Abort(format!("cannot read secret: {e}")))?
            } else {
                let mut s = String::new();
                std::io::stdin().read_to_string(&mut s)?;
                s.trim_end_matches(['\r', '\n']).to_string()
            };
            if t.is_empty() {
                sxfer::abort!("nothing to send");
            }
            lan::Payload::Text(t)
        }
    };
    if let Some(r) = &a.receipt {
        if r.exists() {
            sxfer::abort!(
                "{} already exists; pick another --receipt path",
                r.display()
            );
        }
    }
    let me = Identity::load_or_create()?;

    let (addr, found) = match a.to {
        Some(t) => (lan::resolve_to(&t)?, None),
        None => {
            let (addr, f) = pick_listener()?;
            (addr, Some(f))
        }
    };
    let auth = if a.no_code {
        lan::Auth::Trusted
    } else if let Some(c) = a.code {
        lan::Auth::Code(c)
    } else if found.as_ref().is_some_and(|f| f.trusted_and_pinned()) {
        say("it's a pinned peer that accepts pinned senders: no code needed");
        lan::Auth::Trusted
    } else {
        lan::Auth::Code(prompt_line(&format!(
            "sxfer: one-time code shown on {addr}: "
        ))?)
    };
    if let lan::Auth::Code(c) = &auth {
        if lan::normalize_code(c).len() != 6 {
            sxfer::abort!("the code is 6 digits, like 482-913");
        }
    }
    let opts = lan::SendOpts {
        auth,
        me: &me,
        remember: a.remember,
        expect_fp: None,
    };
    let sent = lan::send_core(addr, &payload, &a.sc, &opts)?;
    if let lan::Payload::Text(_) = payload {
        say(&format!(
            "secret delivered to {} (verified; shown on their screen, not saved)",
            sent.listener.describe()
        ));
    } else if !sent.shredded && !a.sc.keep {
        say("note: source not shredded");
    }
    if let Some(r) = &a.receipt {
        let json = serde_json::to_vec_pretty(&sent.receipt).expect("serializable");
        fs::write(r, json)?;
        say(&format!(
            "signed receipt saved to {} (check it: sxfer receipt verify {})",
            r.display(),
            r.display()
        ));
    }
    Ok(())
}

fn pick_listener() -> R<(SocketAddr, lan::Found)> {
    let nets = config::networks()?;
    if nets.is_empty() {
        sxfer::abort!(
            "no networks configured. Add yours first, e.g.: sxfer config add 192.168.2.0/24   (or use --to <ip>:<port>)"
        );
    }
    let shown: Vec<String> = nets.iter().map(|n| n.to_string()).collect();
    say("looking for listeners (mDNS) ...");
    let found = lan::discover(Duration::from_secs(2))?;
    // allowlist: only listeners advertising an address inside a configured network
    let mut ok: Vec<(SocketAddr, lan::Found)> = found
        .iter()
        .filter_map(|f| f.addr_in(&nets).map(|a| (a, f.clone())))
        .collect();
    let ignored = found.len() - ok.len();
    if ignored > 0 {
        say(&format!(
            "ignoring {ignored} listener(s) outside {}",
            shown.join(", ")
        ));
    }
    ok.retain(|(a, f)| {
        let current = f.version == "2";
        if !current {
            say(&format!(
                "ignoring {} at {a}: it runs an older sxfer (both sides need 0.7+)",
                f.name
            ));
        }
        current
    });
    let label = |a: &SocketAddr, f: &lan::Found| {
        let pinned = if f.trusted_and_pinned() {
            "  (pinned)"
        } else {
            ""
        };
        format!("{} at {a}{pinned}", f.name)
    };
    match ok.len() {
        0 => sxfer::abort!(
            "no listener found on {}. Is `sxfer listen` running on the same network, and is sxfer allowed through its firewall (plus mDNS, UDP 5353)?",
            shown.join(", ")
        ),
        1 => {
            say(&format!("found {}", label(&ok[0].0, &ok[0].1)));
            Ok(ok.remove(0))
        }
        _ => {
            for (i, (a, f)) in ok.iter().enumerate() {
                eprintln!("  {}) {}", i + 1, label(a, f));
            }
            let a = prompt_line("sxfer: which one? ")?;
            let i: usize = a.parse().map_err(|_| Abort("not a number".into()))?;
            if i == 0 || i > ok.len() {
                sxfer::abort!("no such listener");
            }
            Ok(ok.remove(i - 1))
        }
    }
}

/// A full fingerprint in groups of four, for comparing by eye.
fn grouped(fp: &str) -> String {
    let groups: Vec<&str> = (0..fp.len() / 4).map(|i| &fp[i * 4..i * 4 + 4]).collect();
    groups.join("-")
}

fn show_id() -> R<()> {
    let me = Identity::load_or_create()?;
    let fp = me.fingerprint();
    println!("name         {}", me.name);
    println!("fingerprint  {}", grouped(&fp));
    say(&format!(
        "ML-DSA-65 key in {}. To pin this machine elsewhere, compare this fingerprint out of band and run there:\n    sxfer trust add {} {}",
        id::identity_path().display(),
        me.name,
        grouped(&fp)
    ));
    Ok(())
}

fn trust(action: TrustCmd) -> R<()> {
    match action {
        TrustCmd::List => {
            let peers = id::peers();
            if peers.is_empty() {
                say("no pinned peers. Pin one with `sxfer trust add <name> <fingerprint>`, or `--remember` on listen/send");
            }
            for p in peers {
                let at = p.addr.map(|a| format!("  at {a}")).unwrap_or_default();
                println!("{:<24} {}{at}", p.name, grouped(&p.fingerprint));
            }
        }
        TrustCmd::Addr { peer, addr, clear } => {
            let p = if clear {
                id::set_addr(&peer, None)?
            } else if let Some(a) = addr {
                lan::resolve_to(&a)?; // host:port, and it resolves
                id::set_addr(&peer, Some(&a))?
            } else {
                id::find_peer(&peer)?
            };
            match &p.addr {
                Some(a) => say(&format!("{} serves at {a}", p.name)),
                None => say(&format!("{} has no address set: found over mDNS", p.name)),
            }
        }
        TrustCmd::Add { name, fingerprint } => {
            let fp = id::normalize_fp(&fingerprint)?;
            if id::pin(&name, &fp)? {
                say(&format!("pinned {name} [{}]", id::short_fp(&fp)));
            } else {
                say("that fingerprint is already pinned");
            }
        }
        TrustCmd::Remove { peer } => {
            let p = id::unpin(&peer)?;
            say(&format!(
                "unpinned {} [{}]",
                p.name,
                id::short_fp(&p.fingerprint)
            ));
        }
    }
    Ok(())
}

fn verify_receipt(path: &Path, file: Option<&Path>) -> R<()> {
    let bytes = fs::read(path).map_err(|e| Abort(format!("{}: {e}", path.display())))?;
    let r: SignedReceipt = serde_json::from_slice(&bytes)
        .map_err(|e| Abort(format!("{} is not an sxfer receipt: {e}", path.display())))?;
    let b = r.open()?;
    let fp = b.listener_fp();
    let pinned = match id::check_peer(&b.listener, &fp) {
        Known::Yes(_) => "pinned",
        Known::New => "not pinned here",
        Known::Changed { .. } => "NOT the key pinned for that name",
    };
    println!("signature    valid (ML-DSA-65)");
    println!(
        "signed by    {} [{}]  ({pinned})",
        b.listener,
        id::short_fp(&fp)
    );
    println!("sender       {} [{}]", b.sender, id::short_fp(&b.sender_fp));
    println!("{:<12} {}", b.kind, b.path.as_deref().unwrap_or(&b.name));
    println!("size         {} bytes", b.size);
    println!("sha256       {}", b.sha256);
    println!("time         {} (unix seconds)", b.time);
    if let Some(f) = file {
        if sha256_file(f)? != (b.sha256.clone(), b.size) {
            sxfer::abort!("{} does NOT match this receipt", f.display());
        }
        say(&format!("{} matches the receipt", f.display()));
    }
    Ok(())
}

fn sig_path(file: &Path) -> PathBuf {
    PathBuf::from(format!("{}.sig", file.display()))
}

fn sig(action: SigCmd) -> R<()> {
    match action {
        SigCmd::Keygen { key } => {
            id::write_seed(&key, &id::new_seed())?;
            let k = Identity::load(&key, "key")?;
            let public = PathBuf::from(format!("{}.pub.pem", key.display()));
            fs::write(&public, k.public_key_pem())?;
            say(&format!(
                "wrote {} (SECRET: keep it out of git and backups you don't control) and {}",
                key.display(),
                public.display()
            ));
            println!("fingerprint  {}", grouped(&k.fingerprint()));
        }
        SigCmd::Sign { file, key } => {
            let k = Identity::load(&key, "key")?;
            let data = fs::read(&file).map_err(|e| Abort(format!("{}: {e}", file.display())))?;
            let out = sig_path(&file);
            fs::write(&out, k.sign(id::CTX_FILE, &data)?)?;
            say(&format!(
                "signed {} -> {}  (key {})",
                file.display(),
                out.display(),
                id::short_fp(&k.fingerprint())
            ));
        }
        SigCmd::Verify { file, sig, pubkey } => {
            let pk = id::read_public_key_pem(&pubkey)?;
            let data = fs::read(&file).map_err(|e| Abort(format!("{}: {e}", file.display())))?;
            let sig = sig.unwrap_or_else(|| sig_path(&file));
            let s = fs::read(&sig).map_err(|e| Abort(format!("{}: {e}", sig.display())))?;
            if !id::verify(&pk, id::CTX_FILE, &data, &s) {
                sxfer::abort!(
                    "BAD signature: {} was not signed by that key, or was changed",
                    file.display()
                );
            }
            say(&format!(
                "good signature on {} from key {}",
                file.display(),
                grouped(&id::fingerprint(&pk))
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- agent messaging

fn serve(a: ServeArgs) -> R<()> {
    let me = Arc::new(Identity::load_or_create()?);
    let dir = a.inbox.unwrap_or_else(Inbox::default_dir);
    let mut inbox = Inbox::open(&dir)?;
    inbox.max_hops = a.max_hops;
    inbox.rate = a.rate;
    let inbox = Arc::new(inbox);
    // absolute (hooks run elsewhere), without Windows' \\?\ prefix that canonicalize adds
    let dir = std::path::absolute(&dir).unwrap_or(dir);
    if let Some(f) = &a.files {
        if !f.is_dir() {
            sxfer::abort!("no such directory: {}", f.display());
        }
    }

    // --on-receive runs on worker threads, one message at a time each
    let hook_tx = a.on_receive.clone().map(|cmd| {
        let (tx, rx) = mpsc::channel::<String>();
        let rx = Arc::new(Mutex::new(rx));
        for _ in 0..a.jobs {
            let (rx, inbox, cmd) = (Arc::clone(&rx), Arc::clone(&inbox), cmd.clone());
            std::thread::spawn(move || loop {
                let Ok(mid) = rx.lock().unwrap_or_else(|e| e.into_inner()).recv() else {
                    return;
                };
                let Ok(e) = inbox.find(&mid) else { continue };
                match mesh::run_hook(&cmd, &inbox, &e) {
                    Ok(true) => say(&format!(
                        "handled {mid} (--on-receive exited 0; moved to done/)"
                    )),
                    Ok(false) => say(&format!(
                        "--on-receive failed for {mid}; it stays in the inbox (log: {})",
                        inbox.dir.join("logs").display()
                    )),
                    Err(err) => say(&format!("{mid}: {err}")),
                }
            });
        }
        Mutex::new(tx)
    });
    let hook_tx = Arc::new(hook_tx);

    let pending = inbox.list(false)?;
    if !pending.is_empty() {
        if let (true, Some(tx)) = (a.replay, hook_tx.as_ref()) {
            for e in &pending {
                let _ = tx
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .send(e.id().to_string());
            }
        }
    }

    // the outbox: retried in the background while serve runs
    let flusher = Arc::clone(&me);
    spawn_big(move || loop {
        match mesh::flush(&flusher, false, true) {
            Ok(done) => {
                for f in done {
                    match (&f.result, f.gave_up) {
                        (Ok(()), _) => say(&format!("outbox: delivered {} to {}", f.id, f.to)),
                        (Err(e), true) => {
                            say(&format!("outbox: gave up on {} to {}: {e}", f.id, f.to))
                        }
                        (Err(_), false) => {}
                    }
                }
            }
            Err(e) => say(&format!("outbox: {e}")),
        }
        std::thread::sleep(Duration::from_secs(30));
    });

    let report: Arc<lan::OnTransfer> = {
        let hook_tx = Arc::clone(&hook_tx);
        Arc::new(move |peer: SocketAddr, r: R<lan::Received>| match r {
            Ok(lan::Received::Message {
                id,
                already: false,
                sender,
                ..
            }) => {
                say(&format!("message {id} from {}", sender.describe()));
                if let Some(tx) = hook_tx.as_ref() {
                    let _ = tx.lock().unwrap_or_else(|e| e.into_inner()).send(id);
                }
            }
            Ok(lan::Received::Message { id, sender, .. }) => say(&format!(
                "message {id} from {} again (a retry; already in the inbox)",
                sender.describe()
            )),
            Ok(lan::Received::File { path, sender, .. }) => say(&format!(
                "file {} from {}",
                path.display(),
                sender.describe()
            )),
            Ok(lan::Received::Text { .. }) => {}
            Err(e) => say(&format!("{peer}: {e}")),
        })
    };

    let peers = id::peers().len();
    let files_dir = a.files.clone();
    let start = |port: u16| -> R<()> {
        let mut cfg = lan::ListenCfg::new(
            SocketAddr::new(a.bind, port),
            files_dir.clone().unwrap_or_else(|| dir.clone()),
            Arc::clone(&me),
        );
        cfg.advertise = !a.no_mdns;
        cfg.accept_text = false; // secrets would land in an agent's context
        cfg.accept_files = files_dir.is_some();
        cfg.trusted = true;
        cfg.pinned_only = true;
        cfg.inbox = Some(Arc::clone(&inbox));
        lan::serve_core(
            Arc::new(cfg),
            &mut |p| {
                let ip = match a.bind.is_unspecified() {
                    true => lan::primary_ip()
                        .map(|i| i.to_string())
                        .unwrap_or_else(|| "this machine".into()),
                    false => a.bind.to_string(),
                };
                if let Err(e) = mesh::save_serve_state(p, &dir) {
                    say(&format!("could not record the port: {e}"));
                }
                say(&format!(
                    "serving on {ip}:{p} as {} [{}]{}",
                    me.name,
                    id::short_fp(&me.fingerprint()),
                    if a.no_mdns {
                        ", not advertised (peers use `sxfer trust addr`)"
                    } else {
                        ", advertised over mDNS"
                    }
                ));
                say(&format!(
                    "inbox {}  ({} waiting){}",
                    dir.display(),
                    pending.len(),
                    match &files_dir {
                        Some(f) => format!("; files -> {}", f.display()),
                        None => String::new(),
                    }
                ));
                say(&format!(
                    "pinned peers only ({peers} pinned); hop limit {}, {} messages/min per sender. Ctrl+C to stop.",
                    a.max_hops, a.rate
                ));
                if peers == 0 {
                    say("nobody can reach this inbox until you pin a peer: `sxfer trust add`, or `listen --remember` once");
                }
                if let Some(cmd) = &a.on_receive {
                    say(&format!("on each message: {cmd}"));
                }
            },
            Arc::clone(&report),
        )
    };
    match (a.port, mesh::serve_port()) {
        (Some(p), _) => start(p),
        // last time's port keeps replies working across restarts; any port if it's taken now
        (None, Some(last)) => start(last).or_else(|e| {
            say(&format!("{e}; using another port"));
            start(0)
        }),
        (None, None) => start(0),
    }
}

/// The message body: the file, `-` for stdin, or stdin when it's piped. A UTF-8 byte order
/// mark (Windows editors and PowerShell add one) is dropped.
fn read_body(file: &Option<PathBuf>) -> R<String> {
    let stdin = || -> R<String> {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        Ok(s)
    };
    let s = match file {
        Some(p) if p.as_os_str() == "-" => stdin()?,
        Some(p) => fs::read_to_string(p).map_err(|e| Abort(format!("{}: {e}", p.display())))?,
        None if !std::io::stdin().is_terminal() => stdin()?,
        None => String::new(),
    };
    Ok(s.strip_prefix('\u{feff}').map(str::to_string).unwrap_or(s))
}

impl Compose {
    fn draft(&self) -> R<mesh::Draft> {
        let data = match &self.data {
            Some(d) => Some(
                serde_json::from_str(d).map_err(|e| Abort(format!("--data isn't JSON: {e}")))?,
            ),
            None => None,
        };
        Ok(mesh::Draft {
            body: read_body(&self.file)?,
            subject: self.subject.clone(),
            intent: self.intent.clone(),
            attach: self.attach.clone(),
            data,
            ..mesh::Draft::default()
        })
    }
}

fn report_send(out: &mesh::Outcome, json: bool) {
    match out {
        mesh::Outcome::Delivered {
            id,
            peer,
            already,
            receipt,
        } => {
            if json {
                println!(
                    "{}",
                    json!({ "status": "delivered", "id": id, "to": peer.name,
                        "fingerprint": peer.fingerprint, "already_there": already, "receipt": receipt })
                );
                return;
            }
            say(&format!(
                "{} {id} to {}  (receipt signed with its ML-DSA-65 key, verified)",
                if *already {
                    "already delivered"
                } else {
                    "delivered"
                },
                peer.describe()
            ));
            println!("{id}");
        }
        mesh::Outcome::Queued { id, path, why } => {
            if json {
                println!(
                    "{}",
                    json!({ "status": "queued", "id": id, "reason": why, "outbox": path })
                );
                return;
            }
            say(&format!("not delivered yet: {why}"));
            say("queued in the outbox; `sxfer serve` keeps retrying (or `sxfer msg flush` now)");
            println!("{id}");
        }
    }
}

fn msg(action: MsgCmd) -> R<()> {
    match action {
        MsgCmd::Send {
            peer,
            c,
            thread,
            a2a,
            move_,
            yes,
        } => {
            let me = Identity::load_or_create()?;
            let to = id::find_peer(&peer)?;
            let message = if a2a {
                let raw = read_body(&c.file)?;
                let v: Value = serde_json::from_str(&raw)
                    .map_err(|e| Abort(format!("not an A2A message (JSON): {e}")))?;
                mesh::adopt(v)?
            } else {
                let mut d = c.draft()?;
                d.thread = thread;
                mesh::build(&d, &me.name)?
            };
            let src = c.file.as_ref().filter(|p| p.as_os_str() != "-");
            if move_ && src.is_none() {
                sxfer::abort!("--move needs the message as a file");
            }
            // a handoff isn't done until it's delivered: no queueing with --move
            let out = mesh::send(&me, &to, &message, None, !c.no_queue && !move_, true)?;
            report_send(&out, c.json);
            if let (true, Some(p), mesh::Outcome::Delivered { .. }) = (move_, src, &out) {
                let ask = !yes && config::load().confirm_shred();
                if confirm(&format!("Delivered. Shred {}?", p.display()), ask) {
                    shred_local(p, 3)?;
                    say(&format!(
                        "shredded {}: the handoff is complete",
                        p.display()
                    ));
                } else {
                    say(&format!("kept {}", p.display()));
                }
            }
            Ok(())
        }
        MsgCmd::Reply { id: which, c, done } => {
            let me = Identity::load_or_create()?;
            let inbox = Inbox::open(&mesh::current_inbox())?;
            let original = inbox.find(&which)?;
            let (to, d, hint) = mesh::reply_to(&original, c.draft()?)?;
            let message = mesh::build(&d, &me.name)?;
            let out = mesh::send(&me, &to, &message, hint.as_deref(), !c.no_queue, true)?;
            report_send(&out, c.json);
            if done {
                inbox.mark_done(&original)?;
            }
            Ok(())
        }
        MsgCmd::Peers { json } => {
            let peers = mesh::peers_status(true);
            if json {
                println!("{}", Value::Array(peers));
                return Ok(());
            }
            if peers.is_empty() {
                say("no pinned peers: `sxfer trust add <name> <fingerprint>`, or `listen --remember` once");
            }
            for p in peers {
                let state = if p["serving"] == true {
                    format!(
                        "serving at {}",
                        p["advertised_at"][0].as_str().unwrap_or("?")
                    )
                } else {
                    "not seen over mDNS".into()
                };
                let at = p["address"]
                    .as_str()
                    .map(|a| format!("  (address set: {a})"))
                    .unwrap_or_default();
                println!(
                    "{:<24} {}  {state}{at}",
                    p["name"].as_str().unwrap_or("?"),
                    p["short"].as_str().unwrap_or("")
                );
            }
            Ok(())
        }
        MsgCmd::Outbox { json } => {
            let q = mesh::queued();
            if json {
                println!("{}", Value::Array(q));
                return Ok(());
            }
            if q.is_empty() {
                say("the outbox is empty");
            }
            let now: u64 = now_iso().parse().unwrap_or(0);
            for m in q {
                println!(
                    "{}  to {:<20} tries {}  next in {}  ({})",
                    m["id"].as_str().unwrap_or("?"),
                    m["to"].as_str().unwrap_or("?"),
                    m["attempts"],
                    span(m["next_try"].as_u64().unwrap_or(now).saturating_sub(now)),
                    m["last_error"].as_str().unwrap_or("")
                );
            }
            Ok(())
        }
        MsgCmd::Flush => {
            let me = Identity::load_or_create()?;
            let done = mesh::flush(&me, true, true)?;
            if done.is_empty() {
                say("the outbox is empty");
            }
            for f in done {
                match (&f.result, f.gave_up) {
                    (Ok(()), _) => say(&format!("delivered {} to {}", f.id, f.to)),
                    (Err(e), true) => say(&format!("gave up on {} to {}: {e}", f.id, f.to)),
                    (Err(e), false) => say(&format!("still queued {} to {}: {e}", f.id, f.to)),
                }
            }
            Ok(())
        }
    }
}

fn inbox(action: InboxCmd) -> R<()> {
    let inbox = Inbox::open(&mesh::current_inbox())?;
    let now: u64 = now_iso().parse().unwrap_or(0);
    let line = |e: &mesh::Entry| {
        let v = &e.v;
        let at: u64 = v["received"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .unwrap_or(now);
        format!(
            "{}  {:<16} {:<9} {:>4} ago  {}{}",
            e.id().get(..12).unwrap_or(e.id()),
            v["from"]["name"].as_str().unwrap_or("?"),
            v["intent"].as_str().unwrap_or(""),
            span(now.saturating_sub(at)),
            v["subject"].as_str().unwrap_or("(no subject)"),
            if e.done { "  [done]" } else { "" }
        )
    };
    match action {
        InboxCmd::List { all, json } => {
            let entries = inbox.list(all)?;
            if json {
                let v: Vec<Value> = entries.iter().map(mesh::Entry::summary).collect();
                println!("{}", Value::Array(v));
                return Ok(());
            }
            if entries.is_empty() {
                say(&format!("nothing waiting in {}", inbox.dir.display()));
            }
            for e in &entries {
                println!("{}", line(e));
            }
        }
        InboxCmd::Read { id: which, json } => {
            let e = inbox.find(&which)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&e.v).unwrap_or_default());
            } else {
                print!("{}", mesh::render(&e));
            }
        }
        InboxCmd::Wait { timeout, new, json } => {
            let skip: HashSet<PathBuf> = if new {
                inbox.list(false)?.into_iter().map(|e| e.path).collect()
            } else {
                HashSet::new()
            };
            match inbox.wait(timeout.map(Duration::from_secs), &skip)? {
                Some(e) if json => println!("{}", e.summary()),
                Some(e) => print!("{}", mesh::render(&e)),
                None => {
                    say("no message before the timeout");
                    std::process::exit(2);
                }
            }
        }
        InboxCmd::Done { ids } => {
            for which in ids {
                let e = inbox.find(&which)?;
                inbox.mark_done(&e)?;
                say(&format!("{} done", e.id()));
            }
        }
        InboxCmd::Save { id: which, dir } => {
            let e = inbox.find(&which)?;
            if !dir.is_dir() {
                sxfer::abort!("no such directory: {}", dir.display());
            }
            let saved = mesh::save_attachments(&e, &dir)?;
            if saved.is_empty() {
                say("that message has no attachments");
            }
            for p in saved {
                println!("{}", p.display());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_override_configured_confirmation() {
        assert!(resolve_ask(false, false, true), "default config asks");
        assert!(
            !resolve_ask(false, false, false),
            "config off shreds without asking"
        );
        assert!(!resolve_ask(true, false, true), "-y skips the prompt");
        assert!(
            resolve_ask(false, true, false),
            "--ask asks despite config off"
        );
    }

    #[test]
    fn messaging_commands_parse() {
        let parse = |args: &[&str]| Cli::try_parse_from([&["sxfer"], args].concat());
        assert!(
            parse(&["serve", "--replay"]).is_err(),
            "--replay needs --on-receive"
        );
        assert!(parse(&[
            "serve",
            "--on-receive",
            "x",
            "--replay",
            "--jobs",
            "4",
            "--bind",
            "10.8.0.2",
            "--no-mdns"
        ])
        .is_ok());
        assert!(parse(&["serve", "--jobs", "0"]).is_err());
        assert!(parse(&["msg", "send", "laptop", "m.json", "--a2a", "--move"]).is_err());
        assert!(parse(&[
            "msg", "send", "laptop", "m.md", "-s", "hi", "-i", "handoff", "-a", "x.pdf", "-a",
            "y.pdf", "--move", "-y"
        ])
        .is_ok());
        assert!(parse(&["msg", "reply", "ab12", "--done", "--json"]).is_ok());
        assert!(parse(&["inbox", "done"]).is_err(), "needs an id");
        assert!(parse(&["trust", "addr", "laptop", "10.0.0.2:5000", "--clear"]).is_err());
    }

    #[test]
    fn spans_read_naturally() {
        assert_eq!(span(5), "5s");
        assert_eq!(span(120), "2m");
        assert_eq!(span(7200), "2h");
        assert_eq!(span(172_800), "2d");
    }

    #[test]
    fn yes_and_ask_conflict() {
        assert!(Cli::try_parse_from(["sxfer", "push", "a", "h:/", "-y", "--ask"]).is_err());
    }

    #[test]
    fn confirm_unset_means_ask() {
        let c: config::Config = serde_json::from_str(r#"{"networks":[]}"#).unwrap();
        assert!(c.confirm_shred());
        let c: config::Config = serde_json::from_str(r#"{"confirm_shred":false}"#).unwrap();
        assert!(!c.confirm_shred());
    }
}
