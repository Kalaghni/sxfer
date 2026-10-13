//! sxfer - move a file or a secret between machines: encrypted transfer, proven receipt, then
//! shred the source. Two transports:
//!   LAN  `sxfer listen` / `sxfer send`  direct TCP, paired by a one-time code (SPAKE2) plus
//!                                       ML-KEM-768; peers and receipts signed with ML-DSA-65
//!   SSH  `sxfer push` / `sxfer pull`    over your ssh client and its config
//!
//! SHRED CAVEAT: overwriting is reliable on spinning disks. On SSDs, copy-on-write or journaling
//! filesystems, cloud-synced folders, snapshots and backups, old copies can survive. Full-disk
//! encryption (BitLocker / FileVault / LUKS) is what really protects deleted data there.

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::fs;
use std::io::{IsTerminal, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use sxfer::common::*;
use sxfer::identity::{self as id, Identity, Known, SignedReceipt};
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
    let cfg = lan::ListenCfg {
        bind: SocketAddr::from(([0, 0, 0, 0], 0)), // any free port; mDNS tells senders which
        dir,
        advertise: true,
        accept_text: true,
        stop: None,
        me: Arc::clone(&me),
        trusted,
        remember,
    };
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
                println!("{:<24} {}", p.name, grouped(&p.fingerprint));
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
