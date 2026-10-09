//! sxfer - move a file or a secret between machines: encrypted transfer, proven receipt, then
//! shred the source. Two transports:
//!   LAN  `sxfer listen` / `sxfer send`  direct TCP, paired by a one-time code (SPAKE2)
//!   SSH  `sxfer push` / `sxfer pull`    over your ssh client and its config
//!
//! SHRED CAVEAT: overwriting is reliable on spinning disks. On SSDs, copy-on-write or journaling
//! filesystems, cloud-synced folders, snapshots and backups, old copies can survive. Full-disk
//! encryption (BitLocker / FileVault / LUKS) is what really protects deleted data there.

mod common;
mod config;
mod lan;
mod ssh;

use clap::{Args, Parser, Subcommand};
use common::*;
use std::io::{IsTerminal, Read};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

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
    /// Ask before shredding (default: shred as soon as receipt is confirmed)
    #[arg(long)]
    ask: bool,
    /// Random overwrite passes before the final zero pass
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u32).range(1..))]
    passes: u32,
    /// (old flag; shredding without asking is now the default)
    #[arg(long, short = 'y', hide = true)]
    yes: bool,
}

impl ShredOpts {
    fn cfg(&self) -> ShredCfg {
        ShredCfg {
            keep: self.keep,
            ask: self.ask,
            passes: self.passes,
        }
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Receive over the LAN: shows a one-time code and waits for `sxfer send`
    Listen {
        /// Where received files are saved
        #[arg(long, default_value = ".")]
        dir: PathBuf,
        #[arg(long, default_value_t = lan::PORT)]
        port: u16,
    },
    /// Send a file over the LAN - or, with no FILE, a secret you type (shown once on the listener, never saved)
    Send {
        file: Option<PathBuf>,
        /// Listener address or hostname (skips discovery)
        #[arg(long)]
        to: Option<String>,
        #[arg(long, default_value_t = lan::PORT)]
        port: u16,
        /// One-time code (otherwise you're asked for it)
        #[arg(long)]
        code: Option<String>,
        #[command(flatten)]
        shred: ShredOpts,
    },
    /// Networks `send` searches for listeners
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
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Add a network or single address, e.g. 192.168.2.0/24 or 192.168.2.50
    Add { net: String },
    /// Remove a network
    Remove { net: String },
    /// Show configured networks
    List,
}

fn main() {
    let cli = Cli::parse();
    let r = match cli.cmd {
        Cmd::Listen { dir, port } => listen(dir, port),
        Cmd::Send {
            file,
            to,
            port,
            code,
            shred,
        } => send(file, to, port, code, shred.cfg()),
        Cmd::Config { action } => match action {
            ConfigCmd::Add { net } => config::add(&net),
            ConfigCmd::Remove { net } => config::remove(&net),
            ConfigCmd::List => {
                config::list();
                Ok(())
            }
        },
        Cmd::Push { src, dest, shred } => ssh::push(&src, &dest, &shred.cfg()),
        Cmd::Pull { src, dest, shred } => ssh::pull(&src, &dest, &shred.cfg()),
    };
    if let Err(e) = r {
        say(&format!("ABORTED: {e}"));
        std::process::exit(1);
    }
}

fn listen(dir: PathBuf, port: u16) -> R<()> {
    if !dir.is_dir() {
        crate::abort!("no such directory: {}", dir.display());
    }
    let code = lan::new_code();
    let shown_dir = std::fs::canonicalize(&dir).unwrap_or(dir.clone());
    let cfg = lan::ListenCfg {
        bind: SocketAddr::from(([0, 0, 0, 0], port)),
        dir,
    };
    let got = lan::listen_core(&cfg, &code, &mut |p| {
        let ip = lan::primary_ip()
            .map(|i| i.to_string())
            .unwrap_or_else(|| "this machine".into());
        say(&format!(
            "listening on {ip}:{p} as {}  (files -> {})",
            host_name(),
            shown_dir.display()
        ));
        eprintln!();
        eprintln!("    one-time code:  {code}");
        eprintln!();
        say("give the sender this code; it works once (3 wrong tries closes the listener). Ctrl+C to cancel.");
    })?;
    match got {
        lan::Received::File {
            path,
            already,
            shredded,
        } => {
            say(&format!(
                "{} {}  (sender {})",
                if already { "already had" } else { "received" },
                path.display(),
                match shredded {
                    Some(true) => "shredded its copy",
                    Some(false) => "kept its copy",
                    None => "didn't confirm its shred",
                }
            ));
            say(&format!(
                "receipt logged in {}",
                sxfer_dir().join("receipts.jsonl").display()
            ));
        }
        lan::Received::Text { from, text } => {
            println!("----- secret from {from} (shown once, not saved) -----");
            println!("{text}");
            println!("{}", "-".repeat(40 + from.len()));
        }
    }
    Ok(())
}

fn send(
    file: Option<PathBuf>,
    to: Option<String>,
    port: u16,
    code: Option<String>,
    sc: ShredCfg,
) -> R<()> {
    let payload = match file {
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
                crate::abort!("nothing to send");
            }
            lan::Payload::Text(t)
        }
    };

    let addr = match to {
        Some(t) => lan::resolve_to(&t, port)?,
        None => pick_listener(port)?,
    };
    let code = match code {
        Some(c) => c,
        None => prompt_line(&format!("sxfer: one-time code shown on {addr}: "))?,
    };
    if lan::normalize_code(&code).len() != 6 {
        crate::abort!("the code is 6 digits, like 482-913");
    }
    let sent = lan::send_core(addr, &code, &payload, &sc)?;
    if let lan::Payload::Text(_) = payload {
        say(&format!(
            "secret delivered to {addr} (verified; shown on their screen, not saved)"
        ));
    } else if !sent.shredded && !sc.keep {
        say("note: source not shredded");
    }
    Ok(())
}

fn pick_listener(port: u16) -> R<SocketAddr> {
    let nets = config::networks()?;
    if nets.is_empty() {
        crate::abort!("no networks configured. Add yours first, e.g.: sxfer config add 192.168.2.0/24   (or use --to <ip>)");
    }
    let shown: Vec<String> = nets.iter().map(|n| n.to_string()).collect();
    say(&format!(
        "looking for listeners on {} ...",
        shown.join(", ")
    ));
    let found = lan::discover(&nets, port, Duration::from_millis(1500))?;
    match found.len() {
        0 => crate::abort!(
            "no listener found on {}. Is `sxfer listen` running, and is port {port} (TCP+UDP) allowed through its firewall?",
            shown.join(", ")
        ),
        1 => {
            say(&format!("found {} at {}", found[0].name, found[0].addr));
            Ok(found[0].addr)
        }
        _ => {
            for (i, f) in found.iter().enumerate() {
                eprintln!("  {}) {}  {}", i + 1, f.name, f.addr);
            }
            let a = prompt_line("sxfer: which one? ")?;
            let i: usize = a.parse().map_err(|_| Abort("not a number".into()))?;
            found.get(i.wrapping_sub(1)).map(|f| f.addr).ok_or_else(|| Abort("no such listener".into()))
        }
    }
}
