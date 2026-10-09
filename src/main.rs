//! sxfer - move a file or a secret between machines: encrypted transfer, proven receipt, then
//! shred the source. Two transports:
//!   LAN  `sxfer listen` / `sxfer send`  direct TCP, paired by a one-time code (SPAKE2)
//!   SSH  `sxfer push` / `sxfer pull`    over your ssh client and its config
//!
//! SHRED CAVEAT: overwriting is reliable on spinning disks. On SSDs, copy-on-write or journaling
//! filesystems, cloud-synced folders, snapshots and backups, old copies can survive. Full-disk
//! encryption (BitLocker / FileVault / LUKS) is what really protects deleted data there.

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::io::{IsTerminal, Read};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use sxfer::common::*;
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
    },
    /// Send a file over the LAN - or, with no FILE, a secret you type (shown once on the listener, never saved)
    Send {
        file: Option<PathBuf>,
        /// Listener as host:port, as printed by `sxfer listen` (skips mDNS discovery)
        #[arg(long)]
        to: Option<String>,
        /// One-time code (otherwise you're asked for it)
        #[arg(long)]
        code: Option<String>,
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

fn main() {
    let cli = Cli::parse();
    let r = match cli.cmd {
        Cmd::Listen { dir } => listen(dir),
        Cmd::Send {
            file,
            to,
            code,
            shred,
        } => send(file, to, code, shred.cfg()),
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
    };
    if let Err(e) = r {
        say(&format!("ABORTED: {e}"));
        std::process::exit(1);
    }
}

fn listen(dir: PathBuf) -> R<()> {
    if !dir.is_dir() {
        sxfer::abort!("no such directory: {}", dir.display());
    }
    let code = lan::new_code();
    let shown_dir = std::fs::canonicalize(&dir).unwrap_or(dir.clone());
    let cfg = lan::ListenCfg {
        bind: SocketAddr::from(([0, 0, 0, 0], 0)), // any free port; mDNS tells senders which
        dir,
        advertise: true,
        accept_text: true,
        stop: None,
    };
    let got = lan::listen_core(&cfg, &code, &mut |p| {
        let ip = lan::primary_ip()
            .map(|i| i.to_string())
            .unwrap_or_else(|| "this machine".into());
        say(&format!(
            "listening on {ip}:{p} as {}, advertised over mDNS  (files -> {})",
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

fn send(file: Option<PathBuf>, to: Option<String>, code: Option<String>, sc: ShredCfg) -> R<()> {
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
                sxfer::abort!("nothing to send");
            }
            lan::Payload::Text(t)
        }
    };

    let addr = match to {
        Some(t) => lan::resolve_to(&t)?,
        None => pick_listener()?,
    };
    let code = match code {
        Some(c) => c,
        None => prompt_line(&format!("sxfer: one-time code shown on {addr}: "))?,
    };
    if lan::normalize_code(&code).len() != 6 {
        sxfer::abort!("the code is 6 digits, like 482-913");
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

fn pick_listener() -> R<SocketAddr> {
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
    let ok: Vec<(String, SocketAddr)> = found
        .iter()
        .filter_map(|f| f.addr_in(&nets).map(|a| (f.name.clone(), a)))
        .collect();
    let ignored = found.len() - ok.len();
    if ignored > 0 {
        say(&format!(
            "ignoring {ignored} listener(s) outside {}",
            shown.join(", ")
        ));
    }
    match ok.len() {
        0 => sxfer::abort!(
            "no listener found on {}. Is `sxfer listen` running on the same network, and is sxfer allowed through its firewall (plus mDNS, UDP 5353)?",
            shown.join(", ")
        ),
        1 => {
            say(&format!("found {} at {}", ok[0].0, ok[0].1));
            Ok(ok[0].1)
        }
        _ => {
            for (i, (name, addr)) in ok.iter().enumerate() {
                eprintln!("  {}) {}  {}", i + 1, name, addr);
            }
            let a = prompt_line("sxfer: which one? ")?;
            let i: usize = a.parse().map_err(|_| Abort("not a number".into()))?;
            ok.get(i.wrapping_sub(1))
                .map(|(_, a)| *a)
                .ok_or_else(|| Abort("no such listener".into()))
        }
    }
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
