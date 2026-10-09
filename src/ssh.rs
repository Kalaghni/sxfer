//! push / pull over SSH. Transport encryption and auth are your ssh client's (config aliases work).
//!
//! 1 HASH  2 SEND to <dest>.sxfer-part (600, fsync)  3 VERIFY (receiver re-reads from disk; source
//! re-hashed)  4 COMMIT (atomic no-clobber)  5 SHRED source  6 RECEIPT on the destination only.
//! Any failure before 5 leaves the source untouched; reruns are idempotent.

use crate::abort;
use crate::common::*;
use serde_json::json;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

const OK: &str = "SXFER-OK";
const ERR: &str = "SXFER-ERR";

fn q(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn ssh_cmd(host: &str, script: &str) -> Command {
    let mut c = Command::new("ssh");
    c.args([
        "-o",
        "ConnectTimeout=15",
        "-o",
        "ServerAliveInterval=10",
        "-o",
        "ServerAliveCountMax=3",
        host,
    ])
    .arg(format!("sh -c {}", q(script)));
    c
}

struct Out {
    rc: i32,
    out: String,
    err: String,
}

fn finish(o: std::process::Output) -> Out {
    Out {
        rc: o.status.code().unwrap_or(-1),
        out: String::from_utf8_lossy(&o.stdout).into_owned(),
        err: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

fn run(host: &str, script: &str) -> R<Out> {
    let o = ssh_cmd(host, script)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| Abort(format!("cannot run ssh: {e}")))?;
    Ok(finish(o))
}

fn run_with_file(host: &str, script: &str, f: File) -> R<Out> {
    let o = ssh_cmd(host, script)
        .stdin(Stdio::from(f))
        .output()
        .map_err(|e| Abort(format!("cannot run ssh: {e}")))?;
    Ok(finish(o))
}

fn run_with_data(host: &str, script: &str, data: &[u8]) -> R<Out> {
    let mut child = ssh_cmd(host, script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Abort(format!("cannot run ssh: {e}")))?;
    if let Some(mut i) = child.stdin.take() {
        let _ = i.write_all(data);
    }
    Ok(finish(child.wait_with_output()?))
}

fn run_to_file(host: &str, script: &str, f: File) -> R<Out> {
    let o = ssh_cmd(host, script)
        .stdin(Stdio::null())
        .stdout(Stdio::from(f))
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| Abort(format!("cannot run ssh: {e}")))?;
    Ok(finish(o))
}

/// Find the SXFER-OK line and split it into `fields` fields (the last one may contain spaces).
fn parse(o: &Out, what: &str, fields: usize) -> R<Vec<String>> {
    for line in o.out.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{OK} ")) {
            return Ok(rest.splitn(fields, ' ').map(str::to_string).collect());
        }
        if let Some(rest) = line.strip_prefix(ERR) {
            abort!("{what}: {}", rest.trim());
        }
    }
    let detail = if o.err.trim().is_empty() {
        o.out.trim()
    } else {
        o.err.trim()
    };
    abort!("{what} failed (ssh rc {}): {detail}", o.rc)
}

const R_HASH: &str = r#"h=$(sha256sum < "$1" | cut -d" " -f1); s=$(wc -c < "$1" | tr -d " ")"#;

fn r_probe(dest: &str, name: &str) -> String {
    format!(
        r#"set -u
d={d}; b={b}
case "$d" in */) d="$d$b";; esac
[ -d "$d" ] && d="${{d%/}}/$b"
[ -d "$(dirname "$d")" ] || {{ echo "{ERR} no such directory: $(dirname "$d")"; exit 3; }}
if [ -e "$d" ]; then set -- "$d"; {R_HASH}; echo "{OK} exists $h $s $d"; else echo "{OK} absent - 0 $d"; fi"#,
        d = q(dest),
        b = q(name)
    )
}

fn r_receive(dest: &str) -> String {
    format!(
        r#"set -u; umask 077
d={d}
[ -e "$d" ] && {{ echo "{ERR} destination exists: $d"; exit 3; }}
p="$d.sxfer-part"; rm -f "$p"
cat > "$p" || {{ echo "{ERR} write failed"; rm -f "$p"; exit 4; }}
sync "$p" 2>/dev/null || sync
set -- "$p"; {R_HASH}
echo "{OK} $h $s $d""#,
        d = q(dest)
    )
}

fn r_commit(part: &str, dest: &str) -> String {
    format!(
        r#"set -u
p={p}; d={d}
[ -e "$d" ] && {{ echo "{ERR} destination appeared meanwhile: $d"; exit 3; }}
ln "$p" "$d" 2>/dev/null && rm -f "$p" || mv -n "$p" "$d"
[ -e "$p" ] && {{ echo "{ERR} commit failed"; exit 4; }}
sync "$d" 2>/dev/null || sync
set -- "$d"; {R_HASH}
echo "{OK} $h $s $d""#,
        p = q(part),
        d = q(dest)
    )
}

fn r_stat(path: &str) -> String {
    format!(
        r#"set -u; f={f}
[ -f "$f" ] || {{ echo "{ERR} not a regular file: $f"; exit 3; }}
set -- "$f"; {R_HASH}
echo "{OK} $h $s $f""#,
        f = q(path)
    )
}

fn r_shred(path: &str, passes: u32) -> String {
    // ignores hang-ups so a dropped connection can't stop it halfway
    format!(
        r#"set -u; trap "" HUP PIPE; f={f}
command -v shred >/dev/null || {{ echo "{ERR} shred not installed"; exit 5; }}
shred -n {passes} -z -u -- "$f" || {{ echo "{ERR} shred failed"; exit 5; }}
[ -e "$f" ] && {{ echo "{ERR} file still exists"; exit 5; }}
sync; echo "{OK} shredded""#,
        f = q(path)
    )
}

const R_RECEIPT: &str =
    r#"umask 077; mkdir -p "$HOME/.sxfer" && cat >> "$HOME/.sxfer/receipts.jsonl""#;

fn split_remote(spec: &str) -> R<(String, String)> {
    let b = spec.as_bytes();
    let windows_drive = b.len() > 2
        && b[1] == b':'
        && b[0].is_ascii_alphabetic()
        && (b[2] == b'\\' || b[2] == b'/');
    match spec.split_once(':') {
        Some((h, p)) if !windows_drive && !h.is_empty() && !p.is_empty() => {
            Ok((h.to_string(), p.to_string()))
        }
        _ => abort!("expected host:path, got {spec:?}"),
    }
}

fn mbps(n: u64, t: Instant) -> f64 {
    n as f64 / t.elapsed().as_secs_f64().max(0.001) / 1e6
}

pub fn push(src: &Path, target: &str, sc: &ShredCfg) -> R<()> {
    let (host, dest) = split_remote(target)?;
    if !src.is_file() {
        abort!("not a regular file: {}", src.display());
    }
    cloud_warning(src);
    let name = src
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (h0, n0) = sha256_file(src)?;
    say(&format!(
        "1/6 hashed   {}  {n0} bytes  sha256 {}...",
        src.display(),
        &h0[..16]
    ));

    let p = parse(&run(&host, &r_probe(&dest, &name))?, "probe", 4)?;
    let (state, ph, ps, mut rdest) = (p[0].clone(), p[1].clone(), p[2].clone(), p[3].clone());
    if state == "exists" {
        if ph != h0 || ps.parse::<u64>().ok() != Some(n0) {
            abort!("destination exists and differs: {host}:{rdest}; source kept");
        }
        say(&format!(
            "2-4/6 {host}:{rdest} already holds this exact file (earlier run); skipping to shred"
        ));
        return finish_push(src, &host, &rdest, &h0, n0, sc);
    }

    let t = Instant::now();
    let sent = File::open(src)
        .map_err(Abort::from)
        .and_then(|f| run_with_file(&host, &r_receive(&rdest), f))
        .and_then(|o| parse(&o, "send", 3));
    let v = match sent {
        Ok(v) => v,
        Err(e) => {
            let part = format!("{rdest}.sxfer-part");
            let cleaned = run(&host, &format!("rm -f {}", q(&part)))
                .map(|o| o.rc == 0)
                .unwrap_or(false);
            abort!(
                "{e}\n        source untouched; partial upload {}; rerun the same command to retry",
                if cleaned {
                    "removed".to_string()
                } else {
                    format!("may remain at {host}:{part} (server unreachable)")
                }
            );
        }
    };
    let (rh, rs) = (v[0].clone(), v[1].parse::<u64>().unwrap_or(u64::MAX));
    rdest = v[2].clone();
    say(&format!(
        "2/6 sent     -> {host}:{rdest}.sxfer-part  ({:.1} MB/s)",
        mbps(n0, t)
    ));

    let (h1, n1) = sha256_file(src)?;
    if rh != h0 || rs != n0 || h1 != h0 || n1 != n0 {
        let _ = run(
            &host,
            &format!("rm -f {}", q(&format!("{rdest}.sxfer-part"))),
        );
        abort!("VERIFY FAILED: local {h0}/{n0}, after-send {h1}/{n1}, remote {rh}/{rs}; .part removed, source kept");
    }
    say("3/6 verified remote copy (re-read from disk) matches");

    let c = run(&host, &r_commit(&format!("{rdest}.sxfer-part"), &rdest))
        .and_then(|o| parse(&o, "commit", 3))
        .map_err(|e| {
            Abort(format!(
                "{e}\n        commit outcome unknown; source kept. Rerun the same command: if the file arrived intact it is recognised and the run finishes"
            ))
        })?;
    if c[0] != h0 || c[1].parse::<u64>().ok() != Some(n0) {
        abort!(
            "COMMITTED FILE MISMATCH ({}/{}); source kept - investigate {host}:{}",
            c[0],
            c[1],
            c[2]
        );
    }
    say(&format!(
        "4/6 committed {host}:{}  (receipt confirmed)",
        c[2]
    ));
    finish_push(src, &host, &c[2], &h0, n0, sc)
}

fn finish_push(
    src: &Path,
    host: &str,
    final_path: &str,
    h0: &str,
    n0: u64,
    sc: &ShredCfg,
) -> R<()> {
    let mut shredded = false;
    if sc.keep {
        say("5/6 --keep: source left in place");
    } else if confirm(
        &format!(
            "Receipt confirmed on {host}. Shred local {}?",
            src.display()
        ),
        sc.ask,
    ) {
        shred_local(src, sc.passes)?;
        shredded = true;
        say(&format!(
            "5/6 shredded  {}  ({} random passes + zeros, renamed, unlinked)",
            src.display(),
            sc.passes
        ));
    } else {
        say("5/6 not shredded (declined)");
    }
    let abs = std::fs::canonicalize(src).unwrap_or_else(|_| src.to_path_buf());
    let rec = json!({"time": now_iso(), "op": "push", "from": host_name(), "src": abs.to_string_lossy(),
                     "dest": final_path, "bytes": n0, "sha256": h0, "shredded": shredded});
    match run_with_data(host, R_RECEIPT, format!("{rec}\n").as_bytes()) {
        Ok(o) if o.rc == 0 => say(&format!(
            "6/6 receipt  {host}:~/.sxfer/receipts.jsonl  (nothing logged here)"
        )),
        _ => say(&format!(
            "6/6 WARNING: could not write the receipt on {host}; the transfer itself is complete"
        )),
    }
    Ok(())
}

fn local_dest(dest: &Path, name: &str) -> R<PathBuf> {
    let s = dest.to_string_lossy();
    let d = if s.ends_with('/') || s.ends_with('\\') || dest.is_dir() {
        dest.join(name)
    } else {
        dest.to_path_buf()
    };
    let parent = match d.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    if !parent.is_dir() {
        abort!("no such directory: {}", parent.display());
    }
    Ok(d)
}

pub fn pull(source: &str, dest: &Path, sc: &ShredCfg) -> R<()> {
    let (host, src) = split_remote(source)?;
    let st = parse(&run(&host, &r_stat(&src))?, "stat", 3)?;
    let (h0, n0) = (st[0].clone(), st[1].parse::<u64>().unwrap_or(u64::MAX));
    say(&format!(
        "1/6 hashed   {host}:{src}  {n0} bytes  sha256 {}...",
        &h0[..16.min(h0.len())]
    ));
    let name = Path::new(&src)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    let dest = local_dest(dest, &name)?;
    if dest.exists() {
        if sha256_file(&dest)? != (h0.clone(), n0) {
            abort!(
                "destination exists and differs: {}; source kept",
                dest.display()
            );
        }
        say(&format!(
            "2-4/6 {} already holds this exact file (earlier run); skipping to shred",
            dest.display()
        ));
        return finish_pull(&host, &src, &dest, &h0, n0, sc);
    }
    let part = PathBuf::from(format!("{}.sxfer-part", dest.display()));
    let t = Instant::now();
    let res: R<()> = (|| {
        let f = create_new_private(&part)?;
        let o = run_to_file(&host, &format!("cat -- {}", q(&src)), f.try_clone()?)?;
        f.sync_all()?;
        drop(f);
        if o.rc != 0 {
            abort!("send failed (ssh rc {}): {}", o.rc, o.err.trim());
        }
        say(&format!(
            "2/6 received -> {}  ({:.1} MB/s)",
            part.display(),
            mbps(n0, t)
        ));
        let (lh, ln) = sha256_file(&part)?;
        let again = parse(&run(&host, &r_stat(&src))?, "re-stat", 3)?;
        if lh != h0 || ln != n0 || again[0] != h0 || again[1].parse::<u64>().ok() != Some(n0) {
            abort!(
                "VERIFY FAILED: remote {h0}/{n0}, remote-after {}/{}, local {lh}/{ln}; source kept",
                again[0],
                again[1]
            );
        }
        say("3/6 verified local copy (re-read from disk) matches");
        rename_no_clobber(&part, &dest)
    })();
    if let Err(e) = res {
        let _ = std::fs::remove_file(&part);
        return Err(e);
    }
    if sha256_file(&dest)? != (h0.clone(), n0) {
        abort!(
            "COMMITTED FILE MISMATCH; source kept - investigate {}",
            dest.display()
        );
    }
    say(&format!(
        "4/6 committed {}  (receipt confirmed)",
        dest.display()
    ));
    finish_pull(&host, &src, &dest, &h0, n0, sc)
}

fn finish_pull(host: &str, src: &str, dest: &Path, h0: &str, n0: u64, sc: &ShredCfg) -> R<()> {
    let mut shredded = false;
    if sc.keep {
        say("5/6 --keep: remote source left in place");
    } else if confirm(
        &format!("Receipt confirmed locally. Shred {host}:{src}?"),
        sc.ask,
    ) {
        let r = run(host, &r_shred(src, sc.passes)).and_then(|o| parse(&o, "remote shred", 1));
        if let Err(e) = r {
            abort!(
                "{e}\n        your copy is safe and verified at {}; the remote shred may not have finished (it ignores hang-ups, so it usually does). Check: ssh {host} ls -l {}",
                dest.display(),
                q(src)
            );
        }
        shredded = true;
        say(&format!(
            "5/6 shredded  {host}:{src}  (shred -n {} -z -u)",
            sc.passes
        ));
    } else {
        say("5/6 not shredded (declined)");
    }
    let abs = std::fs::canonicalize(dest).unwrap_or_else(|_| dest.to_path_buf());
    let p = receipt_local(
        &json!({"time": now_iso(), "op": "pull", "src": format!("{host}:{src}"),
        "dest": abs.to_string_lossy(), "bytes": n0, "sha256": h0, "shredded": shredded}),
    )?;
    say(&format!("6/6 receipt  {}", p.display()));
    Ok(())
}
