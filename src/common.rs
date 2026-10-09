//! Shared pieces: errors, hashing, shredding, prompts, receipts, config dir.

use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, IsTerminal, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub const CHUNK: usize = 1 << 20;

/// A clean, user-facing failure. The source is never touched once one of these is raised
/// before the shred step.
#[derive(Debug)]
pub struct Abort(pub String);

impl std::fmt::Display for Abort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<io::Error> for Abort {
    fn from(e: io::Error) -> Self {
        Abort(e.to_string())
    }
}

pub type R<T> = Result<T, Abort>;

#[macro_export]
macro_rules! abort {
    ($($t:tt)*) => { return Err($crate::common::Abort(format!($($t)*))) };
}

pub fn say(msg: &str) {
    eprintln!("sxfer: {msg}");
}

#[derive(Clone, Debug)]
pub struct ShredCfg {
    pub keep: bool,
    pub ask: bool,
    pub passes: u32,
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn random_hex(nbytes: usize) -> String {
    let mut b = vec![0u8; nbytes];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex(&b)
}

pub fn sha256_bytes(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

/// sha256 + size of a file, read back from disk.
pub fn sha256_file(p: &Path) -> R<(String, u64)> {
    let mut f = File::open(p).map_err(|e| Abort(format!("{}: {e}", p.display())))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut n = 0u64;
    loop {
        let k = f.read(&mut buf)?;
        if k == 0 {
            break;
        }
        h.update(&buf[..k]);
        n += k as u64;
    }
    Ok((hex(&h.finalize()), n))
}

/// Overwrite `passes` times with random data and once with zeros (fsync after each pass),
/// truncate, rename to a random name, unlink, and confirm it's gone.
pub fn shred_local(p: &Path, passes: u32) -> R<()> {
    let meta = fs::metadata(p)?;
    let size = meta.len();
    let mut perms = meta.permissions();
    if perms.readonly() {
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        fs::set_permissions(p, perms)?;
    }
    {
        let mut f = OpenOptions::new().write(true).open(p)?;
        let mut buf = vec![0u8; CHUNK];
        for pass in 0..=passes {
            f.seek(SeekFrom::Start(0))?;
            let mut left = size;
            while left > 0 {
                let n = left.min(CHUNK as u64) as usize;
                if pass < passes {
                    rand::rngs::OsRng.fill_bytes(&mut buf[..n]);
                } else {
                    buf[..n].fill(0);
                }
                f.write_all(&buf[..n])?;
                left -= n as u64;
            }
            f.sync_all()?;
        }
        f.set_len(0)?;
        f.sync_all()?;
    }
    let dir = match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let junk = dir.join(random_hex(8));
    fs::rename(p, &junk)?;
    fs::remove_file(&junk)?;
    if p.exists() || junk.exists() {
        crate::abort!("shred: file still exists afterwards");
    }
    Ok(())
}

pub fn cloud_warning(p: &Path) {
    let abs = fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let s = abs.to_string_lossy().to_lowercase();
    for m in ["onedrive", "dropbox", "google drive", "icloud"] {
        if s.contains(m) {
            say(&format!("WARNING: source is in a {m} folder; the cloud copy and its version history are NOT shredded"));
        }
    }
}

fn tty_line(prompt: &str) -> Option<String> {
    eprint!("{prompt}");
    let _ = io::stderr().flush();
    if io::stdin().is_terminal() {
        let mut s = String::new();
        io::stdin().lock().read_line(&mut s).ok()?;
        return Some(s);
    }
    let tty = if cfg!(windows) { "CONIN$" } else { "/dev/tty" };
    let f = File::open(tty).ok()?;
    let mut s = String::new();
    io::BufReader::new(f).read_line(&mut s).ok()?;
    Some(s)
}

/// Read a line from the user (stdin, or the terminal if stdin is redirected).
pub fn prompt_line(prompt: &str) -> R<String> {
    tty_line(prompt)
        .map(|s| s.trim().to_string())
        .ok_or_else(|| Abort("no terminal to read from".into()))
}

/// Ask on the terminal before shredding, unless `ask` is false (-y, or `sxfer config confirm off`).
/// With no terminal to ask on, the answer is no and the source is kept.
pub fn confirm(question: &str, ask: bool) -> bool {
    if !ask {
        return true;
    }
    match tty_line(&format!("{question} [y/N] ")) {
        Some(a) => matches!(a.trim().to_lowercase().as_str(), "y" | "yes"),
        None => {
            say("no terminal to ask on; not shredding (-y or `sxfer config confirm off` to skip)");
            false
        }
    }
}

/// ~/.sxfer, or $SXFER_HOME (used by the tests).
pub fn sxfer_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("SXFER_HOME") {
        return PathBuf::from(d);
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".sxfer")
}

fn private_dir(d: &Path) -> R<()> {
    fs::create_dir_all(d)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Receipts live on the DESTINATION only; the source keeps no record of what it shredded.
pub fn receipt_local(rec: &serde_json::Value) -> R<PathBuf> {
    let d = sxfer_dir();
    private_dir(&d)?;
    let p = d.join("receipts.jsonl");
    let mut f = OpenOptions::new().create(true).append(true).open(&p)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600))?;
    }
    writeln!(f, "{rec}")?;
    Ok(p)
}

pub fn now_iso() -> String {
    // seconds since epoch is unambiguous and needs no timezone database
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{t}")
}

pub fn host_name() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".into())
}

/// Create `p` exclusively (fails if it exists), private on unix.
pub fn create_new_private(p: &Path) -> R<File> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(p)
        .map_err(|e| Abort(format!("{}: {e}", p.display())))
}

/// Rename `from` -> `to` without ever replacing an existing `to`.
pub fn rename_no_clobber(from: &Path, to: &Path) -> R<()> {
    if to.exists() {
        crate::abort!("destination appeared meanwhile: {}", to.display());
    }
    #[cfg(unix)]
    {
        // hard link is atomic and fails if `to` exists
        fs::hard_link(from, to).map_err(|e| Abort(format!("commit: {e}")))?;
        fs::remove_file(from)?;
        if let Some(d) = to.parent() {
            if let Ok(df) = File::open(if d.as_os_str().is_empty() {
                Path::new(".")
            } else {
                d
            }) {
                let _ = df.sync_all();
            }
        }
    }
    #[cfg(not(unix))]
    {
        // Windows refuses to rename onto an existing file
        fs::rename(from, to).map_err(|e| Abort(format!("commit: {e}")))?;
    }
    Ok(())
}
