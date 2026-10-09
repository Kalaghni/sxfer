#!/usr/bin/env python3
"""
sxfer - move a file between machines over SSH: encrypted transfer, proven receipt, then shred the source.

    sxfer push <local-file>  <host>:<remote-path>     local  -> remote, shred the local copy
    sxfer pull <host>:<remote-file> <local-path>      remote -> local,  shred the remote copy

    options:  --keep     verify and commit, but don't shred the source
              --passes N overwrite passes when shredding (default 3, then zeros)
              --ask      ask before shredding (default: shred as soon as receipt is confirmed)

<host> is anything `ssh` accepts (aliases from ~/.ssh/config, e.g. web1). A path ending in / or naming
an existing directory receives the file under its own name. Existing files are never overwritten.

PROTOCOL (each step must succeed before the next; any failure leaves the source intact)
  1. HASH     sha256 + size of the source.
  2. SEND     stream over SSH (ciphers/auth = your SSH config) into <dest>.sxfer-part, mode 600, fsync.
  3. VERIFY   the receiver re-reads the .part FROM DISK and returns its sha256 + size; the source is
              re-hashed too (catches a source that changed mid-transfer). Mismatch -> delete .part, abort.
  4. COMMIT   atomic no-clobber rename .part -> <dest>, fsync, hash the final file once more.
  5. SHRED    overwrite the source N times with random data + once with zeros, fsync after every pass,
              truncate, rename to a random name, unlink. Confirm it no longer exists.
  6. RECEIPT  append a JSON line to ~/.sxfer/receipts.jsonl ON THE DESTINATION only (time, paths, size,
              sha256, shredded). The source machine keeps no record of the file it shredded.

SHRED CAVEAT: overwriting is reliable on spinning disks. On SSDs (wear levelling), copy-on-write or
journaling filesystems, cloud-synced folders (OneDrive/Dropbox), snapshots and backups, old copies of the
data can survive. Full-disk encryption (BitLocker / LUKS) is what really protects deleted data there.
"""
import argparse, hashlib, json, os, secrets, shlex, subprocess, sys, time

CHUNK = 1 << 20
ERR = 'SXFER-ERR'
OK = 'SXFER-OK'


class Abort(Exception):
    pass


def say(msg):
    print(f'sxfer: {msg}', file=sys.stderr, flush=True)


def sha256_file(path):
    h, n = hashlib.sha256(), 0
    with open(path, 'rb') as f:
        while b := f.read(CHUNK):
            h.update(b)
            n += len(b)
    return h.hexdigest(), n


def split_remote(spec):
    if ':' not in spec or (os.name == 'nt' and len(spec) > 1 and spec[1] == ':' and len(spec.split(':')[0]) == 1):
        raise Abort(f'expected host:path, got {spec!r}')
    host, path = spec.split(':', 1)
    if not host or not path:
        raise Abort(f'expected host:path, got {spec!r}')
    return host, path


def ssh(host, script, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, data=None):
    """Run a POSIX sh script on host (data, if given, is fed to its stdin). Returns (rc, stdout_text_or_None, stderr_text)."""
    p = subprocess.run(['ssh', '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=3', host, 'sh -c ' + shlex.quote(script)],
                       input=data, stdin=None if data is not None else stdin, stdout=stdout, stderr=subprocess.PIPE)
    out = p.stdout.decode(errors='replace') if isinstance(p.stdout, bytes) else None
    return p.returncode, out, p.stderr.decode(errors='replace')


def parse(out, rc, err, what, fields=3):
    for line in (out or '').splitlines():
        if line.startswith(OK + ' '):
            return line.split(' ', fields)[1:]
        if line.startswith(ERR):
            raise Abort(f'{what}: {line[len(ERR):].strip()}')
    raise Abort(f'{what} failed (ssh rc {rc}): {err.strip() or out}')


# remote helpers (POSIX sh + coreutils)
R_HASH = 'h=$(sha256sum < "$1" | cut -d" " -f1); s=$(wc -c < "$1" | tr -d " ")'


def r_probe(dest, name):
    return f'''set -u
d={shlex.quote(dest)}; b={shlex.quote(name)}
case "$d" in */) d="$d$b";; esac
[ -d "$d" ] && d="${{d%/}}/$b"
[ -d "$(dirname "$d")" ] || {{ echo "{ERR} no such directory: $(dirname "$d")"; exit 3; }}
if [ -e "$d" ]; then set -- "$d"; {R_HASH}; echo "{OK} exists $h $s $d"; else echo "{OK} absent - 0 $d"; fi'''


def r_receive(dest, name):
    return f'''set -u; umask 077
d={shlex.quote(dest)}; b={shlex.quote(name)}
case "$d" in */) d="$d$b";; esac
[ -d "$d" ] && d="${{d%/}}/$b"
[ -e "$d" ] && {{ echo "{ERR} destination exists: $d"; exit 3; }}
[ -d "$(dirname "$d")" ] || {{ echo "{ERR} no such directory: $(dirname "$d")"; exit 3; }}
p="$d.sxfer-part"; rm -f "$p"
cat > "$p" || {{ echo "{ERR} write failed"; rm -f "$p"; exit 4; }}
sync "$p" 2>/dev/null || sync
set -- "$p"; {R_HASH}
echo "{OK} $h $s $d"'''


def r_commit(part, dest):
    return f'''set -u
p={shlex.quote(part)}; d={shlex.quote(dest)}
[ -e "$d" ] && {{ echo "{ERR} destination appeared meanwhile: $d"; exit 3; }}
ln "$p" "$d" 2>/dev/null && rm -f "$p" || mv -n "$p" "$d"
[ -e "$p" ] && {{ echo "{ERR} commit failed"; exit 4; }}
sync "$d" 2>/dev/null || sync
set -- "$d"; {R_HASH}
echo "{OK} $h $s $d"'''


def r_stat(path):
    return f'''set -u; f={shlex.quote(path)}
[ -f "$f" ] || {{ echo "{ERR} not a regular file: $f"; exit 3; }}
set -- "$f"; {R_HASH}
echo "{OK} $h $s $f"'''


def r_shred(path, passes):
    return f'''set -u; trap "" HUP PIPE; f={shlex.quote(path)}
command -v shred >/dev/null || {{ echo "{ERR} shred not installed"; exit 5; }}
shred -n {int(passes)} -z -u -- "$f" || {{ echo "{ERR} shred failed"; exit 5; }}
[ -e "$f" ] && {{ echo "{ERR} file still exists"; exit 5; }}
sync; echo "{OK} shredded"'''


def shred_local(path, passes):
    size = os.path.getsize(path)
    try:
        os.chmod(path, 0o600)              # clears read-only on Windows
    except OSError:
        pass
    with open(path, 'r+b', buffering=0) as f:
        for i in range(passes + 1):
            f.seek(0)
            left = size
            while left:
                n = min(CHUNK, left)
                f.write(os.urandom(n) if i < passes else bytes(n))
                left -= n
            os.fsync(f.fileno())
        f.truncate(0)
        os.fsync(f.fileno())
    junk = os.path.join(os.path.dirname(os.path.abspath(path)), secrets.token_hex(8))
    os.replace(path, junk)
    os.remove(junk)
    if os.path.exists(path) or os.path.exists(junk):
        raise Abort('shred: file still exists afterwards')


def cloud_warning(path):
    p = os.path.abspath(path).lower()
    for marker in ('onedrive', 'dropbox', 'google drive', 'icloud'):
        if marker in p:
            say(f'WARNING: source is in a {marker} folder; the cloud copy and its version history are NOT shredded')


def confirm(question, assume_yes):
    if assume_yes:
        return True
    prompt = f'{question} [y/N] '
    try:
        if sys.stdin.isatty():
            return input(prompt).strip().lower() in ('y', 'yes')
        with open('CONIN$' if os.name == 'nt' else '/dev/tty', 'r') as tty:
            print(prompt, end='', file=sys.stderr, flush=True)
            return tty.readline().strip().lower() in ('y', 'yes')
    except (OSError, EOFError):
        say('no terminal to confirm on; not shredding (drop --ask to shred automatically)')
        return False


def receipt_remote(host, rec):
    """Push: the receipt lives on the destination. The source keeps no record of what it shredded."""
    rc, _, _ = ssh(host, 'umask 077; mkdir -p "$HOME/.sxfer" && cat >> "$HOME/.sxfer/receipts.jsonl"',
                   data=(json.dumps(rec) + '\n').encode())
    return rc == 0


def receipt(rec):
    """Pull: this machine is the destination."""
    d = os.path.join(os.path.expanduser('~'), '.sxfer')
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, 'receipts.jsonl'), 'a', encoding='utf-8') as f:
        f.write(json.dumps(rec) + '\n')


def push(src, target, a):
    host, dest = split_remote(target)
    if not os.path.isfile(src):
        raise Abort(f'not a regular file: {src}')
    cloud_warning(src)
    h0, n0 = sha256_file(src)
    say(f'1/6 hashed   {src}  {n0} bytes  sha256 {h0[:16]}...')
    rc, out, err = ssh(host, r_probe(dest, os.path.basename(src)))
    state, ph, ps, rdest = parse(out, rc, err, 'probe', fields=4)
    if state == 'exists':
        if (ph, int(ps)) != (h0, n0):
            raise Abort(f'destination exists and differs: {host}:{rdest}; source kept')
        say(f'2-4/6 {host}:{rdest} already holds this exact file (earlier run); skipping to shred')
        return finish_push(src, host, rdest, h0, n0, a)
    t = time.time()
    try:
        with open(src, 'rb') as f:
            rc, out, err = ssh(host, r_receive(rdest, os.path.basename(src)), stdin=f)
        rh, rs, rdest = parse(out, rc, err, 'send')
    except Abort as e:
        part = rdest + '.sxfer-part'
        crc, _, _ = ssh(host, f'rm -f {shlex.quote(part)}')
        raise Abort(f'{e}\n        source untouched; partial upload '
                    + ('removed' if crc == 0 else f'may remain at {host}:{part} (server unreachable)')
                    + '; rerun the same command to retry')
    say(f'2/6 sent     -> {host}:{rdest}.sxfer-part  ({n0 / max(time.time() - t, 0.001) / 1e6:.1f} MB/s)')
    h1, n1 = sha256_file(src)
    if (rh, int(rs)) != (h0, n0) or (h1, n1) != (h0, n0):
        ssh(host, f'rm -f {shlex.quote(rdest + ".sxfer-part")}')
        raise Abort(f'VERIFY FAILED: local {h0}/{n0}, after-send {h1}/{n1}, remote {rh}/{rs}; .part removed, source kept')
    say('3/6 verified remote copy (re-read from disk) matches')
    try:
        rc, out, err = ssh(host, r_commit(rdest + '.sxfer-part', rdest))
        ch, cs, final = parse(out, rc, err, 'commit')
    except Abort as e:
        raise Abort(f'{e}\n        commit outcome unknown; source kept. Rerun the same command: '
                    'if the file arrived intact it is recognised and the run finishes')
    if (ch, int(cs)) != (h0, n0):
        raise Abort(f'COMMITTED FILE MISMATCH ({ch}/{cs}); source kept - investigate {host}:{final}')
    say(f'4/6 committed {host}:{final}  (receipt confirmed)')
    finish_push(src, host, final, h0, n0, a)


def finish_push(src, host, final, h0, n0, a):
    shredded = False
    if a.keep:
        say('5/6 --keep: source left in place')
    elif confirm(f'Receipt confirmed on {host}. Shred local {src}?', not a.ask):
        shred_local(src, a.passes)
        shredded = True
        say(f'5/6 shredded  {src}  ({a.passes} random passes + zeros, renamed, unlinked)')
    else:
        say('5/6 not shredded (declined)')
    rec = {'time': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'op': 'push', 'src': os.path.abspath(src),
           'dest': final, 'bytes': n0, 'sha256': h0, 'shredded': shredded}
    if receipt_remote(host, rec):
        say(f'6/6 receipt  {host}:~/.sxfer/receipts.jsonl  (nothing logged here)')
    else:
        say(f'6/6 WARNING: could not write the receipt on {host}; the transfer itself is complete')


def local_dest_path(dest, name):
    if dest.endswith(('/', '\\')) or os.path.isdir(dest):
        dest = os.path.join(dest, name)
    if not os.path.isdir(os.path.dirname(os.path.abspath(dest))):
        raise Abort(f'no such directory: {os.path.dirname(os.path.abspath(dest))}')
    return dest


def pull(source, dest, a):
    host, src = split_remote(source)
    rc, out, err = ssh(host, r_stat(src))
    h0, n0, _ = parse(out, rc, err, 'stat')
    n0 = int(n0)
    say(f'1/6 hashed   {host}:{src}  {n0} bytes  sha256 {h0[:16]}...')
    dest = local_dest_path(dest, os.path.basename(src))
    if os.path.exists(dest):
        if sha256_file(dest) != (h0, n0):
            raise Abort(f'destination exists and differs: {dest}; source kept')
        say(f'2-4/6 {dest} already holds this exact file (earlier run); skipping to shred')
        return finish_pull(host, src, dest, h0, n0, a)
    part = dest + '.sxfer-part'
    t = time.time()
    fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0), 0o600)
    try:
        with os.fdopen(fd, 'wb') as f:
            rc, _, err = ssh(host, f'cat -- {shlex.quote(src)}', stdout=f)
            f.flush()
            os.fsync(f.fileno())
        if rc != 0:
            raise Abort(f'send failed (ssh rc {rc}): {err.strip()}')
        say(f'2/6 received -> {part}  ({n0 / max(time.time() - t, 0.001) / 1e6:.1f} MB/s)')
        lh, ln_ = sha256_file(part)
        rc, out, err = ssh(host, r_stat(src))
        h1, n1, _ = parse(out, rc, err, 're-stat')
        if (lh, ln_) != (h0, n0) or (h1, int(n1)) != (h0, n0):
            raise Abort(f'VERIFY FAILED: remote {h0}/{n0}, remote-after {h1}/{n1}, local {lh}/{ln_}; source kept')
        say('3/6 verified local copy (re-read from disk) matches')
        if os.path.exists(dest):
            raise Abort(f'destination appeared meanwhile: {dest}')
        os.rename(part, dest)                      # Windows refuses to overwrite; checked above for POSIX
    except BaseException:
        if os.path.exists(part):
            os.remove(part)
        raise
    ch, cn = sha256_file(dest)
    if (ch, cn) != (h0, n0):
        raise Abort(f'COMMITTED FILE MISMATCH; source kept - investigate {dest}')
    say(f'4/6 committed {dest}  (receipt confirmed)')
    finish_pull(host, src, dest, h0, n0, a)


def finish_pull(host, src, dest, h0, n0, a):
    shredded = False
    if a.keep:
        say('5/6 --keep: remote source left in place')
    elif confirm(f'Receipt confirmed locally. Shred {host}:{src}?', not a.ask):
        rc, out, err = ssh(host, r_shred(src, a.passes))
        try:
            parse(out, rc, err, 'remote shred')
        except Abort as e:
            raise Abort(f'{e}\n        your copy is safe and verified at {dest}; the remote shred may not have finished '
                        f'(it ignores hang-ups, so it usually does). Check: ssh {host} ls -l {shlex.quote(src)}')
        shredded = True
        say(f'5/6 shredded  {host}:{src}  (shred -n {a.passes} -z -u)')
    else:
        say('5/6 not shredded (declined)')
    receipt({'time': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'op': 'pull', 'src': f'{host}:{src}',
             'dest': os.path.abspath(dest), 'bytes': n0, 'sha256': h0, 'shredded': shredded})
    say('6/6 receipt  ~/.sxfer/receipts.jsonl')


def main():
    ap = argparse.ArgumentParser(prog='sxfer', description='Encrypted transfer over SSH, proven receipt, then shred the source.')
    ap.add_argument('op', choices=['push', 'pull'])
    ap.add_argument('source')
    ap.add_argument('dest')
    ap.add_argument('--keep', action='store_true', help="don't shred the source")
    ap.add_argument('--passes', type=int, default=3, help='random overwrite passes before the zero pass (default 3)')
    ap.add_argument('--ask', action='store_true', help='ask before shredding (default: shred once receipt is confirmed)')
    ap.add_argument('--yes', '-y', action='store_true', help=argparse.SUPPRESS)   # old flag; now the default
    a = ap.parse_args()
    if a.passes < 1:
        ap.error('--passes must be >= 1')
    try:
        (push if a.op == 'push' else pull)(a.source, a.dest, a)
    except Abort as e:
        say(f'ABORTED: {e}')
        sys.exit(1)
    except KeyboardInterrupt:
        say('interrupted; source untouched unless step 5 had started')
        sys.exit(130)


if __name__ == '__main__':
    main()
