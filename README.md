# sxfer

[![build](https://github.com/Kalaghni/sxfer/actions/workflows/build.yml/badge.svg)](https://github.com/Kalaghni/sxfer/actions/workflows/build.yml)

Move a file - or a secret like a password or OTP - from one machine to another: encrypted in
transit, receipt proven against the receiver's disk, then (once you say yes) the source is
shredded. One static binary, no runtime dependencies.

## LAN: direct, paired by a one-time code

```
# receiver
sxfer listen                      # prints a one-time code, e.g. 482-913
sxfer listen --dir ~/Downloads    # choose where files land

# sender (once per network)
sxfer config add 192.168.2.0/24   # networks you'll connect to (IP or CIDR) - an allowlist
sxfer config list | remove <net>

# sender
sxfer send report.pdf             # finds the listener, asks for the code, sends, asks, shreds
sxfer send                        # no file: type a secret (hidden); shown once on the receiver, never saved
echo "$OTP" | sxfer send          # secret from stdin
sxfer send file --to 192.168.2.50:51234   # skip discovery (the listener prints its port)
```

There's no fixed port. The listener takes any free TCP port and advertises it over **Bonjour /
mDNS** (`_sxfer._tcp.local.`); the sender browses for it and only connects to listeners whose
address is inside a configured network, so a listener seen via a VPN, Docker bridge or guest
network is ignored. No Bonjour/avahi install is needed (pure-Rust responder). The receiving
machine's firewall must allow `sxfer` (on Windows, allow it when prompted) and mDNS (UDP 5353),
which is usually already open on home networks.

## SSH: through your existing ssh setup

```
sxfer push secrets.txt myserver:/root/    # send, verify, confirm, shred the local copy
sxfer pull myserver:/root/secrets.txt .   # fetch, verify, confirm, shred the remote copy
```

Uses your `ssh` client and `~/.ssh/config` (aliases, keys, agents). The remote side needs only
`sh`, coreutils `sha256sum` and `shred`.

## Options (send / push / pull)

| | |
|---|---|
| `--keep` | verify and commit, but don't shred the source |
| `-y`, `--yes` | shred without asking, this time |
| `--ask` | ask before shredding, this time (when confirmation is turned off) |
| `--passes N` | random overwrite passes before the final zero pass (default 3) |

### Shred confirmation

Once the receipt checks out, sxfer asks `Shred <file>? [y/N]` before touching the source. Anything
but `y` keeps it. With no terminal to ask on (cron, CI) and no `-y`, the source is kept too.

```
sxfer config confirm          # show the setting
sxfer config confirm off      # shred as soon as receipt is confirmed (the pre-0.5 behaviour)
sxfer config confirm on       # ask first (the default)
```

The setting lives in `~/.sxfer/config.json` (`"confirm_shred": false`) on the machine running
send / push / pull. `-y` and `--ask` override it for one run.

## How it works

1. **Hash** the source (SHA-256 + size).
2. **Send** into `<name>.sxfer-part` on the receiver (mode 600 on Unix), fsync.
3. **Verify** - the receiver re-reads the file *from disk* and checks it; the sender re-hashes its
   source too (catches a file that changed mid-transfer).
4. **Commit** - atomic, never overwrites an existing file. If the destination already holds the
   identical file (an earlier run whose receipt got lost), it counts as delivered.
5. **Shred** the source, once confirmed: N random passes + zeros, fsync each, truncate, rename,
   unlink.
6. **Receipt** - logged on the **destination only** (`~/.sxfer/receipts.jsonl`). The source keeps no
   record of what it shredded.

Any failure before step 5 deletes the partial copy and leaves the source untouched; just rerun.
SSH mode uses keepalives and a hang-up-proof remote shred, so a dropped connection is detected in
about 30 s and never interrupts a shred halfway.

### LAN security

- **SPAKE2** (Ed25519 group) turns the 6-digit code into a strong shared key. The code never crosses
  the network, an eavesdropper can't test guesses offline, and an active attacker gets one guess per
  connection. The listener closes after 3 wrong codes (odds of guessing: 3 in a million).
- **ChaCha20-Poly1305** with HKDF-SHA256-derived keys, one per direction, counter nonces.
- File names from the sender are reduced to a bare name (no paths, no `..`).
- Secrets are capped at 64 KiB, shown once on the receiver's terminal, and never written to disk.

### Shredding caveat

Overwriting is reliable on spinning disks. On SSDs (wear levelling), copy-on-write or journaling
filesystems, cloud-synced folders (OneDrive/Dropbox, which sxfer warns about), snapshots and
backups, old copies of the data can survive. Full-disk encryption (BitLocker / FileVault / LUKS)
is what really protects deleted data.

## Building

```
cargo test
./build.sh        # Linux/WSL: cross-compiles all six targets into dist/ (needs zig + cargo-zigbuild)
```

Every push and pull request runs `.github/workflows/build.yml`: fmt, clippy and tests on Linux,
Windows and macOS, then native builds for Linux (x86-64, ARM64, static), Windows (x86-64, ARM64)
and macOS (Intel, Apple Silicon), uploaded as workflow artifacts. Tagging `vX.Y.Z` also publishes
them to a GitHub release with `SHA256SUMS`.

## Download

Grab a binary from [Releases](https://github.com/Kalaghni/sxfer/releases), or the artifacts of the
latest [build run](https://github.com/Kalaghni/sxfer/actions). Check it against `SHA256SUMS`, then
put it on your PATH. On macOS, a downloaded binary may need `xattr -d com.apple.quarantine sxfer`.
