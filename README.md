# sxfer

[![build](https://github.com/Kalaghni/sxfer/actions/workflows/build.yml/badge.svg)](https://github.com/Kalaghni/sxfer/actions/workflows/build.yml)

Move a file - or a secret like a password or OTP - from one machine to another: encrypted in
transit, receipt proven against the receiver's disk, then (once you say yes) the source is
shredded. One static binary, no runtime dependencies. LAN transfers are post-quantum: ML-KEM-768
key exchange, ML-DSA-65 signed peers and receipts.

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
sxfer send file --receipt r.json  # keep the listener's signed receipt (`sxfer receipt verify r.json`)
```

### Pinned peers: skip the code between your own machines

Every machine has a post-quantum identity (an ML-DSA-65 key, made on first use). Pin each other once
and they can pair without a code, like ssh `known_hosts`:

```
sxfer id                                   # this machine's name and fingerprint
sxfer listen --remember                    # after a transfer with the code, pin the sender
sxfer send report.pdf --remember           # ... and the sender pins the listener
sxfer trust add laptop 3f2a-91c0-...       # or pin by fingerprint, compared in person or by phone
sxfer trust list | remove <name>

sxfer listen --trusted                     # also accept pinned senders without the code
sxfer send report.pdf                      # a pinned --trusted listener: no code asked
sxfer send report.pdf --to 10.8.0.2:51234 --no-code   # same over a VPN (no mDNS there)
```

A pinned name that shows up with a different key is refused, even with the right code
(`KEY CHANGED`). If that machine was reinstalled, `sxfer trust remove <name>` and pair once with a
code.

LAN mode in sxfer 0.7 speaks protocol v2: both sides need 0.7 or later.

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

## MCP server: let an AI assistant move files

`sxfer-mcp` is a second binary that speaks the [Model Context Protocol](https://modelcontextprotocol.io)
over stdio, so an assistant such as Claude can send, push, pull and receive files with the same
hash / verify / commit / shred steps.

```
claude mcp add sxfer -- sxfer-mcp          # Claude Code; other clients: command `sxfer-mcp`, no args
```

| Tool | |
|---|---|
| `send_file` | LAN send to an `sxfer listen` receiver (`path`, `code`, optional `to`, `keep`, `passes`) |
| `push_file` / `pull_file` | over SSH, like `sxfer push` / `pull` |
| `start_listener` / `listener_status` / `stop_listener` | receive one file in the background; returns the code for the sender |
| `discover_listeners`, `get_config` | read-only |

Results name the peer it paired with (ML-DSA-65 fingerprint, pinned or not); `send_file` can skip
the code for a receiver you pinned that runs `--trusted`, and `start_listener` takes `trusted`.

Rules that hold whatever the model asks:

- **You decide on every shred, not the model.** Once the receiver's copy is verified, the server asks
  *you* directly through an MCP prompt (elicitation) that the model can't answer. Anything but an
  explicit yes keeps the source, and so does a client without elicitation support or no answer
  within 9 minutes. No tool takes a "yes"/"confirm" argument; `sxfer config confirm` doesn't apply.
- **Files only.** Secrets would land in the model's context and the transcript, so there's no tool
  for them, and a listener started over MCP refuses them. Use `sxfer send` for passwords and OTPs.
- **The network allowlist and pinned peers are yours.** The server reads `sxfer config` and
  `sxfer trust` but can't change them.
- Paths must be absolute. SSH runs with `BatchMode=yes`: key or agent auth only, no prompts.

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
6. **Receipt** - on the LAN the listener signs it (ML-DSA-65, bound to this session) and the sender
   checks the signature *before* step 5. It's logged on the **destination only**
   (`~/.sxfer/receipts.jsonl`); the source keeps no record of what it shredded unless you ask for
   the signed receipt with `send --receipt`.

Any failure before step 5 deletes the partial copy and leaves the source untouched; just rerun.
SSH mode uses keepalives and a hang-up-proof remote shred, so a dropped connection is detected in
about 30 s and never interrupts a shred halfway.

### LAN security

- **SPAKE2** (Ed25519 group) turns the 6-digit code into a strong shared key. The code never crosses
  the network, an eavesdropper can't test guesses offline, and an active attacker gets one guess per
  connection. The listener closes after 3 wrong codes (odds of guessing: 3 in a million).
- **ML-KEM-768** (FIPS 203) runs alongside it in the same round trip, with a fresh key per
  connection. The session key needs both secrets, so recording a transfer today and breaking
  SPAKE2's elliptic curve with a quantum computer later doesn't decrypt it.
- **ML-DSA-65** (FIPS 204) identities: inside the encrypted channel each side signs the handshake
  transcript, and pinned peers are checked like ssh host keys. Without a code (pinned peers,
  `--trusted`) these signatures are what authenticates the pairing.
- **Signed receipts**: the listener signs what it committed (name, size, SHA-256, path, both
  fingerprints, the session hash). The sender won't shred until that verifies, and a saved receipt
  verifies offline with `sxfer receipt verify r.json [--file report.pdf]`.
- **ChaCha20-Poly1305** with keys from HKDF-SHA256 over both shared secrets, salted with the
  transcript hash; one key per direction, counter nonces.
- File names from the sender are reduced to a bare name (no paths, no `..`).
- Secrets are capped at 64 KiB, shown once on the receiver's terminal, and never written to disk.

What isn't post-quantum: **SSH mode** inherits your OpenSSH's key exchange (OpenSSH 9.0+ defaults to
the hybrid `sntrup761x25519`, 9.9+ to `mlkem768x25519`) and its host keys, and has no signed
receipts, since the remote side runs only `sh`. **Discovery** is plain mDNS; the fingerprint a
listener advertises only decides whether to ask for a code, and is checked once paired.

### Shredding caveat

Overwriting is reliable on spinning disks. On SSDs (wear levelling), copy-on-write or journaling
filesystems, cloud-synced folders (OneDrive/Dropbox, which sxfer warns about), snapshots and
backups, old copies of the data can survive. Full-disk encryption (BitLocker / FileVault / LUKS)
is what really protects deleted data.

## Building

```
cargo test --workspace
./build.sh        # Linux/WSL: cross-compiles sxfer + sxfer-mcp for all six targets into dist/ (needs zig + cargo-zigbuild)
```

The repo is a Cargo workspace: the root crate is the `sxfer` library + CLI, `sxfer-mcp/` the MCP server
built on that library.

Every push and pull request runs `.github/workflows/build.yml`: fmt, clippy and tests on Linux,
Windows and macOS, then native builds of both binaries for Linux (x86-64, ARM64, static), Windows
(x86-64, ARM64) and macOS (Intel, Apple Silicon), uploaded as workflow artifacts. Tagging `vX.Y.Z` also publishes
them to a GitHub release with `SHA256SUMS` and its ML-DSA-65 signature `SHA256SUMS.sig`.

### Release signing (maintainers, once)

```
sxfer sig keygen release.key        # secret seed + release.key.pub.pem; generate it on a machine you trust
```

1. Add the contents of `release.key` as the repository secret `SXFER_RELEASE_KEY`, then move the
   file somewhere offline. Never commit it.
2. Commit `release.key.pub.pem` as `release.pub.pem` in the repo root.

The release job signs `SHA256SUMS`, checks the signature against `release.pub.pem`, and publishes
nothing if that check fails. Without the secret, releases are published unsigned, with a warning.

## Download

Grab a binary from [Releases](https://github.com/Kalaghni/sxfer/releases), or the artifacts of the
latest [build run](https://github.com/Kalaghni/sxfer/actions). Check it against `SHA256SUMS`, then
put it on your PATH. On macOS, a downloaded binary may need `xattr -d com.apple.quarantine sxfer`.

### Verifying a download

Releases from 0.7 on carry `SHA256SUMS.sig`, a post-quantum (ML-DSA-65) signature by the key in
`release.pub.pem` (repo root, once the maintainer has set it up). Check it with OpenSSL 3.5 or
later, which needs no trust in sxfer itself, or with an sxfer you already trust:

```
openssl pkeyutl -verify -pubin -inkey release.pub.pem -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
sxfer sig verify SHA256SUMS --pubkey release.pub.pem
sha256sum -c SHA256SUMS --ignore-missing
```
