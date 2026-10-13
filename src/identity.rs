//! Post-quantum identities: one ML-DSA-65 (FIPS 204) key per machine, the peers you've pinned,
//! and the signed receipts a listener hands back.
//!
//! KEY        ~/.sxfer/identity.mldsa65 holds a 32-byte seed (hex, mode 600), created on first use.
//!            A peer is known by its fingerprint: SHA-256 of its encoded public key.
//! PINNING    ~/.sxfer/known_peers.json maps names to fingerprints, like ssh's known_hosts. A known
//!            name presenting a different key is refused ("KEY CHANGED") until the pin is removed.
//! SIGNATURES hedged ML-DSA-65 with a context string per purpose, so a handshake signature can never
//!            pass as a receipt and vice versa. Files (release checksums) use the empty context, so
//!            OpenSSL 3.5+ can verify them too.

use crate::abort;
use crate::common::*;
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, MlDsa65, Signature};
use ml_dsa::{Seed, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use spki::der::pem::LineEnding;
use spki::{DecodePublicKey, EncodePublicKey};
use std::fs;
use std::path::{Path, PathBuf};

/// Handshake signature by the sender over the session transcript.
pub const CTX_SENDER: &[u8] = b"sxfer/2/hello/sender";
/// Handshake signature by the listener over the session transcript.
pub const CTX_LISTENER: &[u8] = b"sxfer/2/hello/listener";
/// A listener's receipt for a delivered file or secret.
pub const CTX_RECEIPT: &[u8] = b"sxfer/2/receipt";
/// Signatures over whole files (release checksums): plain ML-DSA, empty context.
pub const CTX_FILE: &[u8] = b"";

/// A machine's (or a release key's) ML-DSA-65 signing key.
pub struct Identity {
    sk: ExpandedSigningKey<MlDsa65>,
    pk: Vec<u8>,
    pub name: String,
}

impl Identity {
    pub fn from_seed(seed: &[u8; 32], name: &str) -> Identity {
        let sk = ExpandedSigningKey::<MlDsa65>::from_seed(&Seed::from(*seed));
        let pk = sk.verifying_key().encode().to_vec();
        Identity {
            sk,
            pk,
            name: name.to_string(),
        }
    }

    /// This machine's identity, created on first use.
    pub fn load_or_create() -> R<Identity> {
        let p = identity_path();
        if !p.exists() {
            fs::create_dir_all(sxfer_dir())?;
            write_seed(&p, &new_seed())?;
            say(&format!(
                "created this machine's identity key: {}",
                p.display()
            ));
        }
        Identity::load(&p, &host_name())
    }

    /// A seed file written by `write_seed` (64 hex characters).
    pub fn load(path: &Path, name: &str) -> R<Identity> {
        let text = fs::read_to_string(path)
            .map_err(|e| Abort(format!("cannot read key {}: {e}", path.display())))?;
        let seed: [u8; 32] = unhex(text.trim())
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| Abort(format!("{} is not an sxfer key", path.display())))?;
        Ok(Identity::from_seed(&seed, name))
    }

    pub fn public_key(&self) -> &[u8] {
        &self.pk
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(&self.pk)
    }

    /// Hedged (randomized) ML-DSA signature, per FIPS 204's default.
    pub fn sign(&self, ctx: &[u8], msg: &[u8]) -> R<Vec<u8>> {
        let sig = self
            .sk
            .sign_randomized(msg, ctx, &mut getrandom::SysRng)
            .map_err(|_| Abort("signing failed".into()))?;
        Ok(sig.encode().to_vec())
    }

    /// The public key as an SPKI PEM, the form OpenSSL reads.
    pub fn public_key_pem(&self) -> String {
        public_key_pem(&self.pk).expect("our own key encodes")
    }
}

pub fn identity_path() -> PathBuf {
    sxfer_dir().join("identity.mldsa65")
}

pub fn new_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut s);
    s
}

/// Write a key seed as hex, readable by the owner only; never overwrites.
pub fn write_seed(path: &Path, seed: &[u8; 32]) -> R<()> {
    use std::io::Write;
    let mut f = create_new_private(path)?;
    writeln!(f, "{}", hex(seed))?;
    f.sync_all()?;
    Ok(())
}

/// SHA-256 of the encoded public key, 64 hex characters.
pub fn fingerprint(pk: &[u8]) -> String {
    hex(&Sha256::digest(pk))
}

/// The first 64 bits of a fingerprint, grouped for reading aloud: `ab12-cd34-ef56-7890`.
pub fn short_fp(fp: &str) -> String {
    let head: Vec<&str> = (0..4).filter_map(|i| fp.get(i * 4..i * 4 + 4)).collect();
    head.join("-")
}

/// A fingerprint as the user may type it (any case, dashes, spaces, colons): 64 hex characters.
pub fn normalize_fp(s: &str) -> R<String> {
    let fp: String = s
        .chars()
        .filter(|c| !matches!(c, '-' | ':' | ' '))
        .collect::<String>()
        .to_lowercase();
    if fp.len() != 64 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
        abort!("a fingerprint is 64 hex characters (see `sxfer id` on that machine), got {s:?}");
    }
    Ok(fp)
}

pub fn verify(pk: &[u8], ctx: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let (Ok(pk), Ok(sig)) = (
        EncodedVerifyingKey::<MlDsa65>::try_from(pk),
        EncodedSignature::<MlDsa65>::try_from(sig),
    ) else {
        return false;
    };
    let Some(sig) = Signature::<MlDsa65>::decode(&sig) else {
        return false;
    };
    VerifyingKey::<MlDsa65>::decode(&pk).verify_with_context(msg, ctx, &sig)
}

pub fn public_key_pem(pk: &[u8]) -> R<String> {
    let enc = EncodedVerifyingKey::<MlDsa65>::try_from(pk)
        .map_err(|_| Abort("not an ML-DSA-65 public key".into()))?;
    VerifyingKey::<MlDsa65>::decode(&enc)
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| Abort(format!("cannot encode public key: {e}")))
}

/// An ML-DSA-65 public key from an SPKI PEM file.
pub fn read_public_key_pem(path: &Path) -> R<Vec<u8>> {
    let pem = fs::read_to_string(path)
        .map_err(|e| Abort(format!("cannot read {}: {e}", path.display())))?;
    let vk = VerifyingKey::<MlDsa65>::from_public_key_pem(&pem).map_err(|e| {
        Abort(format!(
            "{} is not an ML-DSA-65 public key: {e}",
            path.display()
        ))
    })?;
    Ok(vk.encode().to_vec())
}

// ---------------------------------------------------------------- pinned peers

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Peer {
    pub name: String,
    pub fingerprint: String,
    pub added: String,
}

#[derive(Serialize, Deserialize, Default)]
struct KnownPeers {
    #[serde(default)]
    peers: Vec<Peer>,
}

#[derive(Debug, PartialEq)]
pub enum Known {
    /// pinned (under this name)
    Yes(String),
    /// never seen
    New,
    /// a pinned name now presents another key
    Changed { pinned_fp: String },
}

fn peers_path() -> PathBuf {
    sxfer_dir().join("known_peers.json")
}

fn load_peers() -> KnownPeers {
    fs::read(peers_path())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save_peers(k: &KnownPeers) -> R<()> {
    fs::create_dir_all(sxfer_dir())?;
    let tmp = sxfer_dir().join(format!("known_peers.{}.tmp", random_hex(4)));
    fs::write(&tmp, serde_json::to_vec_pretty(k).expect("serializable"))?;
    fs::rename(&tmp, peers_path())?;
    Ok(())
}

pub fn peers() -> Vec<Peer> {
    load_peers().peers
}

pub fn check_peer(name: &str, fp: &str) -> Known {
    let k = load_peers();
    if let Some(p) = k.peers.iter().find(|p| p.fingerprint == fp) {
        return Known::Yes(p.name.clone());
    }
    match k.peers.iter().find(|p| p.name.eq_ignore_ascii_case(name)) {
        Some(p) => Known::Changed {
            pinned_fp: p.fingerprint.clone(),
        },
        None => Known::New,
    }
}

/// Pin `fp` as `name`. Returns false if that fingerprint was already pinned.
pub fn pin(name: &str, fp: &str) -> R<bool> {
    let fp = normalize_fp(fp)?;
    let mut k = load_peers();
    if k.peers.iter().any(|p| p.fingerprint == fp) {
        return Ok(false);
    }
    if let Some(p) = k.peers.iter().find(|p| p.name.eq_ignore_ascii_case(name)) {
        abort!(
            "{name} is already pinned to {}; remove it first: sxfer trust remove {name}",
            short_fp(&p.fingerprint)
        );
    }
    k.peers.push(Peer {
        name: name.to_string(),
        fingerprint: fp,
        added: now_iso(),
    });
    save_peers(&k)?;
    Ok(true)
}

/// Unpin by name or fingerprint.
pub fn unpin(which: &str) -> R<Peer> {
    let mut k = load_peers();
    let fp = normalize_fp(which).ok();
    let Some(i) = k
        .peers
        .iter()
        .position(|p| p.name.eq_ignore_ascii_case(which) || Some(&p.fingerprint) == fp.as_ref())
    else {
        abort!("{which} isn't a pinned peer (see `sxfer trust list`)");
    };
    let p = k.peers.remove(i);
    save_peers(&k)?;
    Ok(p)
}

// ---------------------------------------------------------------- signed receipts

/// What a listener attests to. Signed as the exact JSON bytes in `SignedReceipt::body`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ReceiptBody {
    pub v: u32,
    pub time: String,
    pub listener: String,
    /// hex ML-DSA-65 public key; the receipt verifies on its own, offline
    pub listener_pk: String,
    pub sender: String,
    pub sender_fp: String,
    pub kind: String,
    pub name: String,
    pub path: Option<String>,
    pub size: u64,
    pub sha256: String,
    pub already: bool,
    /// the session transcript hash: ties the receipt to one transfer, so it can't be replayed
    pub session: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignedReceipt {
    pub body: String,
    pub sig: String,
}

impl SignedReceipt {
    pub fn sign(id: &Identity, body: &ReceiptBody) -> R<SignedReceipt> {
        let body = serde_json::to_string(body).expect("serializable");
        let sig = id.sign(CTX_RECEIPT, body.as_bytes())?;
        Ok(SignedReceipt {
            body,
            sig: hex(&sig),
        })
    }

    /// Check the signature against the key inside the receipt; returns what it attests to.
    /// Whether that key is the one you expect is the caller's question.
    pub fn open(&self) -> R<ReceiptBody> {
        let body: ReceiptBody = serde_json::from_str(&self.body)
            .map_err(|e| Abort(format!("malformed receipt: {e}")))?;
        let pk = unhex(&body.listener_pk).ok_or_else(|| Abort("malformed receipt key".into()))?;
        let sig = unhex(&self.sig).ok_or_else(|| Abort("malformed receipt signature".into()))?;
        if body.v != 2 || !verify(&pk, CTX_RECEIPT, self.body.as_bytes(), &sig) {
            abort!("receipt signature is INVALID");
        }
        Ok(body)
    }
}

impl ReceiptBody {
    pub fn listener_fp(&self) -> String {
        unhex(&self.listener_pk)
            .map(|pk| fingerprint(&pk))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me(name: &str) -> Identity {
        Identity::from_seed(&new_seed(), name)
    }

    #[test]
    fn sign_verify_and_domain_separation() {
        let id = me("a");
        let sig = id.sign(CTX_RECEIPT, b"hello").unwrap();
        assert_eq!(id.public_key().len(), 1952);
        assert_eq!(sig.len(), 3309);
        assert!(verify(id.public_key(), CTX_RECEIPT, b"hello", &sig));
        assert!(!verify(id.public_key(), CTX_RECEIPT, b"hellO", &sig));
        assert!(
            !verify(id.public_key(), CTX_SENDER, b"hello", &sig),
            "other context"
        );
        assert!(!verify(me("b").public_key(), CTX_RECEIPT, b"hello", &sig));
        assert!(!verify(b"short", CTX_RECEIPT, b"hello", &sig));
        assert!(!verify(id.public_key(), CTX_RECEIPT, b"hello", &sig[1..]));
    }

    #[test]
    fn same_seed_same_key_and_pem_round_trip() {
        let seed = new_seed();
        let (a, b) = (
            Identity::from_seed(&seed, "x"),
            Identity::from_seed(&seed, "y"),
        );
        assert_eq!(a.fingerprint(), b.fingerprint());
        let pem = a.public_key_pem();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        let p = std::env::temp_dir().join(format!("sxfer-pem-{}.pem", random_hex(4)));
        fs::write(&p, pem).unwrap();
        assert_eq!(read_public_key_pem(&p).unwrap(), a.public_key());
        let _ = fs::remove_file(p);
    }

    #[test]
    fn seed_file_round_trip_never_overwrites() {
        let p = std::env::temp_dir().join(format!("sxfer-key-{}", random_hex(4)));
        let seed = new_seed();
        write_seed(&p, &seed).unwrap();
        assert!(
            write_seed(&p, &new_seed()).is_err(),
            "must not clobber a key"
        );
        let id = Identity::load(&p, "k").unwrap();
        assert_eq!(
            id.fingerprint(),
            Identity::from_seed(&seed, "k").fingerprint()
        );
        let _ = fs::remove_file(p);
    }

    #[test]
    fn fingerprints() {
        let fp = me("a").fingerprint();
        assert_eq!(fp.len(), 64);
        assert_eq!(short_fp(&fp).len(), 19);
        let typed = format!("{}-{}", fp[..32].to_uppercase(), &fp[32..]);
        assert_eq!(normalize_fp(&typed).unwrap(), fp);
        assert!(normalize_fp("abc").is_err());
    }

    #[test]
    fn receipts_verify_and_detect_tampering() {
        let id = me("listener");
        let body = ReceiptBody {
            v: 2,
            time: "1".into(),
            listener: id.name.clone(),
            listener_pk: hex(id.public_key()),
            sender: "s".into(),
            sender_fp: "00".repeat(32),
            kind: "file".into(),
            name: "a.txt".into(),
            path: Some("/tmp/a.txt".into()),
            size: 5,
            sha256: "ab".repeat(32),
            already: false,
            session: "cd".repeat(32),
        };
        let r = SignedReceipt::sign(&id, &body).unwrap();
        assert_eq!(r.open().unwrap(), body);
        assert_eq!(body.listener_fp(), id.fingerprint());
        let forged = SignedReceipt {
            body: r.body.replace("\"size\":5", "\"size\":6"),
            sig: r.sig.clone(),
        };
        assert!(forged.open().is_err());
        // swapping in another key doesn't help a forger: the signature no longer matches it
        let other = me("mallory");
        let swapped = SignedReceipt {
            body: r
                .body
                .replace(&hex(id.public_key()), &hex(other.public_key())),
            sig: r.sig,
        };
        assert!(swapped.open().is_err());
    }
}
