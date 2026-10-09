//! ~/.sxfer/config.json: the networks `sxfer send` searches for listeners.

use crate::abort;
use crate::common::*;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub networks: Vec<String>,
}

fn path() -> PathBuf {
    sxfer_dir().join("config.json")
}

pub fn load() -> Config {
    fs::read(path())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save(c: &Config) -> R<()> {
    fs::create_dir_all(sxfer_dir())?;
    fs::write(path(), serde_json::to_vec_pretty(c).expect("serializable"))?;
    Ok(())
}

/// Accepts "192.168.2.0/24", "192.168.2.10" (-> /32) or an IPv6 equivalent; returns the canonical network.
pub fn parse_net(s: &str) -> R<IpNet> {
    if let Ok(n) = s.parse::<IpNet>() {
        return Ok(n.trunc());
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(IpNet::from(ip));
    }
    abort!("not an IP address or CIDR: {s:?}")
}

pub fn networks() -> R<Vec<IpNet>> {
    load().networks.iter().map(|s| parse_net(s)).collect()
}

pub fn add(s: &str) -> R<()> {
    let n = parse_net(s)?.to_string();
    let mut c = load();
    if c.networks.contains(&n) {
        say(&format!("{n} is already configured"));
    } else {
        c.networks.push(n.clone());
        save(&c)?;
        say(&format!("added {n}  ({})", path().display()));
    }
    Ok(())
}

pub fn remove(s: &str) -> R<()> {
    let n = parse_net(s)?.to_string();
    let mut c = load();
    let before = c.networks.len();
    c.networks.retain(|x| x != &n);
    if c.networks.len() == before {
        abort!("{n} isn't configured");
    }
    save(&c)?;
    say(&format!("removed {n}"));
    Ok(())
}

pub fn list() {
    let c = load();
    if c.networks.is_empty() {
        say("no networks configured; add one with: sxfer config add 192.168.2.0/24");
    }
    for n in c.networks {
        println!("{n}");
    }
}
