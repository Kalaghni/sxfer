//! sxfer-mcp - sxfer as a Model Context Protocol server over stdio, for AI assistants.
//!
//! The same hash / send / verify / commit / shred steps as the `sxfer` CLI, with three rules
//! because a model is driving:
//!   SHRED    the user decides, never the model. Once receipt is verified the server asks the
//!            client's user directly (MCP elicitation). No elicitation support, no answer in time,
//!            or anything but an explicit yes keeps the source. `sxfer config confirm` is ignored.
//!   FILES    only. A secret would end up in the model's context and transcript, so there is no
//!            way to send one, and a listener started here refuses them.
//!   NETWORKS the allowlist (`sxfer config add`) is read here, never changed.
//!
//! stdout carries JSON-RPC only; progress goes to stderr, as with the CLI.

use serde_json::{json, Value};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{BufRead, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use sxfer::abort;
use sxfer::common::{cloud_markers, host_name, sxfer_dir, Abort, Asker, ShredCfg, R};
use sxfer::{config, lan, ssh};

/// Newest first. A client asking for one we don't know gets the newest.
const PROTOCOL_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
/// How long the user has to answer a shred question: under the LAN listener's 10-minute wait
/// for the sender's verdict, so the receiver's receipt still records what happened.
const ASK_TIMEOUT: Duration = Duration::from_secs(9 * 60);
const NO_ANSWER: &str = "no answer within 9 minutes";
const DISCOVER_WAIT: Duration = Duration::from_secs(2);

const INSTRUCTIONS: &str = "\
sxfer moves a file to another machine: encrypted, the receiver re-reads it from disk to prove \
it arrived intact, and then the source can be shredded.

- Shredding is the user's decision, not yours. After a verified delivery the server asks the \
user directly with a prompt you can't answer. Unless they say yes, the source is kept. Never \
delete or overwrite a source some other way.
- Files only. Passwords, OTPs and other secrets can't be sent or received here; point the user \
to the sxfer CLI (`sxfer send` with no file) for those.
- A LAN send needs the 6-digit code shown on the receiving machine. Ask the user for it; never \
guess (3 wrong codes close the listener).
- Paths must be absolute.
- The network allowlist belongs to the user (`sxfer config add <cidr>`). You can read it with \
get_config but not change it.";

const SHRED_NOTE: &str = "\
The file was delivered and the receiver's copy verified. Shredding overwrites and deletes the \
source; it can't be undone. Your AI assistant can't answer this for you.";

const CLOUD_NOTE: &str = "the source is in a cloud-synced folder; its cloud copy and version \
history are not shredded";

const NEXT_STEPS: &str = "\
Give the sender this code. On the same network they run `sxfer send <file>`; over a VPN or \
WireGuard, mDNS doesn't cross, so they add `--to <this machine's VPN IP>:<port>`. Check with \
listener_status; stop_listener closes it.";

const USAGE: &str = "\
sxfer-mcp: sxfer as an MCP server over stdio (files only; the user approves every shred).

Add it to an MCP client, e.g. Claude Code:
    claude mcp add sxfer -- sxfer-mcp

Tools: get_config, discover_listeners, send_file, push_file, pull_file,
       start_listener, listener_status, stop_listener";

/// The client end of stdio: replies to it, and questions for its user in the middle of a call.
struct Peer {
    rx: Receiver<String>,
    out: Box<dyn Write>,
    /// client messages that arrived while a question was pending
    backlog: VecDeque<Value>,
    /// the client declared elicitation support
    can_ask: bool,
    asked: u64,
}

impl Peer {
    fn send(&mut self, msg: &Value) {
        let _ = writeln!(self.out, "{msg}");
        let _ = self.out.flush();
    }

    fn reply(&mut self, id: Value, result: Value) {
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "result": result }));
    }

    fn error(&mut self, id: Value, code: i64, message: &str) {
        let error = json!({ "code": code, "message": message });
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "error": error }));
    }

    /// The next message from the client; None once stdin closes.
    fn recv(&mut self) -> Option<Value> {
        if let Some(msg) = self.backlog.pop_front() {
            return Some(msg);
        }
        loop {
            let line = self.rx.recv().ok()?;
            match serde_json::from_str(&line) {
                Ok(msg) => return Some(msg),
                Err(e) if !line.trim().is_empty() => {
                    self.error(Value::Null, -32700, &format!("parse error: {e}"));
                }
                Err(_) => {}
            }
        }
    }

    /// Ask the client's user - not the model - a yes/no question, through MCP elicitation.
    /// Ok only on an explicit yes; Err says why not.
    fn ask_user(&mut self, question: &str) -> Result<(), String> {
        if !self.can_ask {
            return Err("this MCP client can't ask you directly (no elicitation support)".into());
        }
        self.asked += 1;
        let id = format!("sxfer-ask-{}", self.asked);
        let message = format!("{question}\n\n{SHRED_NOTE}");
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "elicitation/create",
            "params": {
                "message": message,
                "requestedSchema": {
                    "type": "object",
                    "properties": {
                        "shred": {
                            "type": "boolean",
                            "title": "Shred the source now",
                            "default": false
                        }
                    },
                    "required": ["shred"]
                }
            }
        }));
        let deadline = Instant::now() + ASK_TIMEOUT;
        loop {
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                return Err(NO_ANSWER.into());
            };
            let line = match self.rx.recv_timeout(left) {
                Ok(line) => line,
                Err(RecvTimeoutError::Timeout) => return Err(NO_ANSWER.into()),
                Err(RecvTimeoutError::Disconnected) => return Err("the client went away".into()),
            };
            let Ok(msg) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            if msg.get("method").is_none() && msg["id"].as_str() == Some(id.as_str()) {
                return answer(&msg);
            }
            if msg["method"] == "ping" && msg.get("id").is_some() {
                self.reply(msg["id"].clone(), json!({}));
            } else {
                self.backlog.push_back(msg); // handled after this call returns
            }
        }
    }
}

/// The user's reply to a shred question.
fn answer(reply: &Value) -> Result<(), String> {
    if let Some(e) = reply.get("error") {
        let why = e["message"].as_str().unwrap_or("unknown error");
        return Err(format!("the client couldn't ask you: {why}"));
    }
    let r = &reply["result"];
    match r["action"].as_str() {
        Some("accept") if r["content"]["shred"] == true => Ok(()),
        Some("accept") => Err("you chose not to shred".into()),
        Some("decline") => Err("you declined".into()),
        _ => Err("you dismissed the question".into()),
    }
}

/// A listener started by start_listener, running on its own thread.
struct Listener {
    code: String,
    port: u16,
    dir: PathBuf,
    stop: Arc<AtomicBool>,
    /// None while it waits for a sender
    done: Arc<Mutex<Option<R<lan::Received>>>>,
}

struct Server {
    peer: Rc<RefCell<Peer>>,
    /// why the last shred question didn't end in a yes
    kept_because: Rc<RefCell<Option<String>>>,
    listener: Option<Listener>,
}

impl Server {
    fn new(rx: Receiver<String>, out: Box<dyn Write>) -> Server {
        let peer = Peer {
            rx,
            out,
            backlog: VecDeque::new(),
            can_ask: false,
            asked: 0,
        };
        Server {
            peer: Rc::new(RefCell::new(peer)),
            kept_because: Rc::new(RefCell::new(None)),
            listener: None,
        }
    }

    fn recv(&self) -> Option<Value> {
        self.peer.borrow_mut().recv()
    }

    fn handle(&mut self, msg: Value) {
        let Some(method) = msg["method"].as_str() else {
            return; // a stray reply, e.g. to a question that timed out
        };
        let Some(id) = msg.get("id").cloned() else {
            return; // notifications need no answer
        };
        let params = &msg["params"];
        let result = match method {
            "initialize" => self.initialize(params),
            "ping" => json!({}),
            "tools/list" => json!({ "tools": tools() }),
            "tools/call" => self.call(params),
            _ => {
                let text = format!("method not found: {method}");
                self.peer.borrow_mut().error(id, -32601, &text);
                return;
            }
        };
        self.peer.borrow_mut().reply(id, result);
    }

    fn initialize(&mut self, params: &Value) -> Value {
        let asked = params["protocolVersion"].as_str().unwrap_or("");
        let version = PROTOCOL_VERSIONS
            .iter()
            .copied()
            .find(|v| *v == asked)
            .unwrap_or(PROTOCOL_VERSIONS[0]);
        self.peer.borrow_mut().can_ask = params["capabilities"].get("elicitation").is_some();
        json!({
            "protocolVersion": version,
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "sxfer", "version": env!("CARGO_PKG_VERSION") },
            "instructions": INSTRUCTIONS
        })
    }

    fn call(&mut self, params: &Value) -> Value {
        let name = params["name"].as_str().unwrap_or("");
        let args = &params["arguments"];
        *self.kept_because.borrow_mut() = None;
        let result = match name {
            "get_config" => get_config(),
            "discover_listeners" => discover_listeners(args),
            "send_file" => self.send_file(args),
            "push_file" => self.push_file(args),
            "pull_file" => self.pull_file(args),
            "start_listener" => self.start_listener(args),
            "listener_status" => self.listener_status(),
            "stop_listener" => self.stop_listener(),
            _ => Err(Abort(format!("unknown tool: {name}"))),
        };
        match result {
            Ok(v) => tool_result(&v, false),
            Err(e) => tool_result(&json!({ "error": e.0 }), true),
        }
    }

    /// Every shred asks the client's user; `keep` skips the question.
    fn shred_cfg(&self, args: &Value) -> R<ShredCfg> {
        let peer = Rc::clone(&self.peer);
        let kept = Rc::clone(&self.kept_because);
        let asker: Asker =
            Rc::new(
                move |question: &str| match peer.borrow_mut().ask_user(question) {
                    Ok(()) => true,
                    Err(why) => {
                        *kept.borrow_mut() = Some(why);
                        false
                    }
                },
            );
        Ok(ShredCfg {
            keep: flag(args, "keep"),
            ask: true,
            passes: passes(args)?,
            asker: Some(asker),
        })
    }

    /// Why the source is still there, if it is.
    fn kept(&self, sc: &ShredCfg, shredded: bool) -> Option<String> {
        if shredded {
            None
        } else if sc.keep {
            Some("keep was requested".into())
        } else {
            self.kept_because.borrow().clone()
        }
    }

    fn send_file(&self, args: &Value) -> R<Value> {
        let path = path_arg(args, "path")?;
        let code = text_arg(args, "code")?;
        if lan::normalize_code(code).len() != 6 {
            abort!("the code is 6 digits, like 482-913");
        }
        let sc = self.shred_cfg(args)?;
        let cloud = warnings(&path);
        let addr = match args["to"].as_str() {
            Some(to) => lan::resolve_to(to)?,
            None => pick_listener()?,
        };
        let payload = lan::Payload::File(path.clone());
        let sent = lan::send_core(addr, code, &payload, &sc)?;
        Ok(json!({
            "sent": path.display().to_string(),
            "to": addr.to_string(),
            "saved_as": sent.dest_path,
            "already_there": sent.already,
            "shredded": sent.shredded,
            "kept_because": self.kept(&sc, sent.shredded),
            "warnings": cloud
        }))
    }

    fn push_file(&self, args: &Value) -> R<Value> {
        let path = path_arg(args, "path")?;
        let dest = text_arg(args, "dest")?;
        let sc = self.shred_cfg(args)?;
        let cloud = warnings(&path);
        let shredded = ssh::push(&path, dest, &sc)?;
        Ok(json!({
            "pushed": path.display().to_string(),
            "to": dest,
            "shredded": shredded,
            "kept_because": self.kept(&sc, shredded),
            "warnings": cloud
        }))
    }

    fn pull_file(&self, args: &Value) -> R<Value> {
        let src = text_arg(args, "src")?;
        let dest = path_arg(args, "dest")?;
        let sc = self.shred_cfg(args)?;
        let shredded = ssh::pull(src, &dest, &sc)?;
        Ok(json!({
            "pulled": src,
            "into": dest.display().to_string(),
            "remote_shredded": shredded,
            "kept_because": self.kept(&sc, shredded)
        }))
    }

    fn start_listener(&mut self, args: &Value) -> R<Value> {
        if let Some(l) = &self.listener {
            // a transfer that has just finished may still be writing its receipt
            let settle = Instant::now() + Duration::from_secs(2);
            while l.done.lock().unwrap().is_none() && Instant::now() < settle {
                std::thread::sleep(Duration::from_millis(50));
            }
            if l.done.lock().unwrap().is_none() {
                abort!(
                    "a listener is already waiting (code {}); stop it first",
                    l.code
                );
            }
        }
        let dir = path_arg(args, "dir")?;
        if !dir.is_dir() {
            abort!("no such directory: {}", dir.display());
        }
        let code = lan::new_code();
        let stop = Arc::new(AtomicBool::new(false));
        let done = Arc::new(Mutex::new(None));
        let cfg = lan::ListenCfg {
            bind: SocketAddr::from(([0, 0, 0, 0], 0)), // any free port; mDNS tells senders which
            dir: dir.clone(),
            advertise: true,
            accept_text: false,
            stop: Some(Arc::clone(&stop)),
        };
        let (port_tx, port_rx) = mpsc::channel();
        let (thread_code, thread_done) = (code.clone(), Arc::clone(&done));
        std::thread::spawn(move || {
            let got = lan::listen_core(&cfg, &thread_code, &mut |p| {
                let _ = port_tx.send(p);
            });
            *thread_done.lock().unwrap() = Some(got);
        });
        let Ok(port) = port_rx.recv_timeout(Duration::from_secs(10)) else {
            if let Some(Err(e)) = &*done.lock().unwrap() {
                abort!("the listener didn't start: {e}");
            }
            stop.store(true, Ordering::Relaxed);
            abort!("the listener didn't start within 10 s");
        };
        let ip = lan::primary_ip().map(|i| i.to_string());
        self.listener = Some(Listener {
            code: code.clone(),
            port,
            dir: dir.clone(),
            stop,
            done,
        });
        Ok(json!({
            "code": code,
            "port": port,
            "address": ip,
            "host": host_name(),
            "saving_to": dir.display().to_string(),
            "next": NEXT_STEPS
        }))
    }

    fn listener_status(&self) -> R<Value> {
        let Some(l) = &self.listener else {
            abort!("no listener; start one with start_listener");
        };
        let done = l.done.lock().unwrap();
        Ok(match &*done {
            None => json!({
                "status": "waiting",
                "code": l.code,
                "port": l.port,
                "saving_to": l.dir.display().to_string()
            }),
            Some(Ok(r)) => received(r),
            Some(Err(e)) => json!({ "status": "closed", "reason": e.0 }),
        })
    }

    fn stop_listener(&mut self) -> R<Value> {
        let Some(l) = self.listener.take() else {
            abort!("no listener is running");
        };
        l.stop.store(true, Ordering::Relaxed);
        Ok(json!({ "stopped": true, "code": l.code }))
    }
}

/// What a finished listener got.
fn received(r: &lan::Received) -> Value {
    match r {
        lan::Received::File {
            path,
            already,
            shredded,
        } => {
            let path = path.display().to_string();
            json!({
                "status": "received",
                "path": path,
                "already_had_it": already,
                "sender_shredded": shredded
            })
        }
        // can't happen: the listener refuses secrets, and the text is never returned anyway
        lan::Received::Text { .. } => json!({ "status": "closed", "reason": "refused a secret" }),
    }
}

fn get_config() -> R<Value> {
    let c = config::load();
    let cli_confirm = c.confirm_shred();
    Ok(json!({
        "networks": c.networks,
        "cli_confirm_shred": cli_confirm,
        "mcp_shredding": "always asks the user first; the CLI confirm setting doesn't apply here",
        "config_file": sxfer_dir().join("config.json").display().to_string(),
        "host": host_name()
    }))
}

fn discover_listeners(args: &Value) -> R<Value> {
    let secs = args["wait_seconds"].as_u64().unwrap_or(2).clamp(1, 10);
    let nets = config::networks()?;
    let found = lan::discover(Duration::from_secs(secs))?;
    let listeners: Vec<Value> = found
        .iter()
        .map(|f| {
            let addresses: Vec<String> = f.addrs.iter().map(|a| a.to_string()).collect();
            let to = f.addr_in(&nets).map(|a| a.to_string());
            json!({
                "name": f.name,
                "addresses": addresses,
                "port": f.port,
                "to": to
            })
        })
        .collect();
    let networks: Vec<String> = nets.iter().map(|n| n.to_string()).collect();
    Ok(json!({
        "listeners": listeners,
        "configured_networks": networks,
        "note": "`to` is set only for listeners inside the configured networks"
    }))
}

/// The one discovered listener inside the configured networks.
fn pick_listener() -> R<SocketAddr> {
    let nets = config::networks()?;
    if nets.is_empty() {
        abort!("no networks configured: the user runs `sxfer config add <cidr>`, or pass `to`");
    }
    let found = lan::discover(DISCOVER_WAIT)?;
    let ok: Vec<SocketAddr> = found.iter().filter_map(|f| f.addr_in(&nets)).collect();
    match ok.as_slice() {
        [one] => Ok(*one),
        [] => abort!("no listener found on the configured networks; pass `to` as ip:port"),
        _ => abort!(
            "{} listeners found; ask the user which, then pass `to`",
            ok.len()
        ),
    }
}

fn warnings(path: &Path) -> Vec<String> {
    cloud_markers(path)
        .into_iter()
        .map(|m| format!("{m}: {CLOUD_NOTE}"))
        .collect()
}

fn tool_result(v: &Value, is_error: bool) -> Value {
    let text = serde_json::to_string_pretty(v).unwrap_or_default();
    json!({ "content": [{ "type": "text", "text": text }], "isError": is_error })
}

fn text_arg<'a>(args: &'a Value, key: &str) -> R<&'a str> {
    match args[key].as_str() {
        Some(s) if !s.trim().is_empty() => Ok(s),
        _ => abort!("missing argument: {key}"),
    }
}

/// Absolute only: the server's working directory means nothing to the user.
fn path_arg(args: &Value, key: &str) -> R<PathBuf> {
    let p = PathBuf::from(text_arg(args, key)?);
    if !p.is_absolute() {
        abort!("{key} must be an absolute path, got {}", p.display());
    }
    Ok(p)
}

fn flag(args: &Value, key: &str) -> bool {
    args[key].as_bool().unwrap_or(false)
}

fn passes(args: &Value) -> R<u32> {
    match args["passes"].as_u64() {
        None => Ok(3),
        Some(n @ 1..=35) => Ok(n as u32),
        Some(n) => abort!("passes must be 1 to 35, got {n}"),
    }
}

fn tools() -> Value {
    let keep = json!({
        "type": "boolean",
        "description": "Deliver and verify, but leave the source alone (the user isn't asked to shred)."
    });
    let passes = json!({
        "type": "integer",
        "minimum": 1,
        "maximum": 35,
        "description": "Random overwrite passes before the final zero pass, if the user approves the shred (default 3)."
    });
    let shred_rule = "Once the receiver's copy is verified, the user is asked directly whether \
to shred the source; you can't answer that question, and anything but their yes keeps it.";
    json!([
        {
            "name": "get_config",
            "description": "Show sxfer's settings on this machine: the networks LAN sends may connect to, and the config file's location.",
            "inputSchema": { "type": "object", "properties": {} },
            "annotations": { "title": "sxfer settings", "readOnlyHint": true, "openWorldHint": false }
        },
        {
            "name": "discover_listeners",
            "description": "Look for `sxfer listen` receivers on the local network (mDNS). Doesn't work across VPNs or WireGuard; use send_file's `to` there.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "wait_seconds": { "type": "integer", "minimum": 1, "maximum": 10, "description": "How long to listen for answers (default 2)." }
                }
            },
            "annotations": { "title": "Find receivers", "readOnlyHint": true, "openWorldHint": true }
        },
        {
            "name": "send_file",
            "description": format!("Send a file directly to a machine running `sxfer listen`, paired by the 6-digit code shown there. Without `to`, finds the one receiver on the configured networks. {shred_rule}"),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Absolute path of the file to send." },
                    "code": { "type": "string", "description": "The one-time code the receiver shows, e.g. 482-913. Ask the user; never guess." },
                    "to": { "type": "string", "description": "Receiver as ip:port (it prints its port). Needed over VPNs, WireGuard, or when several receivers are found." },
                    "keep": keep,
                    "passes": passes
                },
                "required": ["path", "code"]
            },
            "annotations": { "title": "Send a file (LAN)", "readOnlyHint": false, "destructiveHint": true, "openWorldHint": true }
        },
        {
            "name": "push_file",
            "description": format!("Copy a local file to host:path over the user's ssh setup (aliases, keys, agent; no password prompts). The remote side needs sh, sha256sum and shred. {shred_rule}"),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Absolute path of the local file." },
                    "dest": { "type": "string", "description": "host:path, e.g. myserver:/root/ (a trailing / or a directory keeps the file name)." },
                    "keep": keep,
                    "passes": passes
                },
                "required": ["path", "dest"]
            },
            "annotations": { "title": "Push a file (SSH)", "readOnlyHint": false, "destructiveHint": true, "openWorldHint": true }
        },
        {
            "name": "pull_file",
            "description": format!("Copy host:file here over the user's ssh setup. The shred question is about the remote copy. {shred_rule}"),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "src": { "type": "string", "description": "host:path of the remote file." },
                    "dest": { "type": "string", "description": "Absolute local path or directory." },
                    "keep": keep,
                    "passes": passes
                },
                "required": ["src", "dest"]
            },
            "annotations": { "title": "Pull a file (SSH)", "readOnlyHint": false, "destructiveHint": true, "openWorldHint": true }
        },
        {
            "name": "start_listener",
            "description": "Receive one file on this machine: opens a listener in the background and returns its one-time code for the sender. Refuses secrets. Check listener_status afterwards.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "dir": { "type": "string", "description": "Absolute path of the folder received files are saved in." }
                },
                "required": ["dir"]
            },
            "annotations": { "title": "Receive a file", "readOnlyHint": false, "destructiveHint": false, "openWorldHint": true }
        },
        {
            "name": "listener_status",
            "description": "Whether the listener is still waiting, what it received, and whether the sender shredded its copy.",
            "inputSchema": { "type": "object", "properties": {} },
            "annotations": { "title": "Listener status", "readOnlyHint": true, "openWorldHint": false }
        },
        {
            "name": "stop_listener",
            "description": "Close the listener started by start_listener.",
            "inputSchema": { "type": "object", "properties": {} },
            "annotations": { "title": "Stop listening", "readOnlyHint": false, "destructiveHint": false, "openWorldHint": false }
        }
    ])
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("--version" | "-V") => {
            println!("sxfer-mcp {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        Some("--help" | "-h") => {
            println!("{USAGE}");
            return;
        }
        _ => {}
    }
    // ssh must never stop at a password or host-key prompt that nobody can see
    std::env::set_var("SXFER_SSH_BATCH", "1");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let mut server = Server::new(rx, Box::new(std::io::stdout()));
    while let Some(msg) = server.recv() {
        server.handle(msg);
    }
    if let Some(l) = &server.listener {
        l.stop.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Captures what the server writes to the client.
    #[derive(Clone, Default)]
    struct Buf(Rc<RefCell<Vec<u8>>>);

    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Buf {
        fn messages(&self) -> Vec<Value> {
            let text = String::from_utf8(self.0.borrow().clone()).unwrap();
            text.lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        }
    }

    fn server(lines: &[&str]) -> (Server, Buf) {
        let (tx, rx) = mpsc::channel();
        for l in lines {
            tx.send(l.to_string()).unwrap();
        }
        let buf = Buf::default();
        (Server::new(rx, Box::new(buf.clone())), buf)
    }

    fn ask(can_ask: bool, client_lines: &[&str]) -> (Result<(), String>, Server, Buf) {
        let (s, buf) = server(client_lines);
        let r = {
            let mut peer = s.peer.borrow_mut();
            peer.can_ask = can_ask;
            peer.ask_user("Shred /tmp/x?")
        };
        (r, s, buf)
    }

    const YES: &str = r#"{"jsonrpc":"2.0","id":"sxfer-ask-1","result":{"action":"accept","content":{"shred":true}}}"#;

    #[test]
    fn initialize_negotiates_version_and_elicitation() {
        let (mut s, _) = server(&[]);
        let modern =
            json!({ "protocolVersion": "2025-06-18", "capabilities": { "elicitation": {} } });
        assert_eq!(s.initialize(&modern)["protocolVersion"], "2025-06-18");
        assert!(s.peer.borrow().can_ask);
        let unknown = json!({ "protocolVersion": "1999-01-01", "capabilities": {} });
        assert_eq!(
            s.initialize(&unknown)["protocolVersion"],
            PROTOCOL_VERSIONS[0]
        );
        assert!(!s.peer.borrow().can_ask);
    }

    #[test]
    fn tools_are_files_only_with_object_schemas() {
        let tools = tools();
        let names: Vec<&str> = tools
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "get_config",
                "discover_listeners",
                "send_file",
                "push_file",
                "pull_file",
                "start_listener",
                "listener_status",
                "stop_listener"
            ]
        );
        for t in tools.as_array().unwrap() {
            assert_eq!(t["inputSchema"]["type"], "object", "{}", t["name"]);
            assert!(t["description"].as_str().unwrap().len() > 20);
            let props = t["inputSchema"]["properties"].as_object().unwrap();
            for banned in ["text", "secret", "yes", "confirm", "shred"] {
                assert!(!props.contains_key(banned), "{} takes {banned}", t["name"]);
            }
        }
    }

    #[test]
    fn only_an_explicit_yes_shreds() {
        assert_eq!(ask(true, &[YES]).0, Ok(()));
        let unticked = YES.replace("true", "false");
        assert!(ask(true, &[&unticked]).0.is_err());
        let declined = r#"{"jsonrpc":"2.0","id":"sxfer-ask-1","result":{"action":"decline"}}"#;
        assert!(ask(true, &[declined]).0.is_err());
        let cancelled = r#"{"jsonrpc":"2.0","id":"sxfer-ask-1","result":{"action":"cancel"}}"#;
        assert!(ask(true, &[cancelled]).0.is_err());
        let failed = r#"{"jsonrpc":"2.0","id":"sxfer-ask-1","error":{"code":-1,"message":"no"}}"#;
        assert!(ask(true, &[failed]).0.is_err());
        let wrong_id = YES.replace("sxfer-ask-1", "sxfer-ask-9");
        assert!(
            ask(true, &[&wrong_id]).0.is_err(),
            "another id is not an answer"
        );
    }

    #[test]
    fn no_elicitation_means_keep_and_nothing_is_sent() {
        let (r, _, buf) = ask(false, &[YES]);
        assert!(r.unwrap_err().contains("elicitation"));
        assert!(buf.messages().is_empty());
    }

    #[test]
    fn question_goes_to_the_client_and_other_traffic_waits() {
        let ping = r#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#;
        let list = r#"{"jsonrpc":"2.0","id":8,"method":"tools/list"}"#;
        let (r, s, buf) = ask(true, &[ping, list, YES]);
        assert_eq!(r, Ok(()));
        let out = buf.messages();
        assert_eq!(out[0]["method"], "elicitation/create");
        assert!(out[0]["params"]["message"]
            .as_str()
            .unwrap()
            .contains("Shred /tmp/x?"));
        assert_eq!(out[1]["id"], 7, "ping answered while waiting");
        assert_eq!(s.recv().unwrap()["id"], 8, "tools/list kept for later");
    }

    #[test]
    fn json_rpc_round_trip() {
        let (mut s, buf) = server(&[]);
        let init = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} });
        s.handle(init);
        s.handle(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        let call = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "send_file", "arguments": { "path": "relative.txt", "code": "1" } }
        });
        s.handle(call);
        s.handle(json!({ "jsonrpc": "2.0", "id": 3, "method": "nope" }));
        let out = buf.messages();
        assert_eq!(out.len(), 3, "notifications get no reply: {out:?}");
        assert_eq!(out[0]["result"]["serverInfo"]["name"], "sxfer");
        assert_eq!(out[1]["result"]["isError"], true);
        let text = out[1]["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("absolute"), "{text}");
        assert_eq!(out[2]["error"]["code"], -32601);
    }

    #[test]
    fn argument_checks() {
        let abs = std::env::temp_dir().join("x.txt");
        let ok = json!({ "path": abs.to_string_lossy() });
        assert_eq!(path_arg(&ok, "path").unwrap(), abs);
        assert!(path_arg(&json!({ "path": "x.txt" }), "path").is_err());
        assert!(path_arg(&json!({}), "path").is_err());
        assert_eq!(passes(&json!({})).unwrap(), 3);
        assert_eq!(passes(&json!({ "passes": 7 })).unwrap(), 7);
        assert!(passes(&json!({ "passes": 0 })).is_err());
        assert!(passes(&json!({ "passes": 99 })).is_err());
    }
}
