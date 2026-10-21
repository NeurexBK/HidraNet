//! No address, and no destination hostname, reaches the log in the clear.
//!
//! This is a lint over the source rather than a unit test, because the thing
//! it guards against is not a wrong result — it is someone adding one more
//! `info!(peer = %addr, …)` to a relay six months from now. There is nothing
//! to assert at runtime: the line simply appears in a file on an operator's
//! disk, and nobody notices until it matters.
//!
//! It also catches the specific way this codebase gets it wrong. `main.rs`
//! carries its own inlined copies of the relay, proxy, client and p2p
//! modules, so a fix applied only to `src/relay/router.rs` leaves the shipped
//! binary logging exactly as before. That already happened once with the
//! post-quantum handshake, which lived in the library while the binary ran
//! X25519 alone. Scanning every source file means the copies are held to the
//! same rule whether or not anyone remembers they exist.

use std::fs;
use std::path::{Path, PathBuf};

/// Log fields that name a person, a destination, or a hop in a circuit.
const SENSITIVE_FIELDS: &[&str] = &[
    "remote_addr",
    "next_hop",
    "hostname",
    "host",
    "peer",
    "target",
    "relay",
    // These four were missed the first time round. The first sweep looked for
    // `target = %`, which does not match `target_domain = %`, and did not
    // think of `client_ip` at all — so the SOCKS handler went on writing who
    // connected and which site they asked for, on the user's own machine,
    // which is their browsing history on disk.
    "client_ip",
    "target_domain",
    "address",
    "service",
    // Content, not just identity. An exit relay logging the payload it just
    // decrypted writes what a user said to an operator's disk, which is worse
    // than writing who they are; the same goes for what came back. Ping and
    // Pong bodies arrive from a peer, so echoing them lets anyone else write
    // this log too.
    "payload",
    "response",
    // A HidraMail address, a chat nickname and a room id are the identities
    // this product exists to keep apart from each other.
    "nick",
    "room",
    "from",
    "to",
    "mail",
    // A message id appears in both the sender's log and the recipient's, so in
    // the clear it links the two.
    "id",
];

/// Fields that look sensitive but name this node's own configuration. A bind
/// address is in the operator's own config file; scrubbing it would only make
/// the log harder to read.
const OWN_CONFIGURATION: &[&str] = &[
    "listen_addr = %",
    "addr = %addr, \"status API server",
    "addr = %addr, \"analytics dashboard",
    "addr = %addr, \"listening for inbound",
    "addr = %self.addr",
    "addr = %config.listen_addr",
    "addr = %addr, \"local relay node started\"",
    // Bootstrap nodes and DNS seeds are published addresses of public
    // infrastructure, not of a user.
    "\"DNS seed resolved\"",
    "\"DNS seed resolution failed\"",
    "\"pinging bootstrap node\"",
    "\"bootstrap node unreachable\"",
    "\"bootstrap node timed out\"",
    // This node's own mail address and its own site, printed once at startup on
    // the machine of the person they belong to.
    "mail = %self.state.mail_addr",
    "site = %name",
    // The response to a readiness probe is a constant, not a user's traffic.
    "response = %\"ok\"",
];

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// True when the line is a tracing macro call.
///
/// Spans count too: a field on a span is printed with every event logged
/// inside it, so `info_span!("relay_session", remote_addr = %remote_addr)`
/// put the client's address on every line a relay wrote about them, and the
/// first version of this check, looking only at events, never saw it. So does
/// the qualified form, `tracing::warn!(`, which it also missed.
fn is_log_line(line: &str) -> bool {
    let t = line.trim_start();
    [
        "info!(", "warn!(", "error!(", "debug!(", "trace!(",
        "info_span!(", "warn_span!(", "error_span!(", "debug_span!(", "trace_span!(", "span!(",
    ]
    .iter()
    .any(|m| {
        t.starts_with(m)
            || t.contains(&format!(" {m}"))
            || t.contains(&format!("::{m}"))
            || t.contains(&format!("({m}"))
    })
}

/// Every tracing macro call in a file, with the line it starts on, joined
/// into one line. rustfmt breaks a call with several fields over several
/// lines, and a check that looked only at the first one missed
/// `relay = %relay.name` sitting on the line below `info!(`.
fn log_calls(text: &str) -> Vec<(usize, String)> {
    let mut calls = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut n = 0;
    while n < lines.len() {
        if !is_log_line(lines[n]) {
            n += 1;
            continue;
        }
        let start = n;
        let mut joined = String::new();
        let mut depth = 0i32;
        let mut opened = false;
        while n < lines.len() {
            let line = lines[n].trim();
            if !joined.is_empty() {
                joined.push(' ');
            }
            joined.push_str(line);
            for c in line.chars() {
                match c {
                    '(' => {
                        depth += 1;
                        opened = true;
                    }
                    ')' => depth -= 1,
                    _ => {}
                }
            }
            n += 1;
            if opened && depth <= 0 {
                break;
            }
        }
        calls.push((start, joined));
    }
    calls
}

/// The arguments of a macro call, split on the commas between them.
fn arguments(call: &str) -> Vec<&str> {
    let Some(open) = call.find('(') else {
        return Vec::new();
    };
    let inner = &call[open + 1..];
    let mut args = Vec::new();
    let (mut depth, mut quoted, mut from) = (0i32, false, 0);
    for (i, c) in inner.char_indices() {
        match c {
            '"' => quoted = !quoted,
            '(' | '[' | '{' if !quoted => depth += 1,
            ')' | ']' | '}' if !quoted => {
                if depth == 0 {
                    args.push(inner[from..i].trim());
                    return args;
                }
                depth -= 1;
            }
            ',' if !quoted && depth == 0 => {
                args.push(inner[from..i].trim());
                from = i + 1;
            }
            _ => {}
        }
    }
    args
}

#[test]
fn no_log_line_carries_an_unscrubbed_address() {
    let mut files = Vec::new();
    rust_sources(Path::new("src"), &mut files);
    assert!(!files.is_empty(), "found no sources to scan");

    let mut offences = Vec::new();

    for path in &files {
        // safelog is where the scrubbing is implemented and tested.
        if path.ends_with("safelog.rs") {
            continue;
        }
        let Ok(text) = fs::read_to_string(path) else { continue };
        for (n, line) in log_calls(&text) {
            let line = line.as_str();
            if OWN_CONFIGURATION.iter().any(|ok| line.contains(ok)) {
                continue;
            }
            let mut offend = || offences.push(format!("{}:{}  {}", path.display(), n + 1, line));
            // `info!(circuit_id, payload, …)` records a variable under its
            // own name, with no `=` for the check below to find.
            for arg in arguments(line) {
                let bare = arg.trim_start_matches(['%', '?']);
                if SENSITIVE_FIELDS.contains(&bare) {
                    offend();
                }
            }
            for field in SENSITIVE_FIELDS {
                // `field = %value` or `field = ?value`, not already wrapped.
                for sigil in ['%', '?'] {
                    let needle = format!("{field} = {sigil}");
                    let mut from = 0;
                    while let Some(rel) = line[from..].find(&needle) {
                        let at = from + rel;
                        from = at + needle.len();
                        // `id` must not match the tail of `session_id`.
                        let preceded_by_name = line[..at]
                            .chars()
                            .next_back()
                            .is_some_and(|c| c.is_alphanumeric() || c == '_');
                        if preceded_by_name {
                            continue;
                        }
                        let value = &line[at + needle.len()..];
                        if !value.starts_with("sensitive(") {
                            offend();
                        }
                    }
                }
            }
        }
    }

    assert!(
        offences.is_empty(),
        "these log lines would write an address or a hostname to disk in the \
         clear. Wrap the value in safelog::sensitive(&…):\n\n{}\n",
        offences.join("\n")
    );
}

#[test]
fn the_shipped_configuration_keeps_safe_logging_on() {
    for name in ["config.toml", "config_chat.toml", "config_mail.toml"] {
        let Ok(text) = fs::read_to_string(name) else { continue };
        assert!(
            !text.contains("unsafe_addresses = true"),
            "{name} ships with address logging turned on"
        );
        assert!(
            !text.contains(r#"level = "trace""#),
            "{name} ships at trace level"
        );
        assert!(
            !text.contains(r#"level = "debug""#),
            "{name} ships at debug level, which turns on the per-connection \
             lines a relay operator should not be keeping"
        );
    }
}
