//! No address, and no destination hostname, reaches the log in the clear.
//!
//! This is a lint over the source rather than a unit test, because the thing
//! it guards against is not a wrong result — it is someone adding one more
//! `info!(peer = %addr, …)` to a relay six months from now. There is nothing
//! to assert at runtime: the line simply appears in a file on an operator's
//! disk, and nobody notices until it matters.
//!
//! It checks events and spans, including multiline and shorthand fields.
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
    "addr",
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
    "\"bootstrap node responded\"",
    "\"bootstrap node timed out\"",
    // This node's own mail address and its own site, printed once at startup on
    // the machine of the person they belong to.
    "mail = %self.state.mail_addr",
    "site = %name",
    // The response to a readiness probe is a constant, not a user's traffic.
    "response = %\"ok\"",
];

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

// Collect a tracing invocation across lines. Strings are ignored when tracking
// parentheses and commas, so punctuation in a log message is not a field.
fn tracing_calls(source: &str) -> Vec<(usize, String)> {
    let mut calls = Vec::new();
    let mut current = String::new();
    let mut start_line = 0;
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    for (line_no, line) in source.lines().enumerate() {
        if current.is_empty() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            let at = ["trace", "debug", "info", "warn", "error"]
                .iter()
                .flat_map(|level| [format!("{level}!("), format!("{level}_span!(")])
                .filter_map(|name| line.find(&name).map(|at| at + name.len()))
                .min();
            let Some(at) = at else { continue };
            start_line = line_no + 1;
            depth = 1;
            quoted = false;
            escaped = false;
            current.push('(');
            scan_call(
                &line[at..],
                &mut current,
                &mut depth,
                &mut quoted,
                &mut escaped,
            );
        } else {
            current.push('\n');
            scan_call(line, &mut current, &mut depth, &mut quoted, &mut escaped);
        }
        if depth == 0 {
            calls.push((start_line, std::mem::take(&mut current)));
        }
    }
    calls
}

fn scan_call(
    line: &str,
    call: &mut String,
    depth: &mut usize,
    quoted: &mut bool,
    escaped: &mut bool,
) {
    for ch in line.chars() {
        call.push(ch);
        if *quoted {
            if *escaped {
                *escaped = false;
            } else if ch == '\\' {
                *escaped = true;
            } else if ch == '"' {
                *quoted = false;
            }
        } else if ch == '"' {
            *quoted = true;
        } else if ch == '(' {
            *depth += 1;
        } else if ch == ')' {
            *depth -= 1;
            if *depth == 0 {
                break;
            }
        }
    }
}

fn unscrubbed_fields(call: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    let mut start = 0;
    let body = &call[1..call.len() - 1];
    for (at, ch) in body
        .char_indices()
        .chain(std::iter::once((body.len(), ',')))
    {
        if quoted {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
        } else if ch == '"' {
            quoted = true;
        } else if matches!(ch, '(' | '[' | '{') {
            depth += 1;
        } else if matches!(ch, ')' | ']' | '}') {
            depth -= 1;
        } else if ch == ',' && depth == 0 {
            let field = body[start..at].trim();
            start = at + 1;
            let (name, value) = field.split_once('=').unwrap_or((field, ""));
            let name = name.trim().trim_start_matches(['%', '?']);
            if SENSITIVE_FIELDS.contains(&name)
                && !value
                    .trim()
                    .trim_start_matches(['%', '?'])
                    .starts_with("sensitive(")
            {
                fields.push(field.to_string());
            }
        }
    }
    fields
}

#[test]
fn lint_catches_multiline_spans_and_shorthand_fields() {
    let source = r#"
let span = tracing::info_span!(
    "relay_session",
    session_id = %session_id,
    remote_addr = %remote_addr,
);
info!(circuit_id, host, port, "connected (with a comma, too)");
tracing::debug!(payload, "building onion packet");
"#;
    let calls = tracing_calls(source);
    assert_eq!(calls.len(), 3);
    assert_eq!(
        unscrubbed_fields(&calls[0].1),
        ["remote_addr = %remote_addr"]
    );
    assert_eq!(unscrubbed_fields(&calls[1].1), ["host"]);
    assert_eq!(unscrubbed_fields(&calls[2].1), ["payload"]);
}

#[test]
fn lint_accepts_scrubbed_values_without_confusing_session_ids() {
    let calls = tracing_calls(
        r#"
info!(host = %sensitive(&host), bytes = payload.len(), "sent");
let span = tracing::debug_span!("relay", session_id = %session_id,
    remote_addr = ?sensitive(&remote_addr));
// info!(payload, "a commented-out example");
"#,
    );
    assert_eq!(calls.len(), 2);
    assert!(
        calls
            .iter()
            .all(|(_, call)| unscrubbed_fields(call).is_empty())
    );
}

#[test]
fn no_log_line_carries_an_unscrubbed_address() {
    let mut files = Vec::new();
    rust_sources(Path::new("src"), &mut files);
    assert!(!files.is_empty(), "found no sources to scan");
    let mut offences = Vec::new();
    for path in &files {
        if path.ends_with("safelog.rs") {
            continue;
        }
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        for (line_no, call) in tracing_calls(&text) {
            let normalized = call.split_whitespace().collect::<Vec<_>>().join(" ");
            if OWN_CONFIGURATION.iter().any(|ok| normalized.contains(ok)) {
                continue;
            }
            for field in unscrubbed_fields(&call) {
                offences.push(format!("{}:{line_no}  {field}", path.display()));
            }
        }
    }
    assert!(
        offences.is_empty(),
        "these log fields would write an address, identity or payload in the clear. \
         Wrap the value in safelog::sensitive(&…):\n\n{}\n",
        offences.join("\n")
    );
}

#[test]
fn the_shipped_configuration_keeps_safe_logging_on() {
    for name in ["config.toml", "config_chat.toml", "config_mail.toml"] {
        let Ok(text) = fs::read_to_string(name) else {
            continue;
        };
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
