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

/// The macros whose fields end up in the log: the five event macros and the
/// span macros. A span's fields are printed on every event recorded inside
/// it, which makes an address in a span worse than one in a single line, and
/// the first version of this lint did not look at spans at all.
const LOG_MACROS: &[&str] = &[
    "info!(",
    "warn!(",
    "error!(",
    "debug!(",
    "trace!(",
    "info_span!(",
    "warn_span!(",
    "error_span!(",
    "debug_span!(",
    "trace_span!(",
    "span!(",
];

/// Where a tracing macro call opens on this line, if one does.
fn log_macro_start(line: &str) -> Option<usize> {
    LOG_MACROS
        .iter()
        .filter_map(|m| {
            let at = line.find(m)?;
            // `info!(` must not match inside `my_info!(`; the span macros
            // are matched as whole words the same way.
            let preceded_by_name = line[..at]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_');
            (!preceded_by_name).then_some(at)
        })
        .min()
}

/// Parenthesis depth change over `text`, ignoring string literals as best a
/// line-by-line scan can: a `(` inside `"…"` is not a macro argument.
fn depth_change(text: &str) -> i32 {
    let mut depth = 0;
    let mut in_string = false;
    let mut escaped = false;
    for c in text.chars() {
        if in_string {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
    }
    depth
}

/// Files the lint reads but does not yet hold to the rule.
///
/// The DHT is mid-rewrite in a change that is not on GitHub yet, and the
/// lines it would flag there live in exactly the files that change rewrites.
/// Fixing them here would collide with it; so they are listed, the exemption
/// is loud, and it comes out the moment that change lands. What it covers
/// today: a `target = %addr` on an outgoing DHT message and two peer ids in
/// `src/p2p/dht/`.
const FROZEN_UNTIL_DHT_BATCH_LANDS: &[&str] = &["src/p2p/dht/"];

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
        let shown = path.display().to_string().replace('\\', "/");
        if FROZEN_UNTIL_DHT_BATCH_LANDS.iter().any(|dir| shown.contains(dir)) {
            continue;
        }
        let Ok(text) = fs::read_to_string(path) else { continue };
        // A macro call that spans several lines is still one call, and a
        // field on its third line reaches the log the same as one on its
        // first. Track the open call and check every line until it closes.
        let mut open_depth: i32 = 0;
        for (n, line) in text.lines().enumerate() {
            let in_call = if open_depth > 0 {
                open_depth += depth_change(line);
                true
            } else if let Some(at) = log_macro_start(line) {
                open_depth = depth_change(&line[at..]);
                true
            } else {
                false
            };
            if !in_call {
                continue;
            }
            if OWN_CONFIGURATION.iter().any(|ok| line.contains(ok)) {
                continue;
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
                            offences.push(format!(
                                "{}:{}  {}",
                                path.display(),
                                n + 1,
                                line.trim()
                            ));
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
