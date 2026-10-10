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
fn is_log_line(line: &str) -> bool {
    let t = line.trim_start();
    ["info!(", "warn!(", "error!(", "debug!(", "trace!("]
        .iter()
        .any(|m| t.starts_with(m) || t.contains(&format!(" {m}")))
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
        for (n, line) in text.lines().enumerate() {
            if !is_log_line(line) {
                continue;
            }
            if OWN_CONFIGURATION.iter().any(|ok| line.contains(ok)) {
                continue;
            }
            for field in SENSITIVE_FIELDS {
                // `field = %value` or `field = ?value`, not already wrapped.
                for sigil in ['%', '?'] {
                    let needle = format!("{field} = {sigil}");
                    if let Some(at) = line.find(&needle) {
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
