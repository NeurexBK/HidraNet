//! What may reach a log at all.
//!
//! HidraVPN's own code logs counts and states, never an address, a key, a
//! name looked up or a byte of traffic. The libraries it is built on are not
//! held to that: at DEBUG the DNS resolver writes every name it is asked,
//! and a WireGuard library may write peers' endpoints. So whatever `RUST_LOG`
//! asks for applies to HidraVPN's own crates only, and every other crate is
//! silenced, at every level — a node operator who turns on DEBUG to chase a
//! problem must not, by doing so, start recording what their clients do.

/// The `tracing` directives for a `RUST_LOG` value: its directives for
/// HidraVPN's own crates (a bare level applies to all of them), everything
/// else off. With nothing usable in it, `default`.
pub fn directives(rust_log: Option<&str>, default: &str) -> String {
    let mut kept = Vec::new();
    for d in rust_log.unwrap_or_default().split(',') {
        let d = d.trim();
        if d.is_empty() || d.contains('[') || d.contains('{') {
            continue;
        }
        match d.split_once('=') {
            Some((target, level)) => {
                if target.trim().starts_with("hidravpn") && is_level(level) {
                    kept.push(format!("{}={}", target.trim(), level.trim()));
                }
            }
            None if is_level(d) => kept.push(format!("hidravpn={d}")),
            None if d.starts_with("hidravpn") => kept.push(d.to_string()),
            None => {}
        }
    }
    if kept.is_empty() {
        kept.push(default.to_string());
    }
    format!("off,{}", kept.join(","))
}

fn is_level(s: &str) -> bool {
    matches!(
        s.trim().to_ascii_lowercase().as_str(),
        "trace" | "debug" | "info" | "warn" | "error" | "off"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_our_own_crates_ever_log() {
        assert_eq!(
            directives(Some("debug"), "hidravpn_node=info"),
            "off,hidravpn=debug"
        );
        assert_eq!(
            directives(
                Some("hickory_proto=trace,boringtun=debug"),
                "hidravpn_node=info"
            ),
            "off,hidravpn_node=info"
        );
        assert_eq!(
            directives(Some("info,hidravpn_service=debug,tokio=trace"), "x=info"),
            "off,hidravpn=info,hidravpn_service=debug"
        );
        assert_eq!(
            directives(None, "hidravpn_service=info"),
            "off,hidravpn_service=info"
        );
        assert_eq!(
            directives(Some("hidravpn[span{f=1}]=debug"), "hidravpn=info"),
            "off,hidravpn=info"
        );
    }
}
