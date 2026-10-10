//! Keeping addresses out of the log.
//!
//! A relay sees things no one else does. On the way in it sees the address of
//! whoever connected; in the middle it sees the next hop; at the exit it sees
//! the hostname and port the user asked for. Written down together with a
//! circuit id, those lines are a record of who went where — the exact record
//! the network exists to not produce. It does not take a compromise to leak:
//! a support bundle, a crash dump, a shared terminal or a log shipped to a
//! hosting provider is enough, and the node used to ship with
//! `level = "debug"`, so all of it was on by default.
//!
//! So nothing sensitive reaches the log in the clear. Wrapping a value in
//! [`sensitive`] prints `[scrubbed:a1b2c3d4]` instead of the value, where the
//! tag is a keyed BLAKE3 hash under a key generated fresh in memory at
//! startup and never written anywhere.
//!
//! The tag is what makes this usable rather than merely safe. An operator
//! reading one run's log can still see that the same peer appears in three
//! places, which is most of what addresses in a log are for. What they cannot
//! do is recover the address: the key never leaves the process. Nor can
//! anyone line up two runs, or two relays, against each other — each has its
//! own key, so the same address tags differently in each. That matters more
//! than it sounds: an IPv4 address is only 32 bits, so an unkeyed hash of one
//! is recovered by trying all of them.
//!
//! [`set_unsafe_logging`] turns the real values back on for debugging. It is
//! off unless someone asks for it, and asking is recorded in the log.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use rand_core::{OsRng, RngCore};

static UNSAFE_LOGGING: AtomicBool = AtomicBool::new(false);
static CORRELATION_KEY: OnceLock<[u8; 32]> = OnceLock::new();

/// Print real addresses instead of scrubbing them.
///
/// For working out a routing problem on your own machine. On anything
/// carrying other people's traffic it writes down who connected and where
/// they went.
pub fn set_unsafe_logging(enabled: bool) {
    UNSAFE_LOGGING.store(enabled, Ordering::Relaxed);
}

pub fn unsafe_logging() -> bool {
    UNSAFE_LOGGING.load(Ordering::Relaxed)
}

/// The per-process key the tags are computed under. Generated on first use
/// and held only in memory, so it dies with the process and no two runs
/// produce the same tag for the same address.
fn correlation_key() -> &'static [u8; 32] {
    CORRELATION_KEY.get_or_init(|| {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    })
}

/// The tag that stands in for a value: eight hex characters, enough to tell
/// two peers apart in one log without being enough to confirm a guess.
fn tag_for(value: &str) -> String {
    let hash = blake3::keyed_hash(correlation_key(), value.as_bytes());
    hash.as_bytes()[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A value that must not reach the log in the clear.
pub struct Sensitive<T>(T);

/// Wrap a peer address, hostname or anything else that identifies a user.
pub fn sensitive<T>(value: T) -> Sensitive<T> {
    Sensitive(value)
}

impl<T: fmt::Display> fmt::Display for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if unsafe_logging() {
            write!(f, "{}", self.0)
        } else {
            write!(f, "[scrubbed:{}]", tag_for(&self.0.to_string()))
        }
    }
}

// Debug goes through Display as well. A `{:?}` on an address is the easiest
// way to undo all of this by accident.
impl<T: fmt::Display> fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    // The flag is global, so these run one at a time behind a mutex rather
    // than racing each other through it.
    static GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn scrubbed<T: fmt::Display>(value: T) -> String {
        let _lock = GUARD.lock().unwrap_or_else(|e| e.into_inner());
        set_unsafe_logging(false);
        format!("{}", sensitive(value))
    }

    #[test]
    fn an_address_never_appears_in_the_output() {
        let addr: SocketAddr = "203.0.113.9:9150".parse().unwrap();
        let line = scrubbed(addr);
        assert!(!line.contains("203.0.113.9"), "{line}");
        assert!(!line.contains("9150"), "{line}");
        assert!(line.starts_with("[scrubbed:"), "{line}");
    }

    #[test]
    fn a_hostname_never_appears_in_the_output() {
        let line = scrubbed("example.com");
        assert!(!line.contains("example.com"), "{line}");
    }

    #[test]
    fn debug_formatting_scrubs_too() {
        let _lock = GUARD.lock().unwrap_or_else(|e| e.into_inner());
        set_unsafe_logging(false);
        let line = format!("{:?}", sensitive("example.com"));
        assert!(!line.contains("example.com"), "{line}");
    }

    #[test]
    fn the_same_value_tags_the_same_way_within_a_run() {
        let _lock = GUARD.lock().unwrap_or_else(|e| e.into_inner());
        set_unsafe_logging(false);
        let a = format!("{}", sensitive("198.51.100.4:9150"));
        let b = format!("{}", sensitive("198.51.100.4:9150"));
        assert_eq!(a, b, "an operator has to be able to follow one peer");
    }

    #[test]
    fn different_values_tag_differently() {
        let _lock = GUARD.lock().unwrap_or_else(|e| e.into_inner());
        set_unsafe_logging(false);
        let a = format!("{}", sensitive("198.51.100.4:9150"));
        let b = format!("{}", sensitive("198.51.100.5:9150"));
        assert_ne!(a, b);
    }

    #[test]
    fn the_tag_is_not_a_plain_hash_of_the_value() {
        let _lock = GUARD.lock().unwrap_or_else(|e| e.into_inner());
        set_unsafe_logging(false);
        // An unkeyed hash of an IPv4 address is recovered by trying all 2^32
        // of them, so the tag must not be one.
        let value = "198.51.100.4:9150";
        let unkeyed: String = blake3::hash(value.as_bytes()).as_bytes()[..4]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let line = format!("{}", sensitive(value));
        assert!(!line.contains(&unkeyed), "{line}");
    }

    #[test]
    fn opting_out_brings_the_real_value_back() {
        let _lock = GUARD.lock().unwrap_or_else(|e| e.into_inner());
        set_unsafe_logging(true);
        let line = format!("{}", sensitive("203.0.113.9:9150"));
        set_unsafe_logging(false);
        assert_eq!(line, "203.0.113.9:9150");
    }
}
