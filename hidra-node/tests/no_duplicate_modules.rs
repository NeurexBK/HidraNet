//! main.rs declares modules; it does not contain them.
//!
//! It used to contain about five thousand lines of them — its own copies of
//! network, onion, p2p, relay, proxy and client, alongside the library's. The
//! two sets drifted in both directions and nothing said so. The library got
//! the hybrid ML-KEM handshake and the 0600 key creation while the binary
//! went on speaking X25519 and writing secrets with `fs::write`; the binary
//! got the relay router's hidden-service bridging, the DHT's service lookup
//! and the SOCKS handler's `.hidra` resolution while the library had none of
//! it. Every fix had to be applied twice, and the time it was not, the half
//! that shipped kept the old behaviour with every test still green — because
//! the tests read the library and the users ran the binary.
//!
//! That cannot be left to discipline. A module with a body in main.rs is
//! invisible from the library by construction: no test reaches it, no lint
//! compares it to anything, and the only way to find out it has gone stale is
//! for someone to notice at runtime, months later. So the rule is mechanical
//! — declare it with `#[path]` and keep the code in a file both targets read.

use std::fs;
use std::path::Path;

/// `mod name {` at the start of a line: a module with a body.
fn inline_modules(source: &str) -> Vec<(usize, String)> {
    source
        .lines()
        .enumerate()
        .filter_map(|(n, line)| {
            let trimmed = line.trim_start();
            let name = trimmed
                .strip_prefix("pub mod ")
                .or_else(|| trimmed.strip_prefix("mod "))?
                .strip_suffix(" {")?;
            // A test module is the one body that belongs in the file it tests.
            if name == "tests" {
                return None;
            }
            Some((n + 1, name.to_string()))
        })
        .collect()
}

#[test]
fn main_declares_modules_rather_than_containing_them() {
    let source = fs::read_to_string("src/main.rs").expect("src/main.rs");
    let offenders = inline_modules(&source);

    assert!(
        offenders.is_empty(),
        "these modules have a body in main.rs, so the library cannot reach \
         them and nothing can tell when they drift from a copy that can. Move \
         the code to a file under src/ and declare it here with #[path]:\n\n{}\n",
        offenders
            .iter()
            .map(|(line, name)| format!("  src/main.rs:{line}  mod {name}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn every_module_main_declares_resolves_to_a_file_the_library_also_reads() {
    let source = fs::read_to_string("src/main.rs").expect("src/main.rs");
    let lib = fs::read_to_string("src/lib.rs").expect("src/lib.rs");

    // Each `#[path = "x.rs"]` in main.rs has to point at something real.
    let mut missing = Vec::new();
    let mut top_level = Vec::new();
    let mut lines = source.lines().enumerate().peekable();
    while let Some((n, line)) = lines.next() {
        let Some(rest) = line.trim_start().strip_prefix("#[path = \"") else {
            continue;
        };
        let Some(path) = rest.split('"').next() else { continue };
        let indented = line.starts_with(' ');

        // The path is relative to the enclosing module's directory. Only the
        // top-level ones can be checked from here without parsing the nesting,
        // and those are the ones that matter: they are what the library also
        // names.
        if !indented {
            let full = Path::new("src").join(path);
            if !full.exists() {
                missing.push(format!("  src/main.rs:{}  {}", n + 1, full.display()));
            }
            if let Some((_, decl)) = lines.peek() {
                if let Some(name) = decl
                    .trim_start()
                    .strip_prefix("pub mod ")
                    .or_else(|| decl.trim_start().strip_prefix("mod "))
                    .and_then(|s| s.strip_suffix(';'))
                {
                    top_level.push(name.to_string());
                }
            }
        }
    }

    assert!(
        missing.is_empty(),
        "main.rs points at files that do not exist:\n{}",
        missing.join("\n")
    );

    // And the library should be declaring the same ones, so both targets
    // compile the same code.
    let not_in_lib: Vec<&String> = top_level
        .iter()
        .filter(|name| {
            !lib.contains(&format!("pub mod {name};")) && !lib.contains(&format!("mod {name};"))
        })
        .collect();

    assert!(
        not_in_lib.is_empty(),
        "the binary reads these modules and the library does not declare them, \
         so nothing in the test suite covers the code that ships:\n{}",
        not_in_lib
            .iter()
            .map(|n| format!("  mod {n}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
