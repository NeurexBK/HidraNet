//! HidraNet — engine library.
//!
//! The binary (`main.rs`) keeps its own copy of these modules inlined, for
//! historical reasons. This library exposes the module tree that already
//! existed in `src/` as separate files and which, without a library target,
//! nothing was compiling.
//!
//! This is not cosmetic: the four files in `tests/` do `use hidra_node::…` and,
//! with no `lib.rs`, failed to compile with "unresolved crate `hidra_node`".
//! They sat in the repository having never run. With this target they run —
//! 30 integration tests, on top of the 41 unit tests in the modules themselves.
//!
//! The duplication between `main.rs` and this tree remains technical debt to
//! pay off: the binary should consume this library instead of keeping parallel
//! modules. Until that happens, a fix made on one side has to be mirrored on
//! the other — which is precisely why the duplication is a problem rather than
//! a convenience.

pub mod error;
pub mod logging;
pub mod config;

pub mod crypto;
pub mod network;
pub mod onion;
pub mod p2p;
pub mod relay;
pub mod proxy;
pub mod client;
pub mod api;
pub mod local_guard;
pub mod safelog;
