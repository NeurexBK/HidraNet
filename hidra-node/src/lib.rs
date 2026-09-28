//! HidraNet — biblioteca do motor.
//!
//! O binário (`main.rs`) mantém a sua própria cópia dos módulos embutida, por
//! razões históricas. Esta biblioteca expõe a árvore de módulos que já existia
//! em `src/` como ficheiros separados, e que sem um alvo de biblioteca não era
//! compilada por ninguém.
//!
//! Isto não é cosmético: os quatro ficheiros em `tests/` fazem
//! `use hidra_node::…` e, sem `lib.rs`, falhavam a compilar com
//! "unresolved crate `hidra_node`". Estavam no repositório sem nunca terem
//! corrido. Com este alvo passam a correr — 30 testes de integração, além dos
//! 41 unitários dos próprios módulos.
//!
//! A duplicação entre `main.rs` e esta árvore continua a ser dívida técnica a
//! resolver: o binário deve passar a consumir esta biblioteca em vez de manter
//! módulos paralelos. Enquanto isso não acontecer, uma correção feita num dos
//! lados tem de ser replicada no outro — e é exatamente por isso que a
//! duplicação é um problema, não uma conveniência.

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
