//! Ed25519 signatures for HidraVPN release files.
//!
//!   hidravpn-sign keygen --out release.key          make a signing key (run this OFFLINE)
//!   hidravpn-sign sign   --key release.key FILE...  write FILE.sig for each file
//!   hidravpn-sign verify --pubkey BASE64 FILE...    check FILE against FILE.sig
//!   hidravpn-sign sha256 FILE...                    print hashes
//!
//! The secret key never belongs in the repository or on a build machine. The
//! public key is what ships: embedded in the browser in phase 4, so that only
//! a module signed with the matching secret is ever installed.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

#[derive(Parser)]
#[command(
    name = "hidravpn-sign",
    version,
    about = "Sign and verify HidraVPN release files (Ed25519)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Make a new signing key. Do this on a machine that is offline.
    Keygen {
        #[arg(long, default_value = "hidravpn-release.key")]
        out: PathBuf,
    },
    /// Sign files; writes FILE.sig beside each.
    Sign {
        #[arg(long)]
        key: PathBuf,
        files: Vec<PathBuf>,
    },
    /// Verify files against their .sig with the public key.
    Verify {
        #[arg(long)]
        pubkey: String,
        files: Vec<PathBuf>,
    },
    /// Print SHA-256 of files, in sha256sum's format.
    Sha256 { files: Vec<PathBuf> },
}

fn read_key(path: &Path) -> Result<SigningKey> {
    let s = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let bytes: [u8; 32] = B64
        .decode(s.trim())
        .context("the key file is not base64")?
        .try_into()
        .map_err(|_| anyhow!("a signing key is 32 bytes"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        return Err(anyhow!(
            "{} exists; not overwriting a signing key",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        std::io::Write::write_all(&mut f, bytes)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)?;
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Keygen { out } => {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|e| anyhow!("no randomness: {e}"))?;
            let key = SigningKey::from_bytes(&seed);
            write_secret(&out, B64.encode(seed).as_bytes())?;
            eprintln!(
                "secret key written to {} — keep it offline, back it up, never commit it",
                out.display()
            );
            println!("{}", B64.encode(key.verifying_key().to_bytes()));
            eprintln!("the line above is the public key; that is what goes into the browser");
        }
        Cmd::Sign { key, files } => {
            let key = read_key(&key)?;
            if files.is_empty() {
                return Err(anyhow!("nothing to sign"));
            }
            for f in files {
                let bytes =
                    std::fs::read(&f).with_context(|| format!("reading {}", f.display()))?;
                let sig = key.sign(&bytes);
                let sig_path = sig_path(&f);
                std::fs::write(&sig_path, B64.encode(sig.to_bytes()))?;
                println!(
                    "{}  {}  -> {}",
                    sha256_hex(&bytes),
                    f.display(),
                    sig_path.display()
                );
            }
        }
        Cmd::Verify { pubkey, files } => {
            let pk: [u8; 32] = B64
                .decode(pubkey.trim())
                .context("the public key is not base64")?
                .try_into()
                .map_err(|_| anyhow!("a public key is 32 bytes"))?;
            let vk = VerifyingKey::from_bytes(&pk).context("not a valid Ed25519 public key")?;
            // Nothing checked is not "verified": a script testing the exit
            // code must not take an empty list for a good one.
            if files.is_empty() {
                return Err(anyhow!("name the files to verify"));
            }
            let mut bad = 0;
            for f in &files {
                let bytes = std::fs::read(f).with_context(|| format!("reading {}", f.display()))?;
                let sig_b64 = std::fs::read_to_string(sig_path(f))
                    .with_context(|| format!("no signature for {}", f.display()))?;
                let sig_bytes: [u8; 64] = B64
                    .decode(sig_b64.trim())
                    .context("the signature is not base64")?
                    .try_into()
                    .map_err(|_| anyhow!("a signature is 64 bytes"))?;
                let sig = Signature::from_bytes(&sig_bytes);
                match vk.verify(&bytes, &sig) {
                    Ok(()) => println!("OK    {}", f.display()),
                    Err(_) => {
                        bad += 1;
                        println!(
                            "BAD   {}  (signature does not match: do not run this file)",
                            f.display()
                        );
                    }
                }
            }
            if bad > 0 {
                std::process::exit(1);
            }
        }
        Cmd::Sha256 { files } => {
            for f in files {
                let bytes =
                    std::fs::read(&f).with_context(|| format!("reading {}", f.display()))?;
                println!(
                    "{}  {}",
                    sha256_hex(&bytes),
                    f.file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default()
                );
            }
        }
    }
    Ok(())
}

fn sig_path(f: &Path) -> PathBuf {
    let mut s = f.as_os_str().to_owned();
    s.push(".sig");
    PathBuf::from(s)
}
