//! The HidraVPN background service, as a library so both its own binary and
//! the client command line can use the control channel.

pub mod checkout;
pub mod daemon;
pub mod install;
pub mod ipc;
pub mod passes;
pub mod paths;

use anyhow::Result;

/// A best-effort clean disconnect, run from synchronous code (the installer)
/// on its own small runtime. Errors are swallowed by the caller on purpose.
pub fn cli_down_blocking() -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let _ = ipc::call(ipc::Command::Down).await;
    });
    Ok(())
}
