//! Running as a real Windows service.
//!
//! The SCM starts the installed exe with `run`; that calls [`dispatch`],
//! which hands the thread to the SCM and has it call [`service_main`].
//! `service_main` tells the SCM it is starting, then running, runs the
//! daemon until a Stop or system Shutdown control comes, lets the daemon
//! put the network back, and tells the SCM it has stopped. The SCM reads
//! the network back on shutdown too, which a Scheduled Task — hard-ended —
//! never did.
//!
//! Run from a console instead (for debugging), the dispatcher cannot reach
//! an SCM and returns at once with `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`;
//! [`dispatch`] reports that as [`Dispatch::NotStartedByScm`] so the caller
//! runs the daemon in the foreground.

use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result};
use tokio::sync::Notify;
use windows::core::PWSTR;
use windows::Win32::Foundation::{
    ERROR_CALL_NOT_IMPLEMENTED, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, NO_ERROR,
};
use windows::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
    SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE, SERVICE_STOPPED,
    SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};

/// How the attempt to run as a service turned out.
pub(crate) enum Dispatch {
    /// The SCM started us: `service_main` ran and the service has stopped.
    Ran,
    /// No SCM to connect to — started from a console. Run in the foreground.
    NotStartedByScm,
}

/// Signalled by the control handler when the SCM asks the service to stop;
/// awaited by the daemon so it unwinds cleanly.
static STOP: OnceLock<Arc<Notify>> = OnceLock::new();

fn stop_signal() -> Arc<Notify> {
    STOP.get_or_init(|| Arc::new(Notify::new())).clone()
}

/// The handle `SetServiceStatus` needs, kept so the control handler (on an
/// SCM thread) and `service_main` can both report. A Windows handle is sound
/// to use from any thread.
struct StatusHandle(SERVICE_STATUS_HANDLE);
// SAFETY: a SERVICE_STATUS_HANDLE is a kernel handle, valid process-wide and
// safe to pass to SetServiceStatus from any thread.
unsafe impl Send for StatusHandle {}
unsafe impl Sync for StatusHandle {}

static STATUS: OnceLock<StatusHandle> = OnceLock::new();

/// Hands this thread to the SCM. Blocks for the whole life of the service
/// (the SCM calls [`service_main`] on it); returns when the service stops.
pub(crate) fn dispatch() -> Result<Dispatch> {
    let mut name: Vec<u16> = crate::install::SERVICE_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(name.as_mut_ptr()),
            lpServiceProc: Some(ffi_service_main),
        },
        // A zeroed entry ends the table.
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR::null(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: `table` is a valid, null-terminated service table that lives
    // past this call (StartServiceCtrlDispatcherW blocks until the service
    // stops, and `name` and `table` outlive it).
    let r = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
    match r {
        Ok(()) => Ok(Dispatch::Ran),
        Err(e) if e.code() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT.to_hresult() => {
            Ok(Dispatch::NotStartedByScm)
        }
        Err(e) => Err(e).context("the service control dispatcher"),
    }
}

/// What the SCM calls on the dispatcher thread. Thin: it defers to
/// `service_main`, which returns only when the service has stopped.
extern "system" fn ffi_service_main(_argc: u32, _argv: *mut PWSTR) {
    service_main();
}

fn service_main() {
    // Register the control handler first; without the status handle nothing
    // below can tell the SCM anything.
    let name: Vec<u16> = crate::install::SERVICE_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `name` is a valid null-terminated wide string for the call;
    // the handler is a plain function and takes no context.
    let handle = match unsafe {
        RegisterServiceCtrlHandlerExW(
            windows::core::PCWSTR(name.as_ptr()),
            Some(ffi_handler),
            None,
        )
    } {
        Ok(h) => h,
        // Nothing to report to without the handle; the SCM will time us out.
        Err(_) => return,
    };
    let _ = STATUS.set(StatusHandle(handle));

    report(SERVICE_START_PENDING, 0, 1, 15_000, 0);
    crate::init_logging();
    tracing::info!("HidraVPN service starting under the SCM");

    // Running: the SCM may now ask us to stop or tell us the machine is
    // shutting down. The daemon serves until the handler signals STOP.
    report(
        SERVICE_RUNNING,
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
        0,
        0,
        0,
    );
    let stop = stop_signal();
    let result = crate::run_daemon_until(async move { stop.notified().await });

    // Stopped. The handler already reported STOP_PENDING when the control
    // came; by here the daemon has put the network back. An error starting
    // or running it is reported as the service's exit code, which drives the
    // SCM's restart-on-failure.
    let exit = match &result {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!("the service stopped on an error: {e:#}");
            1
        }
    };
    report(SERVICE_STOPPED, 0, 0, 0, exit);
}

/// What the SCM calls (on its own thread) to control the service.
///
/// # Safety
/// Matches `LPHANDLER_FUNCTION_EX`; the pointers are the SCM's and unused.
unsafe extern "system" fn ffi_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut core::ffi::c_void,
    _context: *mut core::ffi::c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            // Tell the SCM we are on our way down, then let the daemon
            // unwind; `service_main` reports STOPPED when it has.
            report(SERVICE_STOP_PENDING, 0, 1, 15_000, 0);
            stop_signal().notify_one();
            NO_ERROR.0
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR.0,
        _ => ERROR_CALL_NOT_IMPLEMENTED.0,
    }
}

/// Tells the SCM the service's state. `checkpoint`/`wait_hint` only matter
/// while a change is pending (they say "still working, ask again in this
/// many ms"); `exit_code` only on STOPPED.
fn report(
    state: SERVICE_STATUS_CURRENT_STATE,
    controls: u32,
    checkpoint: u32,
    wait_hint: u32,
    exit_code: u32,
) {
    let Some(handle) = STATUS.get() else {
        return;
    };
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: controls,
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: checkpoint,
        dwWaitHint: wait_hint,
    };
    // SAFETY: `handle` is the status handle this process registered, and
    // `status` is a fully initialised SERVICE_STATUS borrowed for the call.
    unsafe {
        let _ = SetServiceStatus(handle.0, &status);
    }
}
