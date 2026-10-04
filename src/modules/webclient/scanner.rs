//! The WebDAV detection itself: on an already-authenticated IPC$ session, CREATE
//! the WebClient named pipe and read the NTSTATUS. The pipe's presence is the
//! whole signal; no DCE/RPC bind, no opnum, read-only (the CREATE only opens the
//! pipe). The connection + SESSION_SETUP live in `mod.rs` (shared SMB transport,
//! all three auth paths), exactly like `samr.rs` operates on a connected client
//! for the LocalGroups module.

use log::trace;
use smb2_client::{SmbClient, SmbError};

use crate::modules::webclient::types::{classify, status, Outcome, PIPE_NAME, PIPE_NAME_DISPLAY};

/// Probe the WebClient pipe on a connected IPC$ session.
///
/// Uses the raw `open_pipe` (not the `open_rpc_pipe` anyhow wrapper) so the
/// NTSTATUS survives for [`classify`]: `Ok` => running, `Status(code)` => the
/// reason, anything else => a transport-level error carried verbatim.
pub async fn probe(smb: &mut SmbClient, host: &str) -> Outcome {
    trace!("[{host}] CREATE {PIPE_NAME_DISPLAY}");
    match smb.open_pipe(PIPE_NAME).await {
        Ok(_file_id) => classify(status::SUCCESS),
        Err(SmbError::Status(code, _)) => classify(code),
        Err(other) => Outcome::Error(format!("open {PIPE_NAME_DISPLAY}: {other}")),
    }
}