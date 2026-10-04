//! What the WebClient scanner collects: the WebDAV pipe name, the NTSTATUS
//! values we branch on, the per-host [`Outcome`], and the [`classify`] that maps
//! one onto the other. Kept free of any SMB types so it unit-tests with no
//! Domain Controller (like LocalGroups-rs tests its NDR decoders).
//!
//! Ported from <https://github.com/g0h4n/IsWebClientRunning-rs> for issue #72.

/// SMB2 CREATE filename for the WebClient pipe (no leading separator; the tree
/// is already IPC$). Its presence is the whole signal: a host running the
/// WebClient (WebDAV) service registers this pipe, which makes it an ESC8 /
/// coercion relay candidate.
pub const PIPE_NAME: &str = "DAV RPC SERVICE";

/// Human-facing full path, used in logs.
pub const PIPE_NAME_DISPLAY: &str = r"\PIPE\DAV RPC SERVICE";

/// NTSTATUS values we care about when opening the pipe.
pub mod status {
    pub const SUCCESS: u32 = 0x0000_0000;
    pub const OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
    pub const OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
    pub const PIPE_NOT_AVAILABLE: u32 = 0xC000_00AC;
    pub const ACCESS_DENIED: u32 = 0xC000_0022;
    pub const BAD_NETWORK_NAME: u32 = 0xC000_00CC;
    pub const LOGON_FAILURE: u32 = 0xC000_006D;
}

/// Outcome of a single host probe, before it becomes a serialisable row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The `DAV RPC SERVICE` pipe opened: WebClient is running.
    Running,
    /// The pipe does not exist (STATUS_OBJECT_NAME_NOT_FOUND): service stopped.
    NotRunning,
    /// IPC$ or the pipe was refused (STATUS_ACCESS_DENIED and friends).
    AccessDenied(String),
    /// TCP / NEGOTIATE / SESSION_SETUP never completed (or timed out).
    Unreachable(String),
    /// Credentials were rejected.
    AuthFailed(String),
    /// Anything else, carried verbatim for the trace.
    Error(String),
}

impl Outcome {
    pub fn is_running(&self) -> bool {
        matches!(self, Outcome::Running)
    }

    /// Whether the probe produced a trustworthy running/not-running verdict.
    pub fn collected(&self) -> bool {
        matches!(self, Outcome::Running | Outcome::NotRunning)
    }

    pub fn failure_reason(&self) -> Option<String> {
        match self {
            Outcome::Running | Outcome::NotRunning => None,
            Outcome::AccessDenied(m)
            | Outcome::Unreachable(m)
            | Outcome::AuthFailed(m)
            | Outcome::Error(m) => Some(m.clone()),
        }
    }
}

/// Map the NTSTATUS returned by the pipe CREATE into an [`Outcome`].
/// Isolated from the network so it unit-tests with no Domain Controller.
pub fn classify(nt_status: u32) -> Outcome {
    match nt_status {
        status::SUCCESS => Outcome::Running,
        status::OBJECT_NAME_NOT_FOUND
        | status::OBJECT_PATH_NOT_FOUND
        | status::PIPE_NOT_AVAILABLE => Outcome::NotRunning,
        status::ACCESS_DENIED => Outcome::AccessDenied(format!(
            "CREATE {PIPE_NAME_DISPLAY} refused (0x{nt_status:08X})"
        )),
        status::BAD_NETWORK_NAME => {
            Outcome::Error(format!("IPC$ tree connect failed (0x{nt_status:08X})"))
        }
        status::LOGON_FAILURE => {
            Outcome::AuthFailed(format!("session setup rejected (0x{nt_status:08X})"))
        }
        other => Outcome::Error(format!("unexpected NTSTATUS 0x{other:08X}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_is_running() {
        assert_eq!(classify(status::SUCCESS), Outcome::Running);
        assert!(classify(status::SUCCESS).is_running());
    }

    #[test]
    fn missing_pipe_is_not_running() {
        assert_eq!(classify(status::OBJECT_NAME_NOT_FOUND), Outcome::NotRunning);
        assert_eq!(classify(status::OBJECT_PATH_NOT_FOUND), Outcome::NotRunning);
        assert_eq!(classify(status::PIPE_NOT_AVAILABLE), Outcome::NotRunning);
        assert!(classify(status::OBJECT_NAME_NOT_FOUND).collected());
    }

    #[test]
    fn denied_is_uncollected() {
        let o = classify(status::ACCESS_DENIED);
        assert!(matches!(o, Outcome::AccessDenied(_)));
        assert!(!o.collected());
        assert!(!o.is_running());
    }

    #[test]
    fn auth_and_network_map_through() {
        assert!(matches!(classify(status::LOGON_FAILURE), Outcome::AuthFailed(_)));
        assert!(matches!(classify(status::BAD_NETWORK_NAME), Outcome::Error(_)));
    }

    #[test]
    fn unknown_status_is_error() {
        assert!(matches!(classify(0xC000_0001), Outcome::Error(_)));
    }
}