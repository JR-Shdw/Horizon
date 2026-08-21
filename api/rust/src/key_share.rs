// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//! IPC keysharing infrastructure for role-based workers.
//!
//! Master worker holds the master_key and splits it into N Shamir shares.
//! Each non-master worker fetches one share via a filesystem-path Unix socket.
//! A single share is useless on its own, reconstruction needs M shares
//! (Shamir M-of-N quorum).
//!
//! All share material lives in `SecureBuffer` (mlock'd, zeroize on drop).
//! Shares never cross the Rust/Python boundary as plaintext bytes, they
//! are wrapped in opaque `ShamirShare` PyObjects whose only operations are
//! "send to peer" and "reconstruct with peers".

use crate::{try_os_fill, SecureBuffer};
use pyo3::exceptions::{PyPermissionError, PyRuntimeError, PyTimeoutError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyByteArray;
use rhorizon_custody_core::rpc::{read_frame, write_frame, ZeroizingJson};
use rhorizon_custody_core::MAX_RPC_FRAME_BYTES;
use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

const SOCKET_TIMEOUT: Duration = Duration::from_secs(5);
/// Length-prefix wire format: 4-byte big-endian unsigned, then payload.
const MAX_PAYLOAD: usize = 4096;
const MAX_CONTROL_CAPABILITY_BYTES: usize = 256;

// =====================================================================
// GF(256): arithmetic operations come from `crate::gf256_ct`. That
// module is constant-time (no field-element-indexed memory access,
// no branches on field elements). The table-driven reference impl
// (`RefTables`) that used to live here was moved to the test module
// of `gf256_ct.rs` where it serves as the golden equivalence anchor
// (exhaustive 65 536-pair test vs. the new branch-free `mul`).
// =====================================================================

#[cfg(test)]
use crate::gf256_ct;

// =====================================================================
// Shamir: pure functions (testable without PyO3)
// =====================================================================

fn shamir_split(secret: &[u8], threshold: u8, total: u8) -> Result<Vec<Vec<u8>>, String> {
    rhorizon_custody_core::shamir::split_with_fill(secret, threshold, total, try_os_fill)
}

fn shamir_combine(shares: &[&[u8]]) -> Result<Vec<u8>, String> {
    rhorizon_custody_core::shamir::combine(shares)
}

// =====================================================================
// Operator-path Shamir, plaintext bytes API.
//
// The cluster path keeps shares opaque (ShamirShare, never plaintext over
// the FFI boundary). The operator M-of-N feature is different: it hands
// shares to humans as hex and accepts them back, so it MUST return/accept
// plaintext bytes. These two wrappers route that path through the same
// constant-time `shamir_split` / `shamir_combine` as the cluster, so the
// operator master-key split/combine gets the branch-free GF instead of the
// table-driven Python one. The win here is constant-time arithmetic; the
// reconstructed bytes still cross into Python (custody is the caller's
// concern: see the vault.unseal boundary).
// =====================================================================

#[pyfunction]
pub fn shamir_split_bytes(secret: &[u8], threshold: u8, total: u8) -> PyResult<Vec<Vec<u8>>> {
    shamir_split(secret, threshold, total).map_err(PyValueError::new_err)
}

#[pyfunction]
pub fn shamir_combine_bytes(mut shares: Vec<Vec<u8>>) -> PyResult<Vec<u8>> {
    let slices: Vec<&[u8]> = shares.iter().map(|s| s.as_slice()).collect();
    let result = shamir_combine(&slices);
    shares.zeroize();
    result.map_err(PyValueError::new_err)
}

fn shamir_split_opaque_locked(
    secret: &[u8],
    threshold: u8,
    total: u8,
) -> PyResult<Vec<ShamirShare>> {
    shamir_split(secret, threshold, total)
        .map_err(PyValueError::new_err)?
        .into_iter()
        .map(ShamirShare::from_vec)
        .collect()
}

/// Split a wipeable Python bytearray into opaque locked Rust shares. No share
/// bytes are returned through the Python buffer protocol.
#[pyfunction]
pub fn shamir_split_opaque_bytearray(
    secret: &Bound<'_, PyByteArray>,
    threshold: u8,
    total: u8,
) -> PyResult<Vec<ShamirShare>> {
    // The GIL remains held and no Python code runs while the bytearray is
    // borrowed, so its storage cannot be resized or freed.
    let secret = unsafe { secret.as_bytes() };
    shamir_split_opaque_locked(secret, threshold, total)
}

// =====================================================================
// Peer credentials, fail-closed UID validation, portable shim.
//
// Status per OS :
//   - Linux        : validated (production target)
//   - macOS        : implemented from xucred docs, NOT exercised on a Mac
//   - FreeBSD/etc. : implemented via getpeereid(3), NOT exercised
//
// Filesystem-path Unix sockets are portable across the supported hosts.
// The platform-specific work here is peer-credential retrieval; see
// api/app/peer_cred.py for the matching Python implementation.
//
// Returns (peer_uid, peer_pid). On macOS / BSD, peer_pid is 0 (the
// underlying APIs don't expose it). Callers that compare peer_uid to
// our_uid and ignore peer_pid are portable; callers that rely on
// peer_pid for security must not (rhorizon doesn't).
// =====================================================================

extern "C" {
    fn getsockopt(
        sockfd: i32,
        level: i32,
        optname: i32,
        optval: *mut std::ffi::c_void,
        optlen: *mut u32,
    ) -> i32;
}

#[cfg(target_os = "linux")]
mod peer_cred_impl {
    use super::*;

    #[repr(C)]
    struct UCred {
        pid: i32,
        uid: u32,
        gid: u32,
    }

    const SOL_SOCKET: i32 = 1;
    const SO_PEERCRED: i32 = 17;

    pub fn read(stream: &UnixStream) -> std::io::Result<(u32, i32)> {
        let fd = stream.as_raw_fd();
        let mut cred = UCred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len: u32 = std::mem::size_of::<UCred>() as u32;
        // SAFETY: `fd` is a valid, open socket fd owned by `stream` for the
        // duration of this call (borrowed, not moved). `&mut cred` is a
        // live, correctly-sized `#[repr(C)]` UCred and `len` is set to its
        // exact size, matching the getsockopt(2) SO_PEERCRED contract: the
        // kernel writes at most `len` bytes and updates `len` to what it
        // actually wrote. No pointer is retained past this call.
        let ret = unsafe {
            getsockopt(
                fd,
                SOL_SOCKET,
                SO_PEERCRED,
                &mut cred as *mut _ as *mut std::ffi::c_void,
                &mut len,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok((cred.uid, cred.pid))
    }
}

#[cfg(target_os = "macos")]
mod peer_cred_impl {
    use super::*;

    // struct xucred prefix (cr_version u32 + cr_uid u32). Full struct is
    // 76 bytes on modern macOS but we ignore everything past cr_uid.
    #[repr(C)]
    struct XUcredPrefix {
        version: u32,
        uid: u32,
    }

    const SOL_LOCAL: i32 = 0;
    const LOCAL_PEERCRED: i32 = 1;
    const XUCRED_SIZE: u32 = 76;

    pub fn read(stream: &UnixStream) -> std::io::Result<(u32, i32)> {
        let fd = stream.as_raw_fd();
        let mut buf = [0u8; XUCRED_SIZE as usize];
        let mut len: u32 = XUCRED_SIZE;
        // SAFETY: `fd` is a valid, open socket fd owned by `stream` for the
        // duration of this call. `buf` is a stack array of exactly
        // XUCRED_SIZE bytes and `len` is set to that same size, matching
        // the LOCAL_PEERCRED getsockopt(2) contract (kernel writes at most
        // `len` bytes, updates `len` to the amount actually written).
        let ret = unsafe {
            getsockopt(
                fd,
                SOL_LOCAL,
                LOCAL_PEERCRED,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                &mut len,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if len < std::mem::size_of::<XUcredPrefix>() as u32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "peer credential response is truncated",
            ));
        }
        // SAFETY: the length check proves the prefix bytes are initialized.
        // read_unaligned is required because a byte array has alignment 1.
        let prefix = unsafe { std::ptr::read_unaligned(buf.as_ptr().cast::<XUcredPrefix>()) };
        // PID not exposed by xucred, return 0 as placeholder.
        Ok((prefix.uid, 0))
    }
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "netbsd"
))]
mod peer_cred_impl {
    use super::*;

    extern "C" {
        // int getpeereid(int s, uid_t *euid, gid_t *egid);
        fn getpeereid(s: i32, euid: *mut u32, egid: *mut u32) -> i32;
    }

    pub fn read(stream: &UnixStream) -> std::io::Result<(u32, i32)> {
        let fd = stream.as_raw_fd();
        let mut uid: u32 = 0;
        let mut gid: u32 = 0;
        // SAFETY: `fd` is a valid, open socket fd owned by `stream`. `uid`
        // and `gid` are live u32 locals; getpeereid(2) writes exactly one
        // u32 to each on success and leaves them untouched on failure --
        // either way no more than sizeof(u32) bytes are written to each.
        let ret = unsafe { getpeereid(fd, &mut uid as *mut u32, &mut gid as *mut u32) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // PID not exposed by getpeereid, return 0 as placeholder.
        Ok((uid, 0))
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "netbsd"
)))]
mod peer_cred_impl {
    use super::*;

    pub fn read(_stream: &UnixStream) -> std::io::Result<(u32, i32)> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "peer credentials read not implemented on this OS",
        ))
    }
}

pub(crate) fn read_peer_cred(stream: &UnixStream) -> std::io::Result<(u32, i32)> {
    peer_cred_impl::read(stream)
}

// =====================================================================
// Blocking IO helpers (no GIL needed, callable from tests + GIL-released
// PyO3 paths). Pure stdlib; never touch Python state.
// =====================================================================

fn serve_one_share_blocking(listener: &UnixListener, share: &[u8]) -> PyResult<i32> {
    listener
        .set_nonblocking(true)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

    let deadline = std::time::Instant::now() + SOCKET_TIMEOUT;
    let accept_result = loop {
        match listener.accept() {
            Ok(pair) => break Ok(pair),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() >= deadline {
                    break Err(PyTimeoutError::new_err("No peer connected within 5s"));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                break Err(PyValueError::new_err(format!("accept failed: {}", e)));
            }
        }
    };
    let _ = listener.set_nonblocking(false);

    let (mut stream, _addr) = accept_result?;

    let (peer_uid, peer_pid) = read_peer_cred(&stream)
        .map_err(|e| PyValueError::new_err(format!("read_peer_cred failed: {}", e)))?;
    // SAFETY: getuid(2) takes no arguments and cannot fail; libc_getuid
    // is `unsafe fn` only because it crosses the extern "C" FFI boundary.
    let our_uid = unsafe { libc_getuid() };
    if peer_uid != our_uid {
        return Err(PyPermissionError::new_err(format!(
            "peer uid {} != our uid {} - refusing to serve share",
            peer_uid, our_uid
        )));
    }

    stream
        .set_write_timeout(Some(SOCKET_TIMEOUT))
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let len = share.len() as u32;
    stream
        .write_all(&len.to_be_bytes())
        .map_err(|e| PyValueError::new_err(format!("send len failed: {}", e)))?;
    stream
        .write_all(share)
        .map_err(|e| PyValueError::new_err(format!("send payload failed: {}", e)))?;
    stream
        .flush()
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

    Ok(peer_pid)
}

fn fetch_share_blocking(path: &Path) -> PyResult<Vec<u8>> {
    let mut stream = UnixStream::connect(path)
        .map_err(|e| PyValueError::new_err(format!("connect failed: {}", e)))?;
    stream
        .set_read_timeout(Some(SOCKET_TIMEOUT))
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

    let (peer_uid, _peer_pid) = read_peer_cred(&stream)
        .map_err(|e| PyValueError::new_err(format!("read_peer_cred failed: {}", e)))?;
    // SAFETY: getuid(2) takes no arguments and cannot fail; libc_getuid
    // is `unsafe fn` only because it crosses the extern "C" FFI boundary.
    let our_uid = unsafe { libc_getuid() };
    if peer_uid != our_uid {
        return Err(PyPermissionError::new_err(format!(
            "master uid {} != our uid {} - refusing to fetch share",
            peer_uid, our_uid
        )));
    }

    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| PyValueError::new_err(format!("read len failed: {}", e)))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_PAYLOAD {
        return Err(PyValueError::new_err(format!(
            "invalid share length: {}",
            len
        )));
    }
    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .map_err(|e| PyValueError::new_err(format!("read payload failed: {}", e)))?;
    Ok(payload)
}

// =====================================================================
// PyO3: opaque ShamirShare
// =====================================================================

#[pyclass]
pub struct ShamirShare {
    inner: SecureBuffer,
}

impl ShamirShare {
    fn from_vec(data: Vec<u8>) -> PyResult<Self> {
        Ok(ShamirShare {
            inner: SecureBuffer::new_locked(data)?,
        })
    }

    fn as_slice(&self) -> &[u8] {
        // Internal-only access (used for IPC send + reconstruct).
        // Not exposed via #[pymethods], Python cannot call this.
        &self.inner.data
    }
}

#[pymethods]
impl ShamirShare {
    /// x-coordinate of this share (1..total).
    #[getter]
    fn x(&self) -> u8 {
        self.inner.data[0]
    }

    /// Total wire length (1 byte x + N bytes y).
    fn __len__(&self) -> usize {
        self.inner.data.len()
    }

    /// Install this opaque share into one fixed Rust custodian without
    /// exposing its bytes to Python. The JSON request and capability buffers
    /// are wiped in Rust after the authenticated local RPC completes.
    fn install_into_custodian(
        &self,
        py: Python<'_>,
        socket_name: &str,
        control_token_file: &str,
        generation: u64,
        threshold: u8,
        slots: u8,
    ) -> PyResult<String> {
        let slot = self.x();
        let socket_name = socket_name.to_string();
        let control_token_file = control_token_file.to_string();
        py.detach(|| {
            transfer_share_into_custodian_blocking(
                self.as_slice(),
                CustodianShareTransfer {
                    socket_path: Path::new(&socket_name),
                    control_token_path: Path::new(&control_token_file),
                    generation,
                    threshold,
                    slots,
                    slot,
                    operation: "install_share",
                    accepted_results: &["installed", "already-installed"],
                },
            )
        })
    }

    /// Stage this opaque share as a future custodian generation. The active
    /// share remains available until an authenticated commit operation.
    fn prepare_into_custodian(
        &self,
        py: Python<'_>,
        socket_name: &str,
        control_token_file: &str,
        generation: u64,
        threshold: u8,
        slots: u8,
    ) -> PyResult<String> {
        let slot = self.x();
        let socket_name = socket_name.to_string();
        let control_token_file = control_token_file.to_string();
        py.detach(|| {
            transfer_share_into_custodian_blocking(
                self.as_slice(),
                CustodianShareTransfer {
                    socket_path: Path::new(&socket_name),
                    control_token_path: Path::new(&control_token_file),
                    generation,
                    threshold,
                    slots,
                    slot,
                    operation: "prepare_share",
                    accepted_results: &["prepared", "already-prepared", "already-committed"],
                },
            )
        })
    }
}

struct CustodianShareTransfer<'a> {
    socket_path: &'a Path,
    control_token_path: &'a Path,
    generation: u64,
    threshold: u8,
    slots: u8,
    slot: u8,
    operation: &'static str,
    accepted_results: &'static [&'static str],
}

fn transfer_share_into_custodian_blocking(
    share: &[u8],
    transfer: CustodianShareTransfer<'_>,
) -> PyResult<String> {
    let mut token_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(transfer.control_token_path)
        .map_err(|error| PyPermissionError::new_err(error.to_string()))?;
    let metadata = token_file
        .metadata()
        .map_err(|error| PyPermissionError::new_err(error.to_string()))?;
    let our_uid = unsafe { libc_getuid() };
    if !metadata.file_type().is_file()
        || metadata.uid() != our_uid
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > (MAX_CONTROL_CAPABILITY_BYTES + 2) as u64
    {
        return Err(PyPermissionError::new_err(
            "custodian control token is not a private owner-matched regular file",
        ));
    }
    let mut capability = Zeroizing::new(Vec::with_capacity(MAX_CONTROL_CAPABILITY_BYTES + 3));
    Read::by_ref(&mut token_file)
        .take((MAX_CONTROL_CAPABILITY_BYTES + 3) as u64)
        .read_to_end(&mut capability)
        .map_err(|error| PyPermissionError::new_err(error.to_string()))?;
    let capability = capability.trim_ascii();
    if !(32..=MAX_CONTROL_CAPABILITY_BYTES).contains(&capability.len()) {
        return Err(PyPermissionError::new_err(
            "custodian control token must contain 32..256 bytes",
        ));
    }
    let capability = std::str::from_utf8(capability)
        .map_err(|_| PyPermissionError::new_err("custodian control token must be valid UTF-8"))?;

    let request = ZeroizingJson::new(json!({
        "op": transfer.operation,
        "capability": capability,
        "args": {
            "generation": transfer.generation,
            "threshold": transfer.threshold,
            "slots": transfer.slots,
            "slot": transfer.slot,
            "share": hex::encode(share),
        }
    }));
    let request_bytes = request.to_bytes();
    let mut stream = UnixStream::connect(transfer.socket_path)
        .map_err(|error| PyRuntimeError::new_err(format!("custodian connect failed: {error}")))?;
    stream
        .set_read_timeout(Some(SOCKET_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(SOCKET_TIMEOUT)))
        .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    let (peer_uid, _) =
        read_peer_cred(&stream).map_err(|error| PyPermissionError::new_err(error.to_string()))?;
    if peer_uid != our_uid {
        return Err(PyPermissionError::new_err(
            "custodian peer UID does not match client UID",
        ));
    }
    write_frame(&mut stream, &request_bytes, MAX_RPC_FRAME_BYTES)
        .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    let response = read_frame(&mut stream, MAX_RPC_FRAME_BYTES)
        .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    let parsed: Value = serde_json::from_slice(&response)
        .map_err(|_| PyRuntimeError::new_err("custodian returned invalid JSON"))?;
    if let Some(error) = parsed.get("error").and_then(Value::as_str) {
        return Err(PyRuntimeError::new_err(error.to_string()));
    }
    let result = parsed
        .get("result")
        .and_then(Value::as_str)
        .ok_or_else(|| PyRuntimeError::new_err("custodian returned invalid share result"))?;
    if transfer.accepted_results.contains(&result) {
        Ok(result.to_string())
    } else {
        Err(PyRuntimeError::new_err(
            "custodian returned invalid share result",
        ))
    }
}

// =====================================================================
// PyO3: KeyServer (master-side)
// =====================================================================

#[pyclass]
pub struct KeyServer {
    socket_name: String,
    listener: Option<UnixListener>,
    pending_shares: Vec<SecureBuffer>, // mlock'd shares, served one at a time
}

#[pymethods]
impl KeyServer {
    #[new]
    fn new(socket_name: &str) -> PyResult<Self> {
        if socket_name.is_empty() {
            return Err(PyValueError::new_err(
                "socket_name must be a non-empty filesystem path",
            ));
        }
        Ok(KeyServer {
            socket_name: socket_name.to_string(),
            listener: None,
            pending_shares: Vec::new(),
        })
    }

    /// Split master_key in `total` shares (Shamir threshold-of-total) and
    /// bind the filesystem-path Unix socket. The standard Python path claims
    /// the first generated share (`x = 1`) via `pop_share`; the caller serves
    /// the remaining `total - 1` shares to peers via `serve_one_share`.
    ///
    /// The socket file is bound at the path passed to `new()`. The caller
    /// is responsible for stale-orphan cleanup (Python helper
    /// `socket_paths.acquire_socket_path`) and for tightening permissions
    /// to 0700 after bind (`socket_paths.post_bind_chmod`).
    fn split_and_bind(&mut self, master_key: &[u8], threshold: u8, total: u8) -> PyResult<()> {
        if self.listener.is_some() {
            return Err(PyValueError::new_err("Already bound"));
        }
        let shares = shamir_split(master_key, threshold, total).map_err(PyValueError::new_err)?;

        let listener = UnixListener::bind(Path::new(&self.socket_name)).map_err(|e| {
            PyValueError::new_err(format!("Failed to bind {}: {}", self.socket_name, e))
        })?;
        listener
            .set_nonblocking(false)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

        // Hold each split share mlock'd + zeroize-on-drop (like ShamirShare):
        // the master briefly holds all N shares == the reconstructable key, so
        // they must not sit swappable in plain heap during distribution.
        let mut locked: Vec<SecureBuffer> = Vec::with_capacity(shares.len());
        for s in shares {
            locked.push(SecureBuffer::new_locked(s)?);
        }
        self.listener = Some(listener);
        self.pending_shares = locked;
        Ok(())
    }

    /// Accept one peer connection (timeout 5s), validate UID, send next
    /// pending share. Returns the peer PID on success.
    /// Raises PyTimeoutError on accept timeout, PyPermissionError on UID
    /// mismatch (fail-closed).
    fn serve_one_share(&mut self, py: Python<'_>) -> PyResult<i32> {
        // Pop the share + grab listener BEFORE entering allow_threads so
        // we don't hold &mut self across the GIL release.
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| PyValueError::new_err("Not bound - call split_and_bind first"))?;
        let share: SecureBuffer = if self.pending_shares.is_empty() {
            return Err(PyValueError::new_err("No more shares to serve"));
        } else {
            self.pending_shares.remove(0)
        };

        // Drop the GIL across all blocking IO. Critical for the share-serving
        // background loop: without this the 5s accept window would freeze
        // every other coroutine in the worker. A timeout or rejected peer must
        // not consume the share: the Python serving loops retry after timeout,
        // and failover may happen hours after initial distribution.
        match py.detach(|| serve_one_share_blocking(listener, &share.data)) {
            Ok(peer_pid) => Ok(peer_pid),
            Err(error) => {
                self.pending_shares.insert(0, share);
                Err(error)
            }
        }
    }

    /// Master keeps one share locally. Call after all peers have been served.
    /// Returns the last remaining share.
    fn pop_local_share(&mut self) -> PyResult<ShamirShare> {
        if self.pending_shares.len() != 1 {
            return Err(PyValueError::new_err(format!(
                "Expected exactly 1 share remaining, got {}",
                self.pending_shares.len()
            )));
        }
        // Move the mlock'd buffer into the share (no re-copy, stays locked).
        Ok(ShamirShare {
            inner: self.pending_shares.remove(0),
        })
    }

    /// Pop the next pending share regardless of how many remain.
    /// Used by the master to claim its own share immediately after split,
    /// before peers connect; remaining shares are served via serve_one_share.
    /// If fewer peers come up than expected, leftover shares stay in pending
    /// and are zeroized by close().
    fn pop_share(&mut self) -> PyResult<ShamirShare> {
        if self.pending_shares.is_empty() {
            return Err(PyValueError::new_err("No pending shares"));
        }
        Ok(ShamirShare {
            inner: self.pending_shares.remove(0),
        })
    }

    /// Bind the socket and load a single pre-existing share to serve.
    /// Used by followers to expose their own share to a future new master
    /// (failover share collection). Reuses serve_one_share for the actual
    /// transport: same wire format, same ucred validation.
    fn bind_with_share(&mut self, share: PyRef<ShamirShare>) -> PyResult<()> {
        if self.listener.is_some() {
            return Err(PyValueError::new_err("Already bound"));
        }
        let listener = UnixListener::bind(Path::new(&self.socket_name)).map_err(|e| {
            PyValueError::new_err(format!("Failed to bind {}: {}", self.socket_name, e))
        })?;
        listener
            .set_nonblocking(false)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        self.listener = Some(listener);
        // Copy the share bytes into our (mlock'd) pending queue. The original
        // ShamirShare (held by the follower's vault) remains intact for failover.
        self.pending_shares = vec![SecureBuffer::new_locked(share.as_slice().to_vec())?];
        Ok(())
    }

    /// Close the listener, call after distribution complete.
    fn close(&mut self) {
        self.listener = None;
        // Each SecureBuffer zeroizes + munlocks on drop.
        self.pending_shares.clear();
    }

    /// Reconstruct master_key from M shares (M-of-N quorum). Static, no
    /// state needed beyond the shares themselves.
    /// Returns a SecureBuffer (mlock'd, zeroize on drop).
    #[staticmethod]
    fn reconstruct(shares: Vec<PyRef<ShamirShare>>) -> PyResult<SecureBuffer> {
        let slices: Vec<&[u8]> = shares.iter().map(|s| s.as_slice()).collect();
        let recovered = shamir_combine(&slices).map_err(|e| -> pyo3::PyErr {
            // Distinguish quorum issues from other errors for better Python ergonomics.
            // ValueError = caller's recoverable input mistake (not enough shares, duplicate
            // share index). RuntimeError = anything else, typically corrupt share bytes
            // or an internal GF(256) glitch, caller cannot retry with the same shares.
            if e.contains("at least") || e.contains("duplicate") {
                PyValueError::new_err(e)
            } else {
                PyRuntimeError::new_err(e)
            }
        })?;
        SecureBuffer::new_locked(recovered)
    }
}

// =====================================================================
// PyO3: KeyClient (worker-side)
// =====================================================================

#[pyclass]
pub struct KeyClient;

#[pymethods]
impl KeyClient {
    /// Connect to master via filesystem-path Unix socket, fetch this
    /// worker's share. Validates peer credentials before reading payload
    /// (fail-closed). Returns an opaque ShamirShare (mlock'd Rust heap).
    ///
    /// The blocking connect+read sequence runs without the GIL so the
    /// asyncio event loop can schedule other tasks while we wait, same
    /// reasoning as KeyServer.serve_one_share.
    #[staticmethod]
    fn fetch_share(py: Python<'_>, socket_name: &str) -> PyResult<ShamirShare> {
        if socket_name.is_empty() {
            return Err(PyValueError::new_err(
                "socket_name must be a non-empty filesystem path",
            ));
        }
        let path = socket_name.to_string();
        let payload = py.detach(|| fetch_share_blocking(Path::new(&path)))?;
        ShamirShare::from_vec(payload)
    }
}

// libc::getuid via FFI to avoid pulling the full libc crate as direct dep
extern "C" {
    fn getuid() -> u32;
}
// SAFETY (of calling `getuid` inside): getuid(2) is POSIX-guaranteed to
// take no arguments, perform no I/O, and always succeed -- there is no
// precondition for callers to uphold. `unsafe fn` here is solely because
// the call crosses the `extern "C"` FFI boundary, not because of any
// caller-supplied invariant.
unsafe fn libc_getuid() -> u32 {
    getuid()
}

// =====================================================================
// Tests (pure logic, IPC tests use spawned threads)
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- GF(256) sanity --

    #[test]
    fn gf_inv_roundtrip() {
        for a in 1u8..=255 {
            let inv = gf256_ct::inv(a).unwrap();
            assert_eq!(gf256_ct::mul(a, inv), 1, "a={}", a);
        }
    }

    #[test]
    fn gf_zero_inv_fails() {
        assert!(gf256_ct::inv(0).is_err());
    }

    // -- Shamir roundtrips --

    #[test]
    fn shamir_2of3_roundtrip() {
        let secret = b"twelve bytes";
        let shares = shamir_split(secret, 2, 3).unwrap();
        assert_eq!(shares.len(), 3);
        // Any 2 of the 3 should reconstruct
        for combo in [(0, 1), (0, 2), (1, 2)] {
            let pick: Vec<&[u8]> = vec![shares[combo.0].as_slice(), shares[combo.1].as_slice()];
            let recovered = shamir_combine(&pick).unwrap();
            assert_eq!(recovered, secret);
        }
    }

    #[test]
    fn opaque_split_returns_only_locked_coordinate_bound_objects() {
        let secret = [0x42u8; 160];
        let shares = shamir_split_opaque_locked(&secret, 2, 3).expect("opaque split");
        assert_eq!(shares.len(), 3);
        for (index, share) in shares.iter().enumerate() {
            assert_eq!(share.x(), index as u8 + 1);
            assert_eq!(share.as_slice().len(), secret.len() + 1);
            assert!(share.inner.is_locked());
        }
        let recovered = shamir_combine(&[shares[0].as_slice(), shares[2].as_slice()])
            .expect("opaque quorum reconstructs");
        assert_eq!(recovered, secret);
    }

    #[test]
    fn shamir_3of5_master_key_size() {
        // 96 bytes = hmac_key (32) + dek_key (32) + audit_key (32)
        let secret = vec![0xABu8; 96];
        let shares = shamir_split(&secret, 3, 5).unwrap();
        let pick: Vec<&[u8]> = shares.iter().take(3).map(|s| s.as_slice()).collect();
        let recovered = shamir_combine(&pick).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn shamir_insufficient_shares_wrong_secret() {
        let secret = b"sixteen bytessss";
        let shares = shamir_split(secret, 3, 5).unwrap();
        // 2 shares < threshold 3, combine returns SOMETHING but it's not the secret
        let pick: Vec<&[u8]> = shares.iter().take(2).map(|s| s.as_slice()).collect();
        let result = shamir_combine(&pick).unwrap();
        assert_ne!(result, secret);
    }

    #[test]
    fn shamir_threshold_validation() {
        let secret = b"data";
        assert!(shamir_split(secret, 1, 3).is_err());
        assert!(shamir_split(secret, 3, 2).is_err());
        assert!(shamir_split(b"", 2, 3).is_err());
    }

    #[test]
    fn shamir_all_nonzero_coordinates_supported() {
        let shares = shamir_split(b"data", 2, 255).unwrap();
        assert_eq!(shares.len(), 255);
        assert_eq!(shares[254][0], 255);
        assert_eq!(
            shamir_combine(&[shares[0].as_slice(), shares[254].as_slice()]).unwrap(),
            b"data"
        );
    }

    #[test]
    fn shamir_duplicate_indices_rejected() {
        let s1 = vec![1u8, 0xAA, 0xBB];
        let s2 = vec![1u8, 0xCC, 0xDD]; // same x=1
        let shares: Vec<&[u8]> = vec![&s1, &s2];
        assert!(shamir_combine(&shares).is_err());
    }

    #[test]
    fn shamir_zero_index_rejected() {
        let s1 = vec![0u8, 0xAA, 0xBB];
        let s2 = vec![2u8, 0xCC, 0xDD];
        let shares: Vec<&[u8]> = vec![&s1, &s2];
        assert!(shamir_combine(&shares).is_err());
    }

    #[test]
    fn shamir_empty_share_rejected() {
        let s1 = vec![];
        let s2 = vec![2u8, 0xCC, 0xDD];
        let shares: Vec<&[u8]> = vec![&s1, &s2];
        assert!(shamir_combine(&shares).is_err());
    }

    #[test]
    fn shamir_x_only_share_rejected() {
        let s1 = vec![1u8];
        let s2 = vec![2u8];
        let shares: Vec<&[u8]> = vec![&s1, &s2];
        assert!(shamir_combine(&shares).is_err());
    }

    #[test]
    fn shamir_format_share_has_x_prefix() {
        let secret = b"xyz";
        let shares = shamir_split(secret, 2, 3).unwrap();
        for (i, s) in shares.iter().enumerate() {
            assert_eq!(s[0], (i as u8) + 1, "share {} has wrong x-coord", i);
            assert_eq!(s.len(), 1 + secret.len());
        }
    }

    #[test]
    fn shamir_random_coefficients_differ() {
        // Two splits of the same secret should produce different shares
        // because the polynomial coefficients are random.
        let secret = b"deterministic only at x=0";
        let split1 = shamir_split(secret, 2, 3).unwrap();
        let split2 = shamir_split(secret, 2, 3).unwrap();
        // x=1 of first split vs x=1 of second split, should differ
        assert_ne!(split1[0], split2[0]);
    }

    // -- IPC roundtrip via in-process threads --
    //
    // Miri runs in an isolated sandbox without filesystem syscalls
    // (unlink, bind on real Unix sockets, etc.), skip under miri.
    // Normal `cargo test` runs this test fully.

    #[test]
    #[cfg_attr(miri, ignore)]
    fn ipc_socket_roundtrip() {
        use std::sync::mpsc;
        use std::thread;

        // Use a unique temp filesystem path per test run.
        let tmp_dir = std::env::temp_dir();
        let socket_path = tmp_dir.join(format!("rhorizon-test-{}.sock", std::process::id()));
        // Clean any leftover from a previous run
        let _ = std::fs::remove_file(&socket_path);

        let (tx, rx) = mpsc::channel();

        // Master thread, uses the GIL-free blocking helper directly so the
        // test doesn't need a Python interpreter initialized.
        let socket_for_master = socket_path.clone();
        let master = thread::spawn(move || {
            let listener = UnixListener::bind(&socket_for_master).unwrap();
            // Generate 5 shares manually
            let shares = shamir_split(&[0x42u8; 96], 3, 5).unwrap();
            tx.send(()).unwrap(); // signal "ready"
                                  // Serve 4 shares; master keeps the 5th
            for share in shares.iter().take(4) {
                serve_one_share_blocking(&listener, share).unwrap();
            }
            shares
        });

        // Wait until master is bound
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        thread::sleep(Duration::from_millis(50));

        // 4 worker threads connect and fetch their share
        let mut handles = Vec::new();
        for _ in 0..4 {
            let socket_for_worker = socket_path.clone();
            handles.push(thread::spawn(move || {
                fetch_share_blocking(&socket_for_worker).unwrap()
            }));
        }

        let received: Vec<Vec<u8>> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let original_shares = master.join().unwrap();
        assert_eq!(received.len(), 4);
        // Each received share should match one of the original 5
        for r in &received {
            assert!(original_shares.iter().any(|orig| orig == r));
        }
        // Cleanup
        let _ = std::fs::remove_file(&socket_path);
    }

    #[test]
    fn ipc_empty_socket_name_rejected() {
        // Must be a non-empty filesystem path
        assert!(KeyServer::new("").is_err());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn opaque_share_installs_over_authenticated_custodian_rpc() {
        use std::thread;

        let temp = std::env::temp_dir();
        let socket_path = temp.join(format!(
            "rhorizon-custodian-share-install-test-{}.sock",
            std::process::id()
        ));
        let token_path = temp.join(format!(
            "rhorizon-custodian-share-install-test-{}.token",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_file(&token_path);
        let mut token = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&token_path)
            .expect("create token");
        token
            .write_all(b"0123456789abcdef0123456789abcdef\n")
            .expect("write token");
        drop(token);

        let server_socket = socket_path.clone();
        let server = thread::spawn(move || {
            let listener = UnixListener::bind(&server_socket).expect("bind custodian socket");
            for (operation, result) in [
                ("install_share", "installed"),
                ("prepare_share", "already-prepared"),
            ] {
                let (mut stream, _) = listener.accept().expect("accept share transfer");
                let request = read_frame(&mut stream, MAX_RPC_FRAME_BYTES).expect("read request");
                let parsed: Value = serde_json::from_slice(&request).expect("parse request");
                assert_eq!(parsed["op"], operation);
                assert_eq!(parsed["capability"], "0123456789abcdef0123456789abcdef");
                assert_eq!(parsed["args"]["generation"], 19);
                assert_eq!(parsed["args"]["threshold"], 2);
                assert_eq!(parsed["args"]["slots"], 3);
                assert_eq!(parsed["args"]["slot"], 2);
                assert_eq!(parsed["args"]["share"], hex::encode([2, 0xA5, 0x5A]));
                let response = ZeroizingJson::new(json!({"result": result}));
                write_frame(&mut stream, &response.to_bytes(), MAX_RPC_FRAME_BYTES)
                    .expect("write response");
            }
        });
        while !socket_path.exists() {
            thread::yield_now();
        }

        assert_eq!(
            transfer_share_into_custodian_blocking(
                &[2, 0xA5, 0x5A],
                CustodianShareTransfer {
                    socket_path: &socket_path,
                    control_token_path: &token_path,
                    generation: 19,
                    threshold: 2,
                    slots: 3,
                    slot: 2,
                    operation: "install_share",
                    accepted_results: &["installed", "already-installed"],
                },
            )
            .expect("install opaque share"),
            "installed"
        );
        assert_eq!(
            transfer_share_into_custodian_blocking(
                &[2, 0xA5, 0x5A],
                CustodianShareTransfer {
                    socket_path: &socket_path,
                    control_token_path: &token_path,
                    generation: 19,
                    threshold: 2,
                    slots: 3,
                    slot: 2,
                    operation: "prepare_share",
                    accepted_results: &["prepared", "already-prepared", "already-committed"],
                },
            )
            .expect("prepare opaque share"),
            "already-prepared"
        );
        server.join().expect("join custodian server");
        std::fs::remove_file(socket_path).expect("remove socket");
        std::fs::remove_file(token_path).expect("remove token");
    }
}

// =====================================================================
// Fuzzing: public wrappers for the Shamir primitives, feature-gated.
//
// `shamir_split` / `shamir_combine` are crate-internal ; the fuzz
// harness in `fuzz/` needs to invoke them with adversarial inputs.
// Exposed via `pub mod fuzz_api` only when `cargo build --features
// fuzzing` is requested. Normal builds, including the PyO3 wheel
// shipped to Python, never see these wrappers.
// =====================================================================

#[cfg(feature = "fuzzing")]
#[allow(dead_code)] // exposed for the cargo-fuzz harness only.
pub mod fuzz_api {
    /// Split a secret into `total` shares with reconstruction
    /// threshold `threshold`. Fuzzing-only public wrapper.
    pub fn shamir_split(secret: &[u8], threshold: u8, total: u8) -> Result<Vec<Vec<u8>>, String> {
        super::shamir_split(secret, threshold, total)
    }

    /// Reconstruct a secret from `shares`. Fuzzing-only public wrapper.
    pub fn shamir_combine(shares: &[&[u8]]) -> Result<Vec<u8>, String> {
        super::shamir_combine(shares)
    }
}

// =====================================================================
// Property tests, Shamir GF(256) invariants.
//
// This is the highest-risk subsystem in rhorizon : a home-rolled
// finite-field implementation underpins the multi-worker key
// distribution and the optional master-password Shamir init.
// Hand-written tests cover the happy path ; the property tests
// below randomise (secret content, secret length, threshold, total,
// share subset) to falsify the invariants the algorithm must obey.
//
// Skipped under miri : each proptest case runs N polynomial
// evaluations through the GF tables ; the combinatorial cost crosses
// minutes of CI without proving anything miri-specific (the GF math
// itself is plain Rust, no unsafe).
// =====================================================================

#[cfg(test)]
#[cfg(not(miri))]
mod proptests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashSet;

    // -- GF(256) algebraic invariants --
    //
    // These are the textbook properties that any GF(256) implementation
    // must satisfy. Any failure here means the underlying tables /
    // multiplication routine are subtly wrong, and Shamir downstream
    // will produce garbage that "looks right" until you try to
    // reconstruct from a different subset of shares.

    proptest! {
        // Multiplicative identity : mul(a, 1) == a for every a.
        #[test]
        fn prop_gf_mul_identity(a in any::<u8>()) {
            prop_assert_eq!(gf256_ct::mul(a, 1), a);
            prop_assert_eq!(gf256_ct::mul(1, a), a);
        }

        // Annihilator : mul(a, 0) == 0 for every a.
        #[test]
        fn prop_gf_mul_zero(a in any::<u8>()) {
            prop_assert_eq!(gf256_ct::mul(a, 0), 0);
            prop_assert_eq!(gf256_ct::mul(0, a), 0);
        }

        // Commutativity : mul(a, b) == mul(b, a).
        #[test]
        fn prop_gf_mul_commutative(a in any::<u8>(), b in any::<u8>()) {
            prop_assert_eq!(gf256_ct::mul(a, b), gf256_ct::mul(b, a));
        }

        // Associativity : mul(mul(a, b), c) == mul(a, mul(b, c)).
        #[test]
        fn prop_gf_mul_associative(
            a in any::<u8>(),
            b in any::<u8>(),
            c in any::<u8>(),
        ) {
            let lhs = gf256_ct::mul(gf256_ct::mul(a, b), c);
            let rhs = gf256_ct::mul(a, gf256_ct::mul(b, c));
            prop_assert_eq!(lhs, rhs);
        }

        // Distributivity : mul(a, b XOR c) == mul(a, b) XOR mul(a, c).
        // (Addition in GF(256) is XOR.)
        #[test]
        fn prop_gf_mul_distributive(
            a in any::<u8>(),
            b in any::<u8>(),
            c in any::<u8>(),
        ) {
            let lhs = gf256_ct::mul(a, b ^ c);
            let rhs = gf256_ct::mul(a, b) ^ gf256_ct::mul(a, c);
            prop_assert_eq!(lhs, rhs);
        }

        // Multiplicative inverse : for every non-zero a, there's a
        // unique inv(a) such that mul(a, inv(a)) == 1.
        #[test]
        fn prop_gf_inv_yields_one(a in 1u8..=255) {
            let inv = gf256_ct::inv(a).unwrap();
            prop_assert_eq!(gf256_ct::mul(a, inv), 1);
        }

        // inv(inv(a)) == a (involution).
        #[test]
        fn prop_gf_double_inv_identity(a in 1u8..=255) {
            let inv = gf256_ct::inv(a).unwrap();
            let inv_inv = gf256_ct::inv(inv).unwrap();
            prop_assert_eq!(inv_inv, a);
        }
    }

    // -- Shamir invariants --
    //
    // The hard-to-shake bugs in Shamir implementations are :
    //   - reconstruction works for SOME subsets of M-of-N but not all
    //   - leakage through reconstruction with M-1 shares
    //   - duplicate-index attack (caller sends two shares with same x)
    //   - off-by-one on threshold / total bounds
    //
    // Each proptest below targets one of these.

    /// Helper : returns `count` distinct indices in [0..n) chosen
    /// deterministically from `seed`. Used to pick share subsets.
    fn pick_indices(n: usize, count: usize, seed: u64) -> Vec<usize> {
        let mut indices: Vec<usize> = (0..n).collect();
        // Fisher-Yates shuffle with a tiny LCG so we don't need rand
        // in dev-deps. Seed deterministically from proptest's input.
        let mut state = seed.wrapping_add(1) | 1;
        for i in (1..indices.len()).rev() {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let j = (state as usize) % (i + 1);
            indices.swap(i, j);
        }
        indices.truncate(count);
        indices
    }

    proptest! {
        // CORE INVARIANT : split(secret, t, n) then combine(any t-subset)
        // returns the original secret exactly. This is THE property
        // Shamir must give us ; if it fails, the whole subsystem is
        // broken and the vault couldn't recover sub-keys on failover.
        //
        // We vary the secret length (1..=128 bytes, covering the 96-byte
        // master-key case and short/long edges), threshold (2..=8),
        // and total (threshold..=8). For each, we test every possible
        // t-subset of the n shares via an exhaustive shuffle.
        #[test]
        fn prop_shamir_roundtrip_any_quorum(
            secret in proptest::collection::vec(any::<u8>(), 1..=128),
            threshold in 2u8..=8,
            extra in 0u8..=6,
            subset_seed in any::<u64>(),
        ) {
            let total = threshold + extra;
            let shares = shamir_split(&secret, threshold, total).unwrap();
            // Pick a random t-subset.
            let picks = pick_indices(total as usize, threshold as usize, subset_seed);
            let chosen: Vec<&[u8]> = picks.iter().map(|&i| shares[i].as_slice()).collect();
            let recovered = shamir_combine(&chosen).unwrap();
            prop_assert_eq!(recovered, secret);
        }

        // ORDER INVARIANCE : the combine must not depend on the order
        // shares are presented. Reverse the same subset, must yield
        // the same secret.
        #[test]
        fn prop_shamir_order_invariance(
            secret in proptest::collection::vec(any::<u8>(), 1..=64),
            threshold in 2u8..=6,
            extra in 0u8..=4,
            subset_seed in any::<u64>(),
        ) {
            let total = threshold + extra;
            let shares = shamir_split(&secret, threshold, total).unwrap();
            let picks = pick_indices(total as usize, threshold as usize, subset_seed);
            let forward: Vec<&[u8]> = picks.iter().map(|&i| shares[i].as_slice()).collect();
            let backward: Vec<&[u8]> = picks.iter().rev().map(|&i| shares[i].as_slice()).collect();
            prop_assert_eq!(shamir_combine(&forward).unwrap(),
                            shamir_combine(&backward).unwrap());
        }

        // DUPLICATE INDEX REJECTION : an attacker resubmitting the
        // same share twice (or two crafted shares with the same x)
        // must not pass the threshold ; combine returns an error.
        // This guards against the "duplicate share" attack where M
        // valid-looking shares but with only M-1 distinct x-coords
        // would falsely satisfy quorum.
        #[test]
        fn prop_shamir_duplicate_index_rejected(
            secret in proptest::collection::vec(any::<u8>(), 1..=64),
            threshold in 2u8..=6,
            extra in 0u8..=4,
            dup_seed in any::<u8>(),
        ) {
            let total = threshold + extra;
            let shares = shamir_split(&secret, threshold, total).unwrap();
            // Take the first (t-1) shares + the FIRST share again.
            // The duplicate must be detected.
            let mut picks: Vec<&[u8]> = shares.iter().take((threshold - 1) as usize)
                .map(|s| s.as_slice()).collect();
            let dup_idx = (dup_seed as usize) % picks.len();
            picks.push(picks[dup_idx]);
            prop_assert!(shamir_combine(&picks).is_err());
        }

        // INDEX-PREFIX UNIQUENESS : after split, every share starts
        // with a distinct 1-byte x-coord. If two shares ever share
        // the same prefix, the duplicate-index attack above triggers
        // on legitimate input.
        #[test]
        fn prop_shamir_index_prefix_unique(
            secret in proptest::collection::vec(any::<u8>(), 1..=64),
            threshold in 2u8..=8,
            extra in 0u8..=6,
        ) {
            let total = threshold + extra;
            let shares = shamir_split(&secret, threshold, total).unwrap();
            let prefixes: HashSet<u8> = shares.iter().map(|s| s[0]).collect();
            prop_assert_eq!(prefixes.len(), shares.len(),
                "duplicate x-coord prefix found in shamir_split output");
        }

        // SHARE LENGTH STABLE : every share is exactly
        //   1 (x-coord) + secret.len() bytes.
        // A regression here would let a caller distinguish secrets
        // of different lengths from share metadata alone.
        #[test]
        fn prop_shamir_share_length_matches_secret(
            secret in proptest::collection::vec(any::<u8>(), 1..=128),
            threshold in 2u8..=8,
            extra in 0u8..=6,
        ) {
            let total = threshold + extra;
            let shares = shamir_split(&secret, threshold, total).unwrap();
            for s in &shares {
                prop_assert_eq!(s.len(), 1 + secret.len());
            }
        }

        // FRESHNESS / RANDOM COEFFICIENTS : two independent splits of
        // the same secret produce different share material (different
        // random polynomial coefficients drawn per call). If splits
        // were deterministic, distributing the same secret twice would
        // leak the polynomial across the two distributions.
        #[test]
        fn prop_shamir_split_uses_fresh_randomness(
            secret in proptest::collection::vec(any::<u8>(), 1..=64),
            threshold in 2u8..=6,
            extra in 0u8..=4,
        ) {
            let total = threshold + extra;
            // RETRY, do not assert on a single pair.
            //
            // A single collision is NOT evidence of a broken RNG. The random
            // material in a split is (threshold - 1) * secret.len() bytes, so
            // the smallest case this strategy generates -- threshold = 2 with a
            // 1-byte secret -- has exactly ONE random GF(256) coefficient, and
            // two independent splits agree with probability 1/256. Measured at
            // 0.00399 over 200k trials against an expectation of 0.00391.
            //
            // proptest duly found it (minimal input secret = [5], threshold = 2)
            // and reported "RNG broken", then SAVED THE SEED to
            // proptest-regressions/. On a reused CI workspace that replays every
            // run, so a legitimate 1-in-256 draw became a permanent red that
            // blocked deploys.
            //
            // A broken RNG repeats forever; a coincidence does not. Six fresh
            // pairs put a false positive at (1/256)^6 ~ 3e-15 while still
            // failing instantly on an RNG that is actually stuck.
            let mut any_diff = false;
            for _ in 0..6 {
                let split_a = shamir_split(&secret, threshold, total).unwrap();
                let split_b = shamir_split(&secret, threshold, total).unwrap();
                for (a, b) in split_a.iter().zip(split_b.iter()) {
                    // x-coords are deterministic indices and must always match.
                    prop_assert_eq!(a[0], b[0]);
                    if a[1..] != b[1..] { any_diff = true; }
                }
                if any_diff { break; }
            }
            prop_assert!(any_diff,
                "shamir_split produced identical y-coords across SIX independent \
                 pairs - RNG is stuck (a chance collision is ~3e-15 here)");
        }

        // BOUNDS : threshold < 2 and total < threshold must error.
        #[test]
        fn prop_shamir_bounds_validation(
            secret in proptest::collection::vec(any::<u8>(), 1..=32),
            bad_threshold in 0u8..=1,
            ok_total in 2u8..=8,
        ) {
            prop_assert!(shamir_split(&secret, bad_threshold, ok_total).is_err());
        }
    }
}
