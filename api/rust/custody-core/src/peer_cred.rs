// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//! Fail-closed Unix peer credentials for Linux, macOS, and BSD.

#![allow(unsafe_code)]

use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    pub fn read(stream: &UnixStream) -> std::io::Result<(u32, i32)> {
        let mut credential = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: the borrowed stream owns a live socket fd. `credential` is a
        // correctly sized libc output buffer and `length` describes it.
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credential as *mut libc::ucred).cast(),
                &mut length,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if length < std::mem::size_of::<libc::ucred>() as libc::socklen_t {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "peer credential response is truncated",
            ));
        }
        Ok((credential.uid, credential.pid))
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct XUcredPrefix {
        version: u32,
        uid: u32,
    }

    const XUCRED_SIZE: usize = std::mem::size_of::<libc::xucred>();

    pub fn read(stream: &UnixStream) -> std::io::Result<(u32, i32)> {
        let mut bytes = [0u8; XUCRED_SIZE];
        let mut length = XUCRED_SIZE as libc::socklen_t;
        // SAFETY: the borrowed stream owns a live socket fd. `bytes` is an
        // XUCRED_SIZE output buffer and `length` describes its full capacity.
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERCRED,
                bytes.as_mut_ptr().cast(),
                &mut length,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if length < std::mem::size_of::<XUcredPrefix>() as u32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "peer credential response is truncated",
            ));
        }
        // SAFETY: the length check proves the prefix bytes are initialized.
        // read_unaligned is required because a byte array has alignment 1.
        let prefix = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<XUcredPrefix>()) };
        Ok((prefix.uid, 0))
    }
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_os = "netbsd"
))]
mod platform {
    use super::*;

    pub fn read(stream: &UnixStream) -> std::io::Result<(u32, i32)> {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: the borrowed stream owns a live socket fd. Both pointers are
        // live output locations for the duration of the call.
        let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
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
mod platform {
    use super::*;

    pub fn read(_stream: &UnixStream) -> std::io::Result<(u32, i32)> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "peer credentials read not implemented on this OS",
        ))
    }
}

/// Return `(effective_uid, pid)`. macOS and BSD do not expose the peer PID and
/// return zero for it. Callers must use the UID as the security identity.
pub fn read_peer_cred(stream: &UnixStream) -> std::io::Result<(u32, i32)> {
    platform::read(stream)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    // `SO_PEERCRED` needs a real socket: miri hands out plain file descriptors
    // for `UnixStream::pair`, so `getsockopt` returns ENOTSOCK. Same gate as
    // the socket property tests in the PyO3 crate's `master_rpc`; the peer
    // credential shim is covered on the real OS by `cargo test` and by the
    // FreeBSD/OpenBSD VM matrix.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn socket_pair_reports_current_uid_and_a_pid() {
        let (left, _right) = UnixStream::pair().expect("socket pair");
        let (uid, pid) = read_peer_cred(&left).expect("peer credentials");
        // SAFETY: getuid has no arguments and cannot fail.
        assert_eq!(uid, unsafe { libc::getuid() });
        assert!(pid > 0);
    }
}
