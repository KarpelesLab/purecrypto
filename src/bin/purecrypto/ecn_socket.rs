//! IP ECN plumbing for the QUIC CLI sockets (Linux only).
//!
//! `std::net::UdpSocket` exposes neither the per-datagram IP ECN codepoint on
//! receive nor a way to mark it on send, so the sans-I/O engine's ECN support
//! (RFC 9000 §13.4) can't fire over a real socket without dropping to
//! `recvmsg`/`setsockopt`. To stay consistent with the rest of the crate
//! (which avoids `libc`, issuing `getrandom` via a raw syscall — see
//! `src/rng/linux_getrandom.rs`), this does the same: raw `recvmsg(2)` and
//! `setsockopt(2)` syscalls via inline asm on x86_64 / aarch64.
//!
//! On any other target the helpers are no-ops / plain `recv_from`, so the CLI
//! still works (just without ECN) everywhere else.

#![allow(dead_code)]
// Raw `recvmsg` / `setsockopt` syscalls — the same unsafe carve-out the
// library's `getrandom` path uses, to avoid a `libc` dependency.
#![allow(unsafe_code)]

use purecrypto::quic::EcnCodepoint;
use std::io;
use std::net::SocketAddr;

// ---- Linux x86_64 / aarch64 implementation ---------------------------------

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod imp {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::fd::{AsRawFd, RawFd};

    const IPPROTO_IP: i32 = 0;
    const IPPROTO_IPV6: i32 = 41;
    const IP_TOS: i32 = 1;
    const IP_RECVTOS: i32 = 13;
    const IPV6_TCLASS: i32 = 67;
    const IPV6_RECVTCLASS: i32 = 66;
    const AF_INET: u16 = 2;
    const AF_INET6: u16 = 10;

    // Linux LP64 layouts (identical on x86_64 and aarch64).
    #[repr(C)]
    struct IoVec {
        base: *mut u8,
        len: usize,
    }
    #[repr(C)]
    struct MsgHdr {
        name: *mut u8,
        namelen: u32,
        // repr(C) inserts 4 bytes of padding here to 8-align the next field.
        iov: *mut IoVec,
        iovlen: usize,
        control: *mut u8,
        controllen: usize,
        flags: i32,
    }

    #[cfg(target_arch = "x86_64")]
    const SYS_RECVMSG: isize = 47;
    #[cfg(target_arch = "x86_64")]
    const SYS_SETSOCKOPT: isize = 54;
    #[cfg(target_arch = "aarch64")]
    const SYS_RECVMSG: isize = 212;
    #[cfg(target_arch = "aarch64")]
    const SYS_SETSOCKOPT: isize = 208;

    #[cfg(target_arch = "x86_64")]
    unsafe fn syscall3(n: isize, a: isize, b: isize, c: isize) -> isize {
        let ret;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") n => ret,
                in("rdi") a, in("rsi") b, in("rdx") c,
                lateout("rcx") _, lateout("r11") _,
                options(nostack, preserves_flags),
            );
        }
        ret
    }
    #[cfg(target_arch = "x86_64")]
    unsafe fn syscall5(n: isize, a: isize, b: isize, c: isize, d: isize, e: isize) -> isize {
        let ret;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") n => ret,
                in("rdi") a, in("rsi") b, in("rdx") c, in("r10") d, in("r8") e,
                lateout("rcx") _, lateout("r11") _,
                options(nostack, preserves_flags),
            );
        }
        ret
    }
    #[cfg(target_arch = "aarch64")]
    unsafe fn syscall3(n: isize, a: isize, b: isize, c: isize) -> isize {
        let ret;
        unsafe {
            core::arch::asm!(
                "svc #0",
                in("x8") n,
                inlateout("x0") a => ret,
                in("x1") b, in("x2") c,
                options(nostack, preserves_flags),
            );
        }
        ret
    }
    #[cfg(target_arch = "aarch64")]
    unsafe fn syscall5(n: isize, a: isize, b: isize, c: isize, d: isize, e: isize) -> isize {
        let ret;
        unsafe {
            core::arch::asm!(
                "svc #0",
                in("x8") n,
                inlateout("x0") a => ret,
                in("x1") b, in("x2") c, in("x3") d, in("x4") e,
                options(nostack, preserves_flags),
            );
        }
        ret
    }

    unsafe fn setsockopt(fd: RawFd, level: i32, optname: i32, val: i32) {
        let v = val;
        let _ = unsafe {
            syscall5(
                SYS_SETSOCKOPT,
                fd as isize,
                level as isize,
                optname as isize,
                (&v as *const i32) as isize,
                4,
            )
        };
    }

    /// Marks egress datagrams ECT(0) and asks the kernel to deliver the IP ECN
    /// codepoint of received datagrams (best-effort; failures are ignored, e.g.
    /// `IP_TOS` on an IPv6 socket).
    pub(crate) fn configure(sock: &impl AsRawFd) {
        let fd = sock.as_raw_fd();
        unsafe {
            setsockopt(fd, IPPROTO_IP, IP_TOS, EcnCodepoint::Ect0.to_bits() as i32);
            setsockopt(
                fd,
                IPPROTO_IPV6,
                IPV6_TCLASS,
                EcnCodepoint::Ect0.to_bits() as i32,
            );
            setsockopt(fd, IPPROTO_IP, IP_RECVTOS, 1);
            setsockopt(fd, IPPROTO_IPV6, IPV6_RECVTCLASS, 1);
        }
    }

    fn parse_addr(stor: &[u8; 128]) -> Option<SocketAddr> {
        let family = u16::from_ne_bytes([stor[0], stor[1]]);
        match family {
            AF_INET => {
                let port = u16::from_be_bytes([stor[2], stor[3]]);
                let ip = Ipv4Addr::new(stor[4], stor[5], stor[6], stor[7]);
                Some(SocketAddr::new(IpAddr::V4(ip), port))
            }
            AF_INET6 => {
                let port = u16::from_be_bytes([stor[2], stor[3]]);
                let mut o = [0u8; 16];
                o.copy_from_slice(&stor[8..24]);
                Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(o)), port))
            }
            _ => None,
        }
    }

    fn parse_ecn(ctrl: &[u8]) -> EcnCodepoint {
        let mut off = 0;
        // Each cmsg: { usize len; i32 level; i32 type; data... } 16-byte aligned.
        while off + 16 <= ctrl.len() {
            let len = usize::from_ne_bytes(ctrl[off..off + 8].try_into().unwrap());
            let level = i32::from_ne_bytes(ctrl[off + 8..off + 12].try_into().unwrap());
            let ctype = i32::from_ne_bytes(ctrl[off + 12..off + 16].try_into().unwrap());
            if len < 16 || off + len > ctrl.len() {
                break;
            }
            let is_tos = (level == IPPROTO_IP && ctype == IP_TOS)
                || (level == IPPROTO_IPV6 && ctype == IPV6_TCLASS);
            if is_tos && off + 16 < ctrl.len() {
                // ECN is the low two bits of the TOS/Traffic-Class octet, which
                // is the first data byte for IPv4 (a byte) and the low byte of
                // the little-endian int for IPv6 — `data[0]` works for both.
                return EcnCodepoint::from_bits(ctrl[off + 16]);
            }
            off += (len + 7) & !7; // CMSG_ALIGN
        }
        EcnCodepoint::NotEct
    }

    /// `recvmsg(2)` returning the bytes received, the source address, and the
    /// datagram's IP ECN codepoint.
    pub(crate) fn recv_ecn(
        sock: &impl AsRawFd,
        buf: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, EcnCodepoint)> {
        let mut name = [0u8; 128];
        let mut control = [0u8; 64];
        let mut iov = IoVec {
            base: buf.as_mut_ptr(),
            len: buf.len(),
        };
        let mut msg = MsgHdr {
            name: name.as_mut_ptr(),
            namelen: name.len() as u32,
            iov: &mut iov,
            iovlen: 1,
            control: control.as_mut_ptr(),
            controllen: control.len(),
            flags: 0,
        };
        let n = unsafe {
            syscall3(
                SYS_RECVMSG,
                sock.as_raw_fd() as isize,
                (&mut msg as *mut MsgHdr) as isize,
                0,
            )
        };
        if n < 0 {
            return Err(io::Error::from_raw_os_error((-n) as i32));
        }
        let addr = parse_addr(&name).ok_or_else(|| io::Error::other("unknown address family"))?;
        let ctrl_len = msg.controllen.min(control.len());
        let ecn = parse_ecn(&control[..ctrl_len]);
        Ok((n as usize, addr, ecn))
    }
}

// ---- Portable fallback (non-Linux, other arches) ---------------------------

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
mod imp {
    use super::*;
    use std::net::UdpSocket;

    /// No-op: ECN marking is unavailable without the Linux syscall path.
    pub(crate) fn configure(_sock: &UdpSocket) {}

    /// Plain `recv_from`, reporting `NotEct` (no ECN information available).
    pub(crate) fn recv_ecn(
        sock: &UdpSocket,
        buf: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, EcnCodepoint)> {
        let (n, addr) = sock.recv_from(buf)?;
        Ok((n, addr, EcnCodepoint::NotEct))
    }
}

pub(crate) use imp::{configure, recv_ecn};

#[cfg(all(
    test,
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    /// Round-trips an ECT(0)-marked datagram over loopback: `configure` sets
    /// the egress codepoint and enables IP_RECVTOS, and `recv_ecn` reads it
    /// back out of the control message — validating the raw setsockopt/recvmsg
    /// syscalls and cmsg parsing.
    #[test]
    fn reads_ect0_codepoint_over_loopback() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        configure(&rx);
        configure(&tx);
        tx.send_to(b"ecn-ping", rx.local_addr().unwrap()).unwrap();
        let mut buf = [0u8; 64];
        let (n, _from, ecn) = recv_ecn(&rx, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"ecn-ping");
        assert_eq!(ecn, EcnCodepoint::Ect0, "received codepoint is ECT(0)");
    }
}
