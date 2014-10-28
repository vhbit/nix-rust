// Portions of this file are Copyright 2014 The Rust Project Developers.
// See http://rust-lang.org/COPYRIGHT.

use libc;
use time::Timespec;
use core::{mem, i32};
use core::intrinsics::transmute;
use errno::{SysError, SysResult, from_ffi};
use pthread::Pthread;

pub use libc::consts::os::posix88::{
    SIGHUP,   // 1
    SIGINT,   // 2
    SIGQUIT,  // 3
    SIGILL,   // 4
    SIGABRT,  // 6
    SIGFPE,   // 8
    SIGKILL,  // 9
    SIGSEGV,  // 11
    SIGPIPE,  // 13
    SIGALRM,  // 14
    SIGTERM,  // 15
};

pub use self::signal::{
    SIGTRAP,
    SIGIOT,
    SIGBUS,
    SIGSYS,
    SIGURG,
    SIGSTOP,
    SIGTSTP,
    SIGCONT,
    SIGCHLD,
    SIGTTIN,
    SIGTTOU,
    SIGIO,
    SIGXCPU,
    SIGXFSZ,
    SIGVTALRM,
    SIGPROF,
    SIGWINCH,
    SIGUSR1,
    SIGUSR2,
};

pub use self::signal::{SockFlag, SigHandler, SigInfoHandler, sigset_t};
pub use self::signal::{SA_SIGINFO};
pub use self::siginfo::SigInfo;

// This doesn't always exist, but when it does, it's 7
pub const SIGEMT: libc::c_int = 7;

#[inline]
pub fn SIG_IGN() -> SigHandler {
    unsafe { transmute(0i) }
}

#[inline]
pub fn SIG_IGN_INFO() -> SigInfoHandler {
    unsafe { transmute(0i) }
}

#[inline]
pub fn SIG_DFL() -> SigHandler {
    unsafe { transmute(1i) }
}

#[cfg(any(all(target_os = "linux",
              any(target_arch = "x86",
                  target_arch = "x86_64",
                  target_arch = "arm")),
          target_os = "android"))]
pub mod signal {
    use libc;
    use libc::c_int;

    bitflags!(
        flags SockFlag: libc::c_ulong {
            const SA_NOCLDSTOP = 0x00000001,
            const SA_NOCLDWAIT = 0x00000002,
            const SA_NODEFER   = 0x40000000,
            const SA_ONSTACK   = 0x08000000,
            const SA_RESETHAND = 0x80000000,
            const SA_RESTART   = 0x10000000,
            const SA_SIGINFO   = 0x00000004,
        }
    )

    pub const SIGTRAP:      libc::c_int = 5;
    pub const SIGIOT:       libc::c_int = 6;
    pub const SIGBUS:       libc::c_int = 7;
    pub const SIGUSR1:      libc::c_int = 10;
    pub const SIGUSR2:      libc::c_int = 12;
    pub const SIGSTKFLT:    libc::c_int = 16;
    pub const SIGCHLD:      libc::c_int = 17;
    pub const SIGCONT:      libc::c_int = 18;
    pub const SIGSTOP:      libc::c_int = 19;
    pub const SIGTSTP:      libc::c_int = 20;
    pub const SIGTTIN:      libc::c_int = 21;
    pub const SIGTTOU:      libc::c_int = 22;
    pub const SIGURG:       libc::c_int = 23;
    pub const SIGXCPU:      libc::c_int = 24;
    pub const SIGXFSZ:      libc::c_int = 25;
    pub const SIGVTALRM:    libc::c_int = 26;
    pub const SIGPROF:      libc::c_int = 27;
    pub const SIGWINCH:     libc::c_int = 28;
    pub const SIGIO:        libc::c_int = 29;
    pub const SIGPOLL:      libc::c_int = 29;
    pub const SIGPWR:       libc::c_int = 30;
    pub const SIGSYS:       libc::c_int = 31;
    pub const SIGUNUSED:    libc::c_int = 31;

    pub type SigHandler     = extern fn(libc::c_int);
    pub type SigInfoHandler = extern fn(libc::c_int, info: *const super::SigInfo, *const ());

    #[repr(C)]
    pub struct sigaction {
        pub sa_handler: SigHandler,
        pub sa_sigaction: SigInfoHandler,
        pub sa_mask: sigset_t,
        pub sa_flags: libc::c_ulong,
        sa_restorer: *mut libc::c_void,
    }

    #[repr(C)]
    #[cfg(target_word_size = "32")]
    pub struct sigset_t {
        __val: [libc::c_ulong, ..32],
    }

    #[repr(C)]
    #[cfg(target_word_size = "64")]
    pub struct sigset_t {
        __val: [libc::c_ulong, ..16],
    }
}

#[cfg(target_os = "linux")]
mod siginfo {
    use libc;
    use libc::c_int;
    use std::mem::transmute;

    // this is a union of int and pointer
    type SigVal = libc::c_int;

    #[repr(C)]
    struct RawSigInfo {
        signo:  c_int,
        errno:  c_int,
        code:   c_int,
    }

    #[repr(C)]
    pub struct SigInfo {
        pad: [u64, ..2]
    }

    impl SigInfo {
        pub fn signo(&self) -> c_int {
            self.raw().signo
        }

        pub fn errno(&self) -> c_int {
            self.raw().errno
        }

        pub fn code(&self) -> c_int {
            self.raw().code
        }

        fn raw(&self) -> &RawSigInfo {
            unsafe { transmute(self) }
        }
    }
}

#[cfg(all(target_os = "linux",
          any(target_arch = "mips", target_arch = "mipsel")))]
pub mod signal {
    use libc;

    bitflags!(
        flags SockFlag: libc::c_uint {
            const SA_NOCLDSTOP = 0x00000001,
            const SA_NOCLDWAIT = 0x00001000,
            const SA_NODEFER   = 0x40000000,
            const SA_ONSTACK   = 0x08000000,
            const SA_RESETHAND = 0x80000000,
            const SA_RESTART   = 0x10000000,
            const SA_SIGINFO   = 0x00000008,
        }
    )

    pub const SIGTRAP:      libc::c_int = 5;
    pub const SIGIOT:       libc::c_int = 6;
    pub const SIGBUS:       libc::c_int = 10;
    pub const SIGSYS:       libc::c_int = 12;
    pub const SIGUSR1:      libc::c_int = 16;
    pub const SIGUSR2:      libc::c_int = 17;
    pub const SIGCHLD:      libc::c_int = 18;
    pub const SIGCLD:       libc::c_int = 18;
    pub const SIGPWR:       libc::c_int = 19;
    pub const SIGWINCH:     libc::c_int = 20;
    pub const SIGURG:       libc::c_int = 21;
    pub const SIGIO:        libc::c_int = 22;
    pub const SIGPOLL:      libc::c_int = 22;
    pub const SIGSTOP:      libc::c_int = 23;
    pub const SIGTSTP:      libc::c_int = 24;
    pub const SIGCONT:      libc::c_int = 25;
    pub const SIGTTIN:      libc::c_int = 26;
    pub const SIGTTOU:      libc::c_int = 27;
    pub const SIGVTALRM:    libc::c_int = 28;
    pub const SIGPROF:      libc::c_int = 29;
    pub const SIGXCPU:      libc::c_int = 30;
    pub const SIGFSZ:       libc::c_int = 31;

    pub type SigHandler = extern fn(libc::c_int, info: *const super::SigInfo, *const ());

    #[repr(C)]
    pub struct sigaction {
        pub sa_flags: SockFlag,
        pub sa_handler: SigHandler,
        pub sa_mask: sigset_t,
        sa_restorer: *mut libc::c_void,
        sa_resv: [libc::c_int, ..1],
    }

    #[repr(C)]
    pub struct sigset_t {
        __val: [libc::c_ulong, ..32],
    }
}

#[cfg(any(target_os = "macos",
          target_os = "ios",
          target_os = "freebsd",
          target_os = "dragonfly"))]
pub mod signal {
    use libc;

    bitflags!(
        flags SockFlag: libc::c_int {
            const SA_NOCLDSTOP = 0x0008,
            const SA_NOCLDWAIT = 0x0020,
            const SA_NODEFER   = 0x0010,
            const SA_ONSTACK   = 0x0001,
            const SA_RESETHAND = 0x0004,
            const SA_RESTART   = 0x0002,
            const SA_SIGINFO   = 0x0040,
        }
    )

    pub const SIGTRAP:      libc::c_int = 5;
    pub const SIGIOT:       libc::c_int = 6;
    pub const SIGBUS:       libc::c_int = 10;
    pub const SIGSYS:       libc::c_int = 12;
    pub const SIGURG:       libc::c_int = 16;
    pub const SIGSTOP:      libc::c_int = 17;
    pub const SIGTSTP:      libc::c_int = 18;
    pub const SIGCONT:      libc::c_int = 19;
    pub const SIGCHLD:      libc::c_int = 20;
    pub const SIGTTIN:      libc::c_int = 21;
    pub const SIGTTOU:      libc::c_int = 22;
    pub const SIGIO:        libc::c_int = 23;
    pub const SIGXCPU:      libc::c_int = 24;
    pub const SIGXFSZ:      libc::c_int = 25;
    pub const SIGVTALRM:    libc::c_int = 26;
    pub const SIGPROF:      libc::c_int = 27;
    pub const SIGWINCH:     libc::c_int = 28;
    pub const SIGINFO:      libc::c_int = 29;
    pub const SIGUSR1:      libc::c_int = 30;
    pub const SIGUSR2:      libc::c_int = 31;

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub type sigset_t = u32;
    #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
    #[repr(C)]
    pub struct sigset_t {
        bits: [u32, ..4],
    }

    pub type SigHandler = extern fn(libc::c_int, *const super::SigInfo, *const ());

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[repr(C)]
    pub struct sigaction {
        pub sa_handler: SigHandler,
        sa_tramp: *mut libc::c_void,
        pub sa_mask: sigset_t,
        pub sa_flags: SockFlag,
    }

    #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
    #[repr(C)]
    pub struct sigaction {
        pub sa_handler: extern fn(libc::c_int, *const super::SigInfo, *const ()),
        pub sa_flags: SockFlag,
        pub sa_mask: sigset_t,
    }

}

#[cfg(any(target_os = "macos",
          target_os = "ios",
          target_os = "freebsd",
          target_os = "dragonfly"))]
mod siginfo {
    use libc;
    use libc::c_int;

    type SigVal = libc::c_int;

    #[repr(C)]
    struct SigInfo {
        pub signo:      c_int,
        errno:      c_int,
        code:       c_int,
        pid:        libc::pid_t,
        uid:        libc::uid_t,
        status:     c_int,
        addr:       *const (),
        value:      SigVal,
        band:       libc::c_long,
        pad:        [libc::c_ulong, ..7]
    }
}

mod ffi {
    use libc;
    use libc::c_int;
    use super::signal::{sigaction, sigset_t};
    use pthread::Pthread;

    extern {
        pub fn sigaction(signum: libc::c_int,
                         act: *const sigaction,
                         oldact: *mut sigaction) -> libc::c_int;

        pub fn sigfillset(set: *mut sigset_t) -> libc::c_int;
        pub fn sigaddset(set: *mut sigset_t, signum: libc::c_int) -> libc::c_int;
        pub fn sigdelset(set: *mut sigset_t, signum: libc::c_int) -> libc::c_int;
        pub fn sigemptyset(set: *mut sigset_t) -> libc::c_int;

        pub fn kill(pid: libc::pid_t, signum: libc::c_int) -> libc::c_int;
        pub fn pthread_kill(thread: Pthread, signum: libc::c_int) -> libc::c_int;

        pub fn pthread_sigmask(how: c_int, sigset: *const sigset_t, oldset: *mut sigset_t) -> c_int;

        pub fn sigpending(set: *mut sigset_t) -> libc::c_int;
        pub fn sigwaitinfo(set: *const sigset_t, info: *mut super::SigInfo) -> libc::c_int;
        pub fn sigtimedwait(set: *const sigset_t, info: *mut super::SigInfo, timeout: *const libc::timespec) -> c_int;
    }
}

pub struct SigSet {
    sigset: sigset_t
}

#[repr(C)]
#[deriving(Show)]
pub enum SigMaskHow {
    SIG_BLOCK   = 0,
    SIG_UNBLOCK = 1,
    SIG_SETMASK = 2,
}

pub type SigNum = libc::c_int;

impl SigSet {
    pub fn empty() -> SigSet {
        let mut sigset = unsafe { mem::uninitialized::<sigset_t>() };
        let _ = unsafe { ffi::sigemptyset(&mut sigset as *mut sigset_t) };

        SigSet { sigset: sigset }
    }

    pub fn all() -> SigSet {
        let mut sigset = unsafe { mem::uninitialized::<sigset_t>() };
        let _ = unsafe { ffi::sigfillset(&mut sigset as *mut sigset_t) };

        SigSet { sigset: sigset }
    }

    pub fn inner(&self) -> &sigset_t {
        &self.sigset
    }

    pub fn inner_mut(&mut self) -> &mut sigset_t {
        &mut self.sigset
    }

    pub fn add(&mut self, signum: SigNum) -> SysResult<()> {
        let res = unsafe { ffi::sigaddset(&mut self.sigset as *mut sigset_t, signum) };

        if res < 0 {
            return Err(SysError::last());
        }

        Ok(())
    }

    pub fn remove(&mut self, signum: SigNum) -> SysResult<()> {
        let res = unsafe { ffi::sigdelset(&mut self.sigset as *mut sigset_t, signum) };

        if res < 0 {
            return Err(SysError::last());
        }

        Ok(())
    }
}

type sigaction_t = self::signal::sigaction;

pub struct SigAction {
    sigaction: sigaction_t
}

impl SigAction {
    pub fn new(handler: SigHandler, flags: SockFlag, mask: SigSet) -> SigAction {
        let mut s = unsafe { mem::uninitialized::<sigaction_t>() };

        s.sa_handler = handler;
        s.sa_flags = flags.bits();
        s.sa_mask = mask.sigset;

        SigAction { sigaction: s }
    }

    pub fn new_info(handler: SigInfoHandler, flags: SockFlag, mask: SigSet) -> SigAction {
        let mut s = unsafe { mem::uninitialized::<sigaction_t>() };

        s.sa_sigaction = handler;
        s.sa_flags = flags.bits() | SA_SIGINFO.bits();
        s.sa_mask = mask.sigset;

        SigAction { sigaction: s }
    }
}

pub fn sigaction(signum: SigNum, sigaction: &SigAction) -> SysResult<SigAction> {
    let mut oldact = unsafe { mem::uninitialized::<sigaction_t>() };

    let res = unsafe {
        ffi::sigaction(signum, &sigaction.sigaction as *const sigaction_t, &mut oldact as *mut sigaction_t)
    };

    if res < 0 {
        return Err(SysError::last());
    }

    Ok(SigAction { sigaction: oldact })
}

pub fn pthread_sigmask(how: SigMaskHow, sigset: &SigSet) -> SysResult<SigSet> {
    let mut oldmask = unsafe { mem::uninitialized::<sigset_t>() };

    let res = unsafe {
        ffi::pthread_sigmask(how as libc::c_int, &sigset.sigset as *const sigset_t, &mut oldmask as *mut sigset_t)
    };

    if res < 0 {
        return Err(SysError::last());
    }

    Ok(SigSet { sigset: oldmask })
}

pub fn kill(pid: libc::pid_t, signum: SigNum) -> SysResult<()> {
    let res = unsafe { ffi::kill(pid, signum) };

    if res < 0 {
        return Err(SysError::last());
    }

    Ok(())
}

pub fn pthread_kill(thread: Pthread, sig: SigNum) -> SysResult<()> {
    let res = unsafe { ffi::pthread_kill(thread, sig) };

    if res == 0 {
        Ok(())
    } else {
        Err(SysError::from_errno(res as int))
    }
}

pub fn sigwaitinfo(set: SigSet) -> SysResult<SigInfo> {
    let mut info = unsafe { mem::uninitialized::<SigInfo>() };
    let res = unsafe { ffi::sigwaitinfo(set.inner(), &mut info as *mut SigInfo) };

    if res < 0 {
        return Err(SysError::last());
    }

    Ok(info)
}

pub fn sigtimedwait(set: SigSet, timeout: Timespec) -> SysResult<SigInfo> {
    let timespec = libc::timespec { tv_sec: timeout.sec, tv_nsec: timeout.nsec as libc::c_long };
    let mut info = unsafe { mem::uninitialized::<SigInfo>() };
    let res = unsafe { ffi::sigtimedwait(set.inner(), &mut info as *mut SigInfo, &timespec as *const libc::timespec) };

    if res < 0 {
        return Err(SysError::last());
    }

    Ok(info)
}

pub fn sigpending() -> SysResult<SigSet> {
    let mut set = unsafe { mem::uninitialized::<SigSet>() };
    let res = unsafe { ffi::sigpending(set.inner_mut()) };

    if res < 0 {
        return Err(SysError::last());
    }

    Ok(set)
}

#[cfg(test)]
mod test {
    use libc;
    use pthread::pthread_self;
    use time::Timespec;
    use super::{
        SigSet,
        SigAction,
        SA_SIGINFO,
        SIG_IGN,
        SIG_IGN_INFO,
        SIG_BLOCK,
        SIGQUIT,
        pthread_sigmask,
        pthread_kill,
        sigaction,
        sigwaitinfo,
        sigtimedwait,
    };

    #[test]
    fn test_simple_signal() {
        let mut mask = SigSet::empty();
        mask.add(SIGQUIT).unwrap();

        pthread_sigmask(SIG_BLOCK, &mask).unwrap();

        let action = SigAction::new_info(SIG_IGN_INFO(), SA_SIGINFO, SigSet::empty());
        sigaction(SIGQUIT, &action).unwrap();

        pthread_kill(pthread_self(), SIGQUIT).unwrap();

        let info = sigtimedwait(mask, Timespec { sec: 0, nsec: 0 }).unwrap();

        assert_eq!(info.signo(), SIGQUIT);
    }
}
