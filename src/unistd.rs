use std::{mem, ptr};
use libc::{c_char, c_void, c_int, size_t, pid_t, off_t};
use errno::Errno;
use fcntl::{fcntl, Fd, OFlag, O_NONBLOCK, O_CLOEXEC, FD_CLOEXEC};
use fcntl::FcntlArg::{F_SETFD, F_SETFL};
use {NixError, NixResult, NixPath, from_ffi};

use core::raw::Slice as RawSlice;
use std::ffi::CString;

#[cfg(target_os = "linux")]
pub use self::linux::*;

mod ffi {
    use super::{IovecR,IovecW};
    use libc::{c_char, c_int, size_t, ssize_t};
    pub use libc::{close, read, write, pipe, ftruncate, unlink};
    pub use libc::funcs::posix88::unistd::fork;
    use fcntl::Fd;

    extern {
        // duplicate a file descriptor
        // doc: http://man7.org/linux/man-pages/man2/dup.2.html
        pub fn dup(oldfd: c_int) -> c_int;
        pub fn dup2(oldfd: c_int, newfd: c_int) -> c_int;

        // change working directory
        // doc: http://man7.org/linux/man-pages/man2/chdir.2.html
        pub fn chdir(path: *const c_char) -> c_int;

        // execute program
        // doc: http://man7.org/linux/man-pages/man2/execve.2.html
        pub fn execve(filename: *const c_char, argv: *const *const c_char, envp: *const *const c_char) -> c_int;

        // run the current process in the background
        // doc: http://man7.org/linux/man-pages/man3/daemon.3.html
        pub fn daemon(nochdir: c_int, noclose: c_int) -> c_int;

        // sets the hostname to the value given
        // doc: http://man7.org/linux/man-pages/man2/gethostname.2.html
        pub fn gethostname(name: *mut c_char, len: size_t) -> c_int;

        // gets the hostname
        // doc: http://man7.org/linux/man-pages/man2/gethostname.2.html
        pub fn sethostname(name: *const c_char, len: size_t) -> c_int;

        // vectorized version of write
        // doc: http://man7.org/linux/man-pages/man2/writev.2.html
        pub fn writev(fd: Fd, iov: *const IovecW, iovcnt: c_int) -> ssize_t;

        // vectorized version of read
        // doc: http://man7.org/linux/man-pages/man2/readv.2.html
        pub fn readv(fd: Fd, iov: *const IovecR, iovcnt: c_int) -> ssize_t;
    }
}

#[derive(Copy)]
pub enum Fork {
    Parent(pid_t),
    Child
}

impl Fork {
    pub fn is_child(&self) -> bool {
        match *self {
            Fork::Child => true,
            _ => false
        }
    }

    pub fn is_parent(&self) -> bool {
        match *self {
            Fork::Parent(_) => true,
            _ => false
        }
    }
}

pub fn fork() -> NixResult<Fork> {
    use self::Fork::*;

    let res = unsafe { ffi::fork() };

    if res < 0 {
        return Err(NixError::Sys(Errno::last()));
    } else if res == 0 {
        Ok(Child)
    } else {
        Ok(Parent(res))
    }
}

// We use phantom types to maintain memory safety.
// If readv/writev were using simple &[Iovec] we could initialize
// Iovec with immutable slice and then pass it to readv, overwriting content
// we dont have write access to:
// let mut v = Vec::new();
// let iov = Iovec::from_slice(immutable_vec.as_slice());
// v.push(iov);
// let _:NixResult<usize> = readv(fd, v.as_slice());

// We do not want <T> to appear in ffi functions, so we provide this aliases.
type IovecR = Iovec<ToRead>;
type IovecW = Iovec<ToWrite>;

#[derive(Copy)]
pub struct ToRead;
#[derive(Copy)]
pub struct ToWrite;

#[repr(C)]
pub struct Iovec<T> {
    iov_base: *mut c_void,
    iov_len: size_t,
    marker: ::std::marker::PhantomData<T>,
}

impl <T> Iovec<T> {
    #[inline]
    pub fn as_slice<'a>(&'a self) -> &'a [u8] {
        unsafe { mem::transmute(RawSlice { data: self.iov_base as *const u8, len: self.iov_len as usize }) }
    }
}

impl Iovec<ToWrite> {
    #[inline]
    pub fn from_slice(buf: &[u8]) -> Iovec<ToWrite> {
        Iovec {
            iov_base: buf.as_ptr() as *mut c_void,
            iov_len: buf.len() as size_t,
            marker: ::std::marker::PhantomData
        }
    }
}

impl Iovec<ToRead> {
    #[inline]
    pub fn from_mut_slice(buf: &mut [u8]) -> Iovec<ToRead> {
        Iovec {
            iov_base: buf.as_ptr() as *mut c_void,
            iov_len: buf.len() as size_t,
            marker: ::std::marker::PhantomData
        }
    }
}


#[inline]
pub fn dup(oldfd: Fd) -> NixResult<Fd> {
    let res = unsafe { ffi::dup(oldfd) };

    if res < 0 {
        return Err(NixError::Sys(Errno::last()));
    }

    Ok(res)
}

#[inline]
pub fn dup2(oldfd: Fd, newfd: Fd) -> NixResult<Fd> {
    let res = unsafe { ffi::dup2(oldfd, newfd) };

    if res < 0 {
        return Err(NixError::Sys(Errno::last()));
    }

    Ok(res)
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
pub fn dup3(oldfd: Fd, newfd: Fd, flags: OFlag) -> NixResult<Fd> {
    type F = unsafe extern "C" fn(c_int, c_int, c_int) -> c_int;

    extern {
        #[linkage = "extern_weak"]
        static dup3: *const ();
    }

    if !dup3.is_null() {
        let res = unsafe {
            mem::transmute::<*const (), F>(dup3)(
                oldfd, newfd, flags.bits())
        };

        if res < 0 {
            return Err(NixError::Sys(Errno::last()));
        }

        Ok(res)
    } else {
        dup3_polyfill(oldfd, newfd, flags)
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub fn dup3(oldfd: Fd, newfd: Fd, flags: OFlag) -> NixResult<Fd> {
    dup3_polyfill(oldfd, newfd, flags)
}

#[inline]
fn dup3_polyfill(oldfd: Fd, newfd: Fd, flags: OFlag) -> NixResult<Fd> {
    use errno::EINVAL;

    if oldfd == newfd {
        return Err(NixError::Sys(Errno::EINVAL));
    }

    let fd = try!(dup2(oldfd, newfd));

    if flags.contains(O_CLOEXEC) {
        if let Err(e) = fcntl(fd, F_SETFD(FD_CLOEXEC)) {
            let _ = close(fd);
            return Err(e);
        }
    }

    Ok(fd)
}

#[inline]
pub fn chdir<P: NixPath>(path: P) -> NixResult<()> {
    let res = try!(path.with_nix_path(|ptr| {
        unsafe { ffi::chdir(ptr) }
    }));

    if res != 0 {
        return Err(NixError::Sys(Errno::last()));
    }

    return Ok(())
}

#[inline]
pub fn execve(filename: &CString, args: &[CString], env: &[CString]) -> NixResult<()> {
    let mut args_p: Vec<*const c_char> = args.iter().map(|s| s.as_ptr()).collect();
    args_p.push(ptr::null());

    let mut env_p: Vec<*const c_char> = env.iter().map(|s| s.as_ptr()).collect();
    env_p.push(ptr::null());

    let res = unsafe {
        ffi::execve(filename.as_ptr(), args_p.as_ptr(), env_p.as_ptr())
    };

    if res != 0 {
        return Err(NixError::Sys(Errno::last()));
    }

    unreachable!()
}

pub fn daemon(nochdir: bool, noclose: bool) -> NixResult<()> {
    let res = unsafe { ffi::daemon(nochdir as c_int, noclose as c_int) };
    from_ffi(res)
}

pub fn sethostname(name: &[u8]) -> NixResult<()> {
    let ptr = name.as_ptr() as *const c_char;
    let len = name.len() as size_t;

    let res = unsafe { ffi::sethostname(ptr, len) };
    from_ffi(res)
}

pub fn gethostname(name: &mut [u8]) -> NixResult<()> {
    let ptr = name.as_mut_ptr() as *mut c_char;
    let len = name.len() as size_t;

    let res = unsafe { ffi::gethostname(ptr, len) };
    from_ffi(res)
}

pub fn close(fd: Fd) -> NixResult<()> {
    let res = unsafe { ffi::close(fd) };
    from_ffi(res)
}

pub fn read(fd: Fd, buf: &mut [u8]) -> NixResult<usize> {
    let res = unsafe { ffi::read(fd, buf.as_mut_ptr() as *mut c_void, buf.len() as size_t) };

    if res < 0 {
        return Err(NixError::Sys(Errno::last()));
    }

    return Ok(res as usize)
}

pub fn write(fd: Fd, buf: &[u8]) -> NixResult<usize> {
    let res = unsafe { ffi::write(fd, buf.as_ptr() as *const c_void, buf.len() as size_t) };

    if res < 0 {
        return Err(NixError::Sys(Errno::last()));
    }

    return Ok(res as usize)
}

pub fn writev(fd: Fd, iov: &[Iovec<ToWrite>]) -> NixResult<usize> {
    let res = unsafe { ffi::writev(fd, iov.as_ptr(), iov.len() as c_int) };
    if res < 0 {
        return Err(NixError::Sys(Errno::last()));
    }

    return Ok(res as usize)
}

pub fn readv(fd: Fd, iov: &mut [Iovec<ToRead>]) -> NixResult<usize> {
    let res = unsafe { ffi::readv(fd, iov.as_ptr(), iov.len() as c_int) };
    if res < 0 {
        return Err(NixError::Sys(Errno::last()));
    }

    return Ok(res as usize)
}

pub fn pipe() -> NixResult<(Fd, Fd)> {
    unsafe {
        let mut res;
        let mut fds: [c_int; 2] = mem::uninitialized();

        res = ffi::pipe(fds.as_mut_ptr());

        if res < 0 {
            return Err(NixError::Sys(Errno::last()));
        }

        Ok((fds[0], fds[1]))
    }
}

#[cfg(target_os = "linux")]
pub fn pipe2(flags: OFlag) -> NixResult<(Fd, Fd)> {
    type F = unsafe extern "C" fn(fds: *mut c_int, flags: c_int) -> c_int;

    extern {
        #[linkage = "extern_weak"]
        static pipe2: *const ();
    }

    let feat_atomic = !pipe2.is_null();

    unsafe {
        let mut res;
        let mut fds: [c_int; 2] = mem::uninitialized();

        if feat_atomic {
            res = mem::transmute::<*const (), F>(pipe2)(
                fds.as_mut_ptr(), flags.bits());
        } else {
            res = ffi::pipe(fds.as_mut_ptr());
        }

        if res < 0 {
            return Err(NixError::Sys(Errno::last()));
        }

        if !feat_atomic {
            try!(pipe2_setflags(fds[0], fds[1], flags));
        }

        Ok((fds[0], fds[1]))
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub fn pipe2(flags: OFlag) -> NixResult<(Fd, Fd)> {
    unsafe {
        let mut res;
        let mut fds: [c_int; 2] = mem::uninitialized();

        res = ffi::pipe(fds.as_mut_ptr());

        if res < 0 {
            return Err(NixError::Sys(Errno::last()));
        }

        try!(pipe2_setflags(fds[0], fds[1], flags));

        Ok((fds[0], fds[1]))
    }
}

fn pipe2_setflags(fd1: Fd, fd2: Fd, flags: OFlag) -> NixResult<()> {
    let mut res = Ok(());

    if flags.contains(O_CLOEXEC) {
        res = res
            .and_then(|_| fcntl(fd1, F_SETFD(FD_CLOEXEC)))
            .and_then(|_| fcntl(fd2, F_SETFD(FD_CLOEXEC)));
    }

    if flags.contains(O_NONBLOCK) {
        res = res
            .and_then(|_| fcntl(fd1, F_SETFL(O_NONBLOCK)))
            .and_then(|_| fcntl(fd2, F_SETFL(O_NONBLOCK)));
    }

    match res {
        Ok(_) => Ok(()),
        Err(e) => {
            let _ = close(fd1);
            let _ = close(fd2);
            return Err(e);
        }
    }
}

pub fn ftruncate(fd: Fd, len: off_t) -> NixResult<()> {
    if unsafe { ffi::ftruncate(fd, len) } < 0 {
        Err(NixError::Sys(Errno::last()))
    } else {
        Ok(())
    }
}

pub fn isatty(fd: Fd) -> NixResult<bool> {
    use libc;

    if unsafe { libc::isatty(fd) } == 1 {
        Ok(true)
    } else {
        match Errno::last() {
            // ENOTTY means `fd` is a valid file descriptor, but not a TTY, so
            // we return `Ok(false)`
            Errno::ENOTTY => Ok(false),
            err => Err(NixError::Sys(err))
        }
    }
}

pub fn unlink<P: NixPath>(path: P) -> NixResult<()> {
    let res = try!(path.with_nix_path(|ptr| {
    unsafe {
        ffi::unlink(ptr)
    }
    }));
    from_ffi(res)
}

#[cfg(target_os = "linux")]
mod linux {
    use syscall::{syscall, SYSPIVOTROOT};
    use errno::Errno;
    use {NixError, NixResult, NixPath};

    pub fn pivot_root<P1: NixPath, P2: NixPath>(new_root: P1,
                                                put_old: P2) -> NixResult<()> {
        let res = try!(try!(new_root.with_nix_path(|new_root| {
            put_old.with_nix_path(|put_old| {
                unsafe {
                    syscall(SYSPIVOTROOT, new_root, put_old)
                }
            })
        })));

        if res != 0 {
            return Err(NixError::Sys(Errno::last()));
        }

        Ok(())
    }
}
