// Copyright 2019 UCloud.cn, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use libc::stat as FileStat;
use libc::statvfs as Statvfs;
use libc::{self, c_char, c_int, c_uchar, c_void, dev_t, dirent, gid_t, mode_t, off_t, uid_t, DIR};

use std::mem::MaybeUninit;
use std::os::unix::io::RawFd;

use std::ffi::{CStr, CString};

use std::io::{IoSlice, IoSliceMut, Read, Write};

use std::cmp;
use std::fmt::{self, Debug};
use std::{io, mem, ptr, result};

type Result<T> = result::Result<T, io::Error>;

macro_rules! libc_err {
    ($callback:expr) => {{
        let ret = $callback;
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }};
}

macro_rules! libc_ret {
    ($callback:expr) => {{
        let ret = $callback;
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret)
        }
    }};
}

pub trait FdNum {
    fn fd_num(&self) -> u64;
}

#[derive(Debug)]
pub struct Fd(RawFd);

impl Fd {
    pub fn open(name: &CStr, flag: c_int) -> Result<Fd> {
        let ret = unsafe { libc::open(name.as_ptr(), flag) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Fd(ret as RawFd))
        }
    }

    pub fn openat(&self, name: Option<&CStr>, flag: c_int) -> Result<Fd> {
        let name_c = name.unwrap_or(Default::default()).as_ptr();
        let ret = unsafe { libc::openat(self.0, name_c, flag) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Fd(ret as RawFd))
        }
    }



    pub fn reopen(&self, flag: c_int) -> Result<Fd> {
        let name = format!("/proc/self/fd/{}\0", self.0);
        // It should be safe because `\0` is at the end of name.
        let name_c = unsafe { CStr::from_bytes_with_nul_unchecked(name.as_bytes()) };

        let ret = unsafe { libc::open(name_c.as_ptr(), flag) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Fd(ret as RawFd))
        }
    }

    pub fn fstatat(&self, name: Option<&CStr>, flag: c_int) -> Result<FileStat> {
        let (name, flag) = match name {
            Some(n) => (n, flag),
            None => (<&CStr>::default(), flag | libc::AT_EMPTY_PATH),
        };

        let mut buf = MaybeUninit::<FileStat>::uninit();
        let ret = unsafe { libc::fstatat(self.0, name.as_ptr(), buf.as_mut_ptr(), flag) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            // It's safe because buf has been initialiezed.
            unsafe { Ok(buf.assume_init()) }
        }
    }

    pub fn lseek(&self, offset: off_t, whence: c_int) -> Result<off_t> {
        libc_ret!(unsafe { libc::lseek(self.0, offset, whence) })
    }

    pub fn mknodat(&self, name: &CStr, mode: mode_t, dev: dev_t) -> Result<()> {
        libc_err!(unsafe { libc::mknodat(self.0, name.as_ptr(), mode, dev) })
    }

    pub fn fstatvfs(&self) -> Result<Statvfs> {
        let mut buf = MaybeUninit::<Statvfs>::uninit();
        let ret = unsafe { libc::fstatvfs(self.0, buf.as_mut_ptr()) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            // It's safe because buf has been initialiezed.
            unsafe { Ok(buf.assume_init()) }
        }
    }

    pub fn fchown(&self, owner: uid_t, group: gid_t) -> Result<()> {
        libc_err!(unsafe { libc::fchown(self.0, owner, group) })
    }

    pub fn unlinkat(&self, name: Option<&CStr>, flag: c_int) -> Result<()> {
        let name_c = name.unwrap_or(Default::default()).as_ptr();
        libc_err!(unsafe { libc::unlinkat(self.0, name_c, flag) })
    }

    pub fn mkdirat(&self, name: &CStr, mode: mode_t) -> Result<()> {
        libc_err!(unsafe { libc::mkdirat(self.0, name.as_ptr(), mode) })
    }

    pub fn fchmod(&self, mode: mode_t) -> Result<()> {
        libc_err!(unsafe { libc::fchmod(self.0, mode) })
    }

    pub fn symlinkat(&self, linkpath: &CStr, target: &CStr) -> Result<()> {
        libc_err!(unsafe { libc::symlinkat(target.as_ptr(), self.0, linkpath.as_ptr()) })
    }

    pub fn readlinkat(&self, name: Option<&CStr>) -> Result<CString> {
        let name_c = name.unwrap_or(Default::default()).as_ptr();
        let mut buf = Vec::with_capacity(libc::PATH_MAX as usize);
        let ret = unsafe {
            libc::readlinkat(
                self.0,
                name_c,
                buf.as_mut_ptr() as *mut c_char,
                buf.capacity(),
            )
        };

        if ret < 0 {
            Err(io::Error::last_os_error())
        } else if ret as c_int >= libc::PATH_MAX {
            Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG))
        } else {
            // It's safe because the size of buf has been checked
            unsafe {
                buf.set_len(ret as usize);
                Ok(CString::from_vec_unchecked(buf))
            }
        }
    }

    pub fn linkat(
        &self,
        old_name: Option<&CStr>,
        new_fd: &Fd,
        new_name: &CStr,
        flag: c_int,
    ) -> Result<()> {
        let old_name_c = old_name.unwrap_or(Default::default()).as_ptr();
        let new_name_c = new_name.as_ptr();
        libc_err!(unsafe { libc::linkat(self.0, old_name_c, new_fd.0, new_name_c, flag) })
    }
}

impl Read for Fd {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let ret = libc_ret!(unsafe {
            libc::read(
                self.0,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as libc::size_t,
            )
        })?;
        Ok(ret as usize)
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        let ret = libc_ret!(unsafe {
            libc::readv(
                self.0,
                bufs.as_ptr() as *const libc::iovec,
                cmp::min(bufs.len(), c_int::max_value() as usize) as c_int,
            )
        })?;
        Ok(ret as usize)
    }
}

impl Write for Fd {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let ret = libc_ret!(unsafe {
            libc::write(self.0,
                        buf.as_ptr() as *const c_void,
                        cmp::min(buf.len(), <libc::ssize_t>::max_value() as usize))
        })?;
        Ok(ret as usize)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        let ret = libc_ret!(unsafe {
            libc::writev(self.0,
                         bufs.as_ptr() as *const libc::iovec,
                         cmp::min(bufs.len(), c_int::max_value() as usize) as c_int)
        })?;
        Ok(ret as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl FdNum for Fd {
        fn fd_num(&self) -> u64 {
        self.0 as u64
    }
}

impl Drop for Fd {
    fn drop(&mut self) {
        error!("**FUCK** CLOSE FD {}", self.0);
        unsafe { libc::close(self.0) };
    }
}

pub struct Dir {
    dir: *mut DIR,
    fd: RawFd,
}

unsafe impl Send for Dir {}

impl Dir {
    pub fn openat222(raw_fd: &Fd, name: Option<&CStr>, flag: c_int) -> Result<Self> {
        let dot_cstr = unsafe { CStr::from_bytes_with_nul_unchecked(b".\0") };
        let name_c = name.unwrap_or(dot_cstr).as_ptr();
        let ret = unsafe { libc::openat(raw_fd.0, name_c, flag) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Dir::from_fd(ret)
        }
    }

    // pub fn openat(raw_fd: RawFd, name: Option<&CStr>, flag: c_int) -> Result<Self> {
    //     let dot_cstr = unsafe { CStr::from_bytes_with_nul_unchecked(b".\0") };
    //     let name_c = name.unwrap_or(dot_cstr).as_ptr();
    //     let ret = unsafe { libc::openat(raw_fd, name_c, flag) };
    //     if ret < 0 {
    //         Err(io::Error::last_os_error())
    //     } else {
    //         Dir::from_fd(ret)
    //     }
    // }

    fn from_fd(fd: RawFd) -> Result<Self> {
        let d = unsafe { libc::fdopendir(fd) };
        if d.is_null() {
            let e = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(e);
        };
        Ok(Dir{dir: d, fd: fd})
    }

    pub fn iter(&mut self) -> Iter {
        Iter(self)
    }
}

impl FdNum for Dir {
     fn fd_num(&self) -> u64 {
        self.fd as u64
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        error!("**FUCK** CLOSE DIR ");
        unsafe { libc::closedir(self.dir) };
    }
}

pub struct Iter<'d>(&'d mut Dir);

impl<'d> Iterator for Iter<'d> {
    type Item = Result<Entry>;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            let mut ret = Entry(mem::zeroed());
            let mut entry_ptr = ptr::null_mut();
            if libc::readdir_r((self.0).dir, &mut ret.0, &mut entry_ptr) != 0 {
                return Some(Err(io::Error::last_os_error()));
            }
            if entry_ptr.is_null() {
                return None;
            }
            Some(Ok(ret))
        }
    }
}

impl<'d> Drop for Iter<'d> {
    fn drop(&mut self) {
        unsafe { libc::rewinddir((self.0).dir) }
    }
}

pub struct Entry(dirent);

impl Entry {
    pub fn ino(&self) -> u64 {
        self.0.d_ino as u64
    }

    pub fn file_name(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.0.d_name.as_ptr()) }
    }

    pub fn file_type(&self) -> c_uchar {
        self.0.d_type
    }

    pub fn off(&self) -> i64 {
        self.0.d_off
    }
}

impl Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Entry")
            .field("ino", &self.ino())
            .field("type", &self.file_type())
            .field("name", &self.file_name())
            .field("off", &self.off())
            .finish()
    }
}



// pub fn mknodat(dirfd: RawFd, name: &CStr, mode: mode_t, dev: dev_t) -> Result<()> {
//     libc_err!(unsafe { libc::mknodat(dirfd, name.as_ptr(), mode, dev) })
// }

// pub fn mkdirat(dirfd: RawFd, name: &CStr, mode: mode_t) -> Result<()> {
//     libc_err!(unsafe { libc::mkdirat(dirfd, name.as_ptr(), mode) })
// }

// pub fn fchmod(dirfd: RawFd, mode: mode_t) -> Result<()> {
//     libc_err!(unsafe { libc::fchmod(dirfd, mode) })
// }

// pub fn fchown(dirfd: RawFd, owner: uid_t, group: gid_t) -> Result<()> {
//     libc_err!(unsafe { libc::fchown(dirfd, owner, group) })
// }

// pub fn unlinkat(dirfd: RawFd, name: Option<&CStr>, flag: c_int) -> Result<()> {
//     let name_c = name.unwrap_or(Default::default()).as_ptr();
//     libc_err!(unsafe { libc::unlinkat(dirfd, name_c, flag) })
// }

// pub fn symlinkat(dirfd: RawFd, linkpath: &CStr, target: &CStr) -> Result<()> {
//     libc_err!(unsafe { libc::symlinkat(target.as_ptr(), dirfd, linkpath.as_ptr()) })
// }

// pub fn readlinkat(dirfd: RawFd, name: Option<&CStr>) -> Result<CString> {
//     let name_c = name.unwrap_or(Default::default()).as_ptr();
//     let mut buf = Vec::with_capacity(libc::PATH_MAX as usize);
//     let ret = unsafe {
//         libc::readlinkat(
//             dirfd,
//             name_c,
//             buf.as_mut_ptr() as *mut c_char,
//             buf.capacity(),
//         )
//     };

//     if ret < 0 {
//         Err(io::Error::last_os_error())
//     } else if ret as c_int >= libc::PATH_MAX {
//         Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG))
//     } else {
//         // It's safe because the size of buf has been checked
//         unsafe {
//             buf.set_len(ret as usize);
//             Ok(CString::from_vec_unchecked(buf))
//         }
//     }
// }

// pub fn fstatat(dirfd: RawFd, name: Option<&CStr>, flag: c_int) -> Result<FileStat> {
//     let name_c = name.unwrap_or(Default::default()).as_ptr();
//     let mut buf = MaybeUninit::<FileStat>::uninit();
//     let ret = unsafe { libc::fstatat(dirfd, name_c, buf.as_mut_ptr(), flag) };
//     if ret < 0 {
//         Err(io::Error::last_os_error())
//     } else {
//         // It's safe because buf has been initialiezed.
//         unsafe { Ok(buf.assume_init()) }
//     }
// }

// pub fn fstatvfs(dirfd: RawFd) -> Result<Statvfs> {
//     let mut buf = MaybeUninit::<Statvfs>::uninit();
//     let ret = unsafe { libc::fstatvfs(dirfd, buf.as_mut_ptr()) };
//     if ret < 0 {
//         Err(io::Error::last_os_error())
//     } else {
//         // It's safe because buf has been initialiezed.
//         unsafe { Ok(buf.assume_init()) }
//     }
// }

// pub fn openat(dirfd: RawFd, name: Option<&CStr>, flag: c_int) -> Result<RawFd> {
//     let name_c = name.unwrap_or(Default::default()).as_ptr();
//     let ret = unsafe { libc::openat(dirfd, name_c, flag) };
//     if ret < 0 {
//         Err(io::Error::last_os_error())
//     } else {
//         Ok(ret as RawFd)
//     }
// }

// pub fn open(name: &CStr, flag: c_int) -> Result<RawFd> {
//     let ret = unsafe { libc::open(name.as_ptr(), flag) };
//     if ret < 0 {
//         Err(io::Error::last_os_error())
//     } else {
//         Ok(ret as RawFd)
//     }
// }

// pub fn close(fd: RawFd) -> Result<()> {
//     libc_err!(unsafe { libc::close(fd) })
// }

// pub fn linkat(
//     old_fd: RawFd,
//     old_name: Option<&CStr>,
//     new_fd: RawFd,
//     new_name: &CStr,
//     flag: c_int,
// ) -> Result<()> {
//     let old_name_c = old_name.unwrap_or(Default::default()).as_ptr();
//     let new_name_c = new_name.as_ptr();
//     libc_err!(unsafe { libc::linkat(old_fd, old_name_c, new_fd, new_name_c, flag) })
// }

// struct Cred {
//     euid: uid_t,
//     egid: gid_t,
// }

// impl Cred {
//     fn change_to(euid: uid_t, egid: gid_t) -> Result<Cred> {
//         let saved = unsafe {
//             Cred {
//                 euid: libc::getuid(),
//                 egid: libc::getgid(),
//             }
//         };

//         let ret = unsafe { libc::setegid(egid) };
//         if ret < 0 {
//             return Err(io::Error::last_os_error());
//         }

//         let ret = unsafe { libc::seteuid(euid) };
//         if ret < 0 {
//             let saved_err = io::Error::last_os_error();
//             unsafe { libc::setegid(saved.egid) };
//             return Err(saved_err);
//         }
//         Ok(saved)
//     }

//     fn restore(&self) -> Result<()> {
//         libc_err!(unsafe { libc::seteuid(self.euid) })?;
//         libc_err!(unsafe { libc::setegid(self.egid) })
//     }
// }

// pub fn with_cred<F>(uid: uid_t, gid: gid_t, f: F) -> Result<()>
// where
//     F: FnOnce() -> Result<()>,
// {
//     let saved_cred = Cred::change_to(uid, gid)?;
//     let ret = f();
//     saved_cred.restore().unwrap();
//     ret
// }
