// Copyright 2019 UCloud.cn, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::mem;
use std::result;

use libc::stat as FileStat;
// use std::os::unix::io::AsRawFd;
// use std::os::unix::io::RawFd;

// use super::filesystem::{
//     close, fchmod, fchown, fstatat, fstatvfs, linkat, mkdirat, mknodat, open, openat, readlinkat,
//     symlinkat, unlinkat,
// };
use std::ffi::{CStr, CString};

use super::filesystem::{Dir, Fd, FdNum};

use libc::statvfs as Statvfs;

use super::util::FuseDirent;
use fuse_gen::fuse::*;

use libc::{dev_t, gid_t, mode_t, uid_t};

use memory_model::{GuestAddress, GuestMemory};

use super::super::DescriptorChain;

use super::error::ExecuteError;

/// The max size of write requests from the kernel. The absolute minimum is 4k,
/// FUSE recommends at least 128k, max 16M. The FUSE default is 128k.
const FUSE_MAX_WRITE_SIZE: usize = 16 * 1024 * 1024;

const FUSE_KERNEL_VERSION: u32 = 7;
const FUSE_KERNEL_MINOR_VERSION: u32 = 19;
const FUSE_INIT_FLAGS: u32 = FUSE_ASYNC_READ | FUSE_MAX_PAGES | FUSE_BIG_WRITES;
const FUSE_DEFAULT_MAX_BACKGROUND: u16 = 12;
const FUSE_DEFAULT_CONGESTION_THRESHOLD: u16 = (FUSE_DEFAULT_MAX_BACKGROUND * 3 / 4);

type Result<T> = result::Result<T, ExecuteError>;

#[derive(Debug)]
pub enum VtfsError {
    /// Guest gave us bad memory addresses.
    // GuestMemory(GuestMemoryError),
    /// Guest gave us offsets that would have overflowed a usize.
    // CheckedOffset(GuestAddress, usize),
    /// Guest gave us a write only descriptor that protocol says to read from.
    UnexpectedWriteOnlyDescriptor,
    /// Guest gave us a read only descriptor that protocol says to write to.
    // UnexpectedReadOnlyDescriptor,
    /// Guest gave us too few descriptors in a descriptor chain.
    DescriptorChainTooShort,
    /// Guest gave us a descriptor that was too short to use.
    // DescriptorLengthTooSmall,
    /// Getting a block's metadata fails for any reason.
    // GetFileMetadata,
    /// The requested operation would cause a seek beyond disk end.
    InvalidOffset,
    // Not Found Inode
    // NotFoundInodeError,
}

struct DataBuf {
    addr: GuestAddress,
    len: usize,
}

// #[derive(Clone)]
pub struct Request<'a> {
    memory: &'a GuestMemory,
    in_header: fuse_in_header,
    in_arg_addr: GuestAddress,
    in_arg_len: u32,
    in_data_buf: Vec<DataBuf>,
    out_header_addr: GuestAddress,
    out_arg_addr: GuestAddress,
    out_data_buf: Vec<DataBuf>,
}

impl<'a> Request<'a> {
    pub fn parse<'k>(
        avail_desc: &DescriptorChain,
        mem: &'k GuestMemory,
    ) -> result::Result<Request<'k>, VtfsError> {
        if avail_desc.is_write_only() {
            return Err(VtfsError::UnexpectedWriteOnlyDescriptor);
        }

        let mut r = Request {
            memory: mem,
            in_header: mem
                .read_obj_from_addr(avail_desc.addr)
                .map_err(|_| VtfsError::InvalidOffset)?,
            in_arg_addr: GuestAddress(0),
            in_arg_len: 0,
            in_data_buf: Vec::new(),
            out_header_addr: GuestAddress(0),
            out_arg_addr: GuestAddress(0),
            out_data_buf: Vec::new(),
        };
        r.check_chain(avail_desc).map(|_| r)
    }

    #[allow(non_upper_case_globals)]
    pub fn execute(&self, fs: &mut FuseBackend) -> Result<u32> {
        let ret = match self.in_header.opcode {
            fuse_opcode_FUSE_INIT => fs.do_init(self),
            fuse_opcode_FUSE_GETATTR => fs.do_getattr(self),
            fuse_opcode_FUSE_LOOKUP => fs.do_lookup(self),
            fuse_opcode_FUSE_OPENDIR => fs.do_opendir(self),
            fuse_opcode_FUSE_READDIR => fs.do_readdir(self),
            fuse_opcode_FUSE_ACCESS => fs.do_access(self),
            fuse_opcode_FUSE_FORGET => fs.do_forget(self),
            fuse_opcode_FUSE_RELEASEDIR => fs.do_releasedir(self),
            fuse_opcode_FUSE_STATFS => fs.do_statfs(self),
            fuse_opcode_FUSE_MKNOD => fs.do_mknod(self),
            fuse_opcode_FUSE_MKDIR => fs.do_mkdir(self),
            fuse_opcode_FUSE_RMDIR => fs.do_rmdir(self),
            fuse_opcode_FUSE_SETATTR => fs.do_setattr(self),
            fuse_opcode_FUSE_UNLINK => fs.do_unlink(self),
            fuse_opcode_FUSE_SYMLINK => fs.do_symlink(self),
            fuse_opcode_FUSE_READLINK => fs.do_readlink(self),
            fuse_opcode_FUSE_LINK => fs.do_link(self),
            fuse_opcode_FUSE_OPEN => fs.do_open(self),
            fuse_opcode_FUSE_READ => fs.do_read(self),
            fuse_opcode_FUSE_WRITE => fs.do_write(self),
            fuse_opcode_FUSE_RELEASE => fs.do_release(self),
            _ => Err(ExecuteError::InvalidMethod),
        };
        error!("FUCK EXEC {:?}", ret);
        ret
    }

    #[allow(non_upper_case_globals)]
    fn check_chain(&mut self, avail_desc: &DescriptorChain) -> result::Result<(), VtfsError> {
        error!("FUCK -------> OPCODE {}", self.in_header.opcode);
        match self.in_header.opcode {
            // only in_header
            fuse_opcode_FUSE_FORGET => {
                self.in_arg_addr = avail_desc
                    .addr
                    .unchecked_add(mem::size_of::<fuse_in_header>());
            }
            // in_header + in_arg + out_header
            fuse_opcode_FUSE_RELEASEDIR
            | fuse_opcode_FUSE_RELEASE
            | fuse_opcode_FUSE_ACCESS
            | fuse_opcode_FUSE_RMDIR
            | fuse_opcode_FUSE_UNLINK => {
                let in_arg_desc = avail_desc
                    .next_descriptor()
                    .ok_or(VtfsError::DescriptorChainTooShort)?;
                self.in_arg_addr = in_arg_desc.addr;
                self.in_arg_len = in_arg_desc.len;

                let out_header_desc = in_arg_desc
                    .next_descriptor()
                    .ok_or(VtfsError::DescriptorChainTooShort)?;
                self.out_header_addr = out_header_desc.addr;
            }
            // in_header + out_header + out_arg
            fuse_opcode_FUSE_STATFS | fuse_opcode_FUSE_READLINK => {
                let out_header_desc = avail_desc
                    .next_descriptor()
                    .ok_or(VtfsError::DescriptorChainTooShort)?;
                self.out_header_addr = out_header_desc.addr;

                let out_arg_desc = out_header_desc
                    .next_descriptor()
                    .ok_or(VtfsError::DescriptorChainTooShort)?;
                self.out_arg_addr = out_arg_desc.addr;
            }

            // in_header + in_arg + out_header + out_data
            fuse_opcode_FUSE_READ => {
                let in_arg_desc = avail_desc
                    .next_descriptor()
                    .ok_or(VtfsError::DescriptorChainTooShort)?;
                let out_header_desc = in_arg_desc
                    .next_descriptor()
                    .ok_or(VtfsError::DescriptorChainTooShort)?;

                self.in_arg_addr = in_arg_desc.addr;
                self.in_arg_len = in_arg_desc.len;
                self.out_header_addr = out_header_desc.addr;
                // self.out_arg_addr = out_arg_desc.addr;

                // error!("FUCK CHECKCHAIN READ {} {} {}", out_arg_desc.is_write_only(), out_arg_desc.has_next(), out_arg_desc.len);

                // let out_arg_desc = out_header_desc
                //     .next_descriptor()
                //     .ok_or(VtfsError::DescriptorChainTooShort)?;

                let mut aaa = out_header_desc;
                while aaa.has_next() {
                    aaa = aaa.next_descriptor().unwrap();
                    error!("FUCK CHECKCHAIN READ NEXT {} {}", aaa.has_next(), aaa.len);
                    self.out_data_buf.push(DataBuf {
                        addr: aaa.addr,
                        len: aaa.len as usize,
                    });
                }
            }

            // in_header + in_arg + in_data + out_header + out_arg
            fuse_opcode_FUSE_WRITE => {
                let in_arg_desc = avail_desc
                    .next_descriptor()
                    .ok_or(VtfsError::DescriptorChainTooShort)?;

                self.in_arg_addr = in_arg_desc.addr;

                let mut aaa = in_arg_desc
                    .next_descriptor()
                    .ok_or(VtfsError::DescriptorChainTooShort)?;;
                while !aaa.is_write_only() {
                    error!(
                        "FUCK CHECKCHAIN WRITE---- NEXT {} {} {}",
                        aaa.has_next(),
                        aaa.len,
                        aaa.is_write_only()
                    );
                    self.in_data_buf.push(DataBuf {
                        addr: aaa.addr,
                        len: aaa.len as usize,
                    });
                    aaa = aaa.next_descriptor().unwrap();
                }

                self.out_header_addr = aaa.addr;

                let out_arg_desc = aaa
                    .next_descriptor()
                    .ok_or(VtfsError::DescriptorChainTooShort)?;

                self.out_arg_addr = out_arg_desc.addr;
            }

            // in_header + in_arg + out_header + out_arg
            _ => {
                let in_arg_desc = avail_desc
                    .next_descriptor()
                    .ok_or(VtfsError::DescriptorChainTooShort)?;
                let out_header_desc = in_arg_desc
                    .next_descriptor()
                    .ok_or(VtfsError::DescriptorChainTooShort)?;

                let out_arg_desc = out_header_desc
                    .next_descriptor()
                    .ok_or(VtfsError::DescriptorChainTooShort)?;

                self.in_arg_addr = in_arg_desc.addr;
                self.in_arg_len = in_arg_desc.len;
                self.out_header_addr = out_header_desc.addr;
                self.out_arg_addr = out_arg_desc.addr;
            }
        }

        Ok(())
    }

    fn send_arg<T: memory_model::DataInit>(&self, arg: T) -> u32 {
        let our_header = fuse_out_header {
            len: (mem::size_of::<fuse_out_header>() + mem::size_of::<T>()) as u32,
            error: 0,
            unique: self.in_header.unique,
        };

        // We use unwrap because the request parsing process already checked that the
        // addr was valid.
        self.memory
            .write_obj_at_addr(our_header, self.out_header_addr)
            .unwrap();
        self.memory
            .write_obj_at_addr(arg, self.out_arg_addr)
            .unwrap();

        our_header.len
    }

    fn send_slice(&self, buf: &[u8]) -> u32 {
        let our_header = fuse_out_header {
            len: (mem::size_of::<fuse_out_header>() + buf.len()) as u32,
            error: 0,
            unique: self.in_header.unique,
        };

        // We use unwrap because the request parsing process already checked that the
        // addr was valid.
        self.memory
            .write_obj_at_addr(our_header, self.out_header_addr)
            .unwrap();
        self.memory
            .write_slice_at_addr(buf, self.out_arg_addr)
            .unwrap();

        our_header.len
    }

    fn send_data<F: std::io::Read>(&self, src: &mut F) -> u32 {
        let mut read_size = 0;
        for buf in self.out_data_buf.iter() {
            let aaa = self
                .memory
                .read_to_memory_inexact(buf.addr, src, buf.len)
                .unwrap();
            error!("FUCK SENDDATA {:?} {} {}", buf.addr, buf.len, aaa);
            if aaa == 0 {
                break;
            }
            read_size += aaa;
        }

        let our_header = fuse_out_header {
            len: (mem::size_of::<fuse_out_header>() + read_size) as u32,
            error: 0,
            unique: self.in_header.unique,
        };

        // We use unwrap because the request parsing process already checked that the
        // addr was valid.
        self.memory
            .write_obj_at_addr(our_header, self.out_header_addr)
            .unwrap();

        our_header.len
    }

    fn write_data<F: std::io::Write>(&self, dst: &mut F) -> u32 {
        let mut write_size = 0;
        for buf in self.in_data_buf.iter() {
            let aaa = self
                .memory
                .write_from_memory_inexact(buf.addr, dst, buf.len)
                .unwrap();
            error!("FUCK SENDDATA {:?} {} {}", buf.addr, buf.len, aaa);
            write_size += aaa;
            if aaa != buf.len {
                break;
            }
        }

        write_size as u32
    }

    // fn send_header(&self, body_len: u32) -> u32 {
    //     let our_header = fuse_out_header {
    //         len: (mem::size_of::<fuse_out_header>() ) as u32 + body_len,
    //         error: 0,
    //         unique: self.in_header.unique,
    //     };

    //     // We use unwrap because the request parsing process already checked that the
    //     // addr was valid.
    //     self.memory
    //         .write_obj_at_addr(our_header, self.out_header_addr)
    //         .unwrap();

    //     our_header.len
    // }

    fn send_dirent_vec(&self, arg: Vec<FuseDirent>) -> u32 {
        let mut arg_len = 0;
        for entry in arg.iter() {
            arg_len += entry.aligned_size();
        }

        let our_header = fuse_out_header {
            len: (mem::size_of::<fuse_out_header>() + arg_len) as u32,
            error: 0,
            unique: self.in_header.unique,
        };

        // We use unwrap because the request parsing process already checked that the
        // addr was valid.
        self.memory
            .write_obj_at_addr(our_header, self.out_header_addr)
            .unwrap();
        let mut dirent_addr = self.out_arg_addr;
        for element in arg.iter() {
            element.write_to_memory(self.memory, dirent_addr);
            dirent_addr = dirent_addr.unchecked_add(element.aligned_size());
        }

        our_header.len
    }

    pub fn send_err(&self, err: i32) -> u32 {
        let our_header = fuse_out_header {
            len: (mem::size_of::<fuse_out_header>()) as u32,
            error: -err,
            unique: self.in_header.unique,
        };

        // We use unwrap because the request parsing process already checked that the
        // addr was valid.
        self.memory
            .write_obj_at_addr(our_header, self.out_header_addr)
            .unwrap();

        our_header.len
    }
}

#[derive(Debug)]
struct InodeHandler {
    fd: Fd,
    host_inode: HostInode,
    nlookup: u64,
}

impl InodeHandler {
    fn new(path: &str) -> Option<InodeHandler> {
        let oflag = libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_RDONLY;
        let name = CString::new(path).ok()?;
        let fd = Fd::open(&name, oflag).ok()?;
        let at_flag = libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW;
        let filestat = fd.fstatat(None, at_flag).ok()?;

        Some(InodeHandler {
            fd: fd,
            host_inode: HostInode {
                st_dev: filestat.st_dev,
                st_ino: filestat.st_ino,
            },
            nlookup: 0,
        })
    }

    fn lookup(&self, path: &CStr) -> Result<InodeHandler> {
        let oflag = libc::O_PATH | libc::O_NOFOLLOW;
        let new_fd = self.fd.openat(Some(path), oflag)?;

        let at_flag = libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW;
        let filestat = new_fd.fstatat(None, at_flag)?;

        Ok(InodeHandler {
            fd: new_fd,
            host_inode: HostInode {
                st_dev: filestat.st_dev,
                st_ino: filestat.st_ino,
            },
            nlookup: 0,
        })
    }

    fn inc_nlookup(&mut self, delta: u64) {
        self.nlookup += delta;
    }

    fn dec_nlookup(&mut self, delta: u64) {
        debug_assert!(self.nlookup >= delta);
        self.nlookup -= delta;
    }

    fn nlookup_zero(&self) -> bool {
        self.nlookup <= 0
    }

    fn metadata(&self) -> Result<FileStat> {
        let at_flag = libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW;
        self.fd
            .fstatat(None, at_flag)
            .map_err(|e| ExecuteError::from(e))
    }

    fn opendir(&self) -> Result<Dir> {
        let oflg = libc::O_RDONLY;
        Dir::openat222(&self.fd, None, oflg).map_err(|e| ExecuteError::from(e))
    }

    fn fstatvfs(&self) -> Result<Statvfs> {
        self.fd.fstatvfs().map_err(|e| ExecuteError::from(e))
    }

    fn mknod(&self, name: &CStr, mode: mode_t, dev: dev_t) -> Result<()> {
        self.fd
            .mknodat(name, mode, dev)
            .map_err(|e| ExecuteError::from(e))
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
struct HostInode {
    st_dev: u64,
    st_ino: u64,
}

#[derive(Debug, Default)]
struct InodeMap {
    ino_map: HashMap<u64, InodeHandler>,
    attr_map: HashMap<HostInode, u64>,
    next_key: u64,
}

impl InodeMap {
    fn new(start_key: u64) -> InodeMap {
        InodeMap {
            next_key: start_key,
            ino_map: HashMap::default(),
            attr_map: HashMap::default(),
        }
    }
    fn add(&mut self, v: InodeHandler) -> u64 {
        let ino = self.next_key;
        self.next_key += 1;

        // let id = v.id();
        let host_inode = v.host_inode;
        self.ino_map.insert(ino, v);
        self.attr_map.insert(host_inode, ino);
        ino
    }

    fn remove(&mut self, ino: u64) {
        // if let Some(aaaa) = self.ino_map.get(&ino) {
        //     self.attr_map.remove(&aaaa.host_inode);
        // }
        self.ino_map.remove(&ino);
    }

    // TO DO: not necessary ?
    fn identify(&mut self, inode: InodeHandler) -> u64 {
        match self.attr_map.get(&inode.host_inode) {
            Some(ino) => *ino,
            None => self.add(inode),
        }
    }

    fn lookup333(&mut self, inode: InodeHandler) -> u64 {
        match self.attr_map.get(&inode.host_inode) {
            None => self.add(inode),
            Some(&ino) => {
                self.ino_map.entry(ino).or_insert(inode);
                ino
            }
        }
    }

    fn id22222(&self, inode: &InodeHandler) -> Option<u64> {
        self.attr_map.get(&inode.host_inode).map(|i| *i)
    }

    fn get(&self, ino: u64) -> Result<&InodeHandler> {
        self.ino_map.get(&ino).ok_or(ExecuteError::UnknownHandle)
    }

    fn get222(&mut self, ino: u64) -> Result<&mut InodeHandler> {
        self.ino_map
            .get_mut(&ino)
            .ok_or(ExecuteError::UnknownHandle)
    }

    fn inc_nlookup(&mut self, ino: u64, delta: u64) {
        self.ino_map.entry(ino).and_modify(|e| e.nlookup += delta);
    }
}

// struct Handler {
//     fd: Fd,
//     sn: u64,
// }

// struct HandlerMap {
//     map: HashMap<u64, Handler>,
//     next_key: u64,
// }

// impl HandlerMap {
//     fn new(start_key: u64) -> HandlerMap {
//         HandlerMap {
//             map: HashMap::default(),
//             next_key: start_key,
//         }
//     }

//     fn insert(&mut self, v: Fd) -> u64 {
//         let key = self.next_key;
//         self.next_key += 1;

//         let value = Handler { fd: v, sn: key };

//         self.map.insert(key, value);
//         key
//     }

//     fn remove(&mut self, key: u64) {
//         self.map.remove(&key);
//     }

//     fn get(&self, key: u64) -> Result<&Handler> {
//         self.map.get(&key).ok_or(ExecuteError::UnknownHandle)
//     }

//     fn get_mut(&mut self, key: u64) -> Result<&mut Handler> {
//         self.map.get_mut(&key).ok_or(ExecuteError::UnknownHandle)
//     }
// }

struct HandlerMap222<T: FdNum> {
    map: HashMap<u64, T>,
}

impl<T> HandlerMap222<T>
where
    T: FdNum,
{
    fn new() -> Self {
        HandlerMap222 {
            map: HashMap::default(),
        }
    }

    fn insert(&mut self, value: T) -> u64 {
        let key = value.fd_num();
        self.map.insert(key, value);
        key
    }

    fn remove(&mut self, key: u64) {
        self.map.remove(&key);
    }

    fn get(&self, key: u64) -> Result<&T> {
        self.map.get(&key).ok_or(ExecuteError::UnknownHandle)
    }

    fn get_mut(&mut self, key: u64) -> Result<&mut T> {
        self.map.get_mut(&key).ok_or(ExecuteError::UnknownHandle)
    }
}

// struct FDMap<V> {
//     map: HashMap<u64, V>,
//     next_key: u64,
// }

// impl<V> FDMap<V> {
//     fn new(start_key: u64) -> FDMap<V> {
//         FDMap {
//             map: HashMap::default(),
//             next_key: start_key,
//         }
//     }

//     fn insert(&mut self, value: V) -> u64 {
//         let key = self.next_key;
//         self.next_key += 1;

//         self.map.insert(key, value);
//         key
//     }

//     fn remove(&mut self, key: u64) {
//         self.map.remove(&key);
//     }

//     fn get(&self, key: u64) -> Result<&V> {
//         self.map.get(&key).ok_or(ExecuteError::UnknownHandle)
//     }

//     fn get_mut(&mut self, key: u64) -> Result<&mut V> {
//         self.map.get_mut(&key).ok_or(ExecuteError::UnknownHandle)
//     }
// }

#[derive(Debug)]
enum Handler<'a> {
    Fd(&'a Fd),
    Inode(&'a InodeHandler),
}

pub struct FuseBackend {
    dir_map: HandlerMap222<Dir>,
    fd_map: HandlerMap222<Fd>,
    ino_map: InodeMap,
}

impl FuseBackend {
    pub fn new(fs_path: &str) -> Option<FuseBackend> {
        let mut ino_map = InodeMap::new(1);
        let root_inode = InodeHandler::new(fs_path)?;
        ino_map.add(root_inode);

        Some(FuseBackend {
            dir_map: HandlerMap222::new(),
            fd_map: HandlerMap222::new(),
            ino_map: ino_map,
        })
    }

    pub fn do_init(&self, request: &Request) -> Result<u32> {
        let guest_mem = request.memory;
        let in_arg: fuse_init_in = guest_mem.read_obj_from_addr(request.in_arg_addr)?;

        unsafe {
            libc::umask(0);
        }

        let mut out_arg = fuse_init_out::default();
        out_arg.major = FUSE_KERNEL_VERSION;
        out_arg.minor = FUSE_KERNEL_MINOR_VERSION;
        out_arg.max_readahead = in_arg.max_readahead;
        out_arg.flags = in_arg.flags & FUSE_INIT_FLAGS;
        out_arg.max_background = FUSE_DEFAULT_MAX_BACKGROUND;
        out_arg.congestion_threshold = FUSE_DEFAULT_CONGESTION_THRESHOLD;
        out_arg.max_write = FUSE_MAX_WRITE_SIZE as u32;
        out_arg.max_pages = 10;

        Ok(request.send_arg(out_arg))
    }

    pub fn do_getattr(&self, request: &Request) -> Result<u32> {
        let guest_mem = request.memory;
        let in_arg: fuse_getattr_in = guest_mem.read_obj_from_addr(request.in_arg_addr)?;

        let out_arg = match in_arg.getattr_flags {
            0 => {
                let inode = self.ino_map.get(request.in_header.nodeid)?;
                self.get_ino_fuse_attr(inode)?
            }
            _ => {
                let fh = self.fd_map.get(in_arg.fh)?;
                self.get_fh_fuse_attr(fh)?
            }
        };

        // error!("FUCK GETATTR 111 {:?}", inode);

        // let inode = self.ino_map.get(ino)?;
        // let out_arg = self.get_ino_fuse_attr(inode)?;

        error!("FUCK GETATTR {:?}", out_arg.attr);

        Ok(request.send_arg(out_arg))
    }

    pub fn do_forget(&mut self, request: &Request) -> Result<u32> {
        let guest_mem = request.memory;
        let in_arg: fuse_forget_in = guest_mem.read_obj_from_addr(request.in_arg_addr)?;
        error!(
            "FUCK FORGET {} {}",
            request.in_header.nodeid, in_arg.nlookup
        );

        let inh = self.ino_map.get222(request.in_header.nodeid)?;
        inh.dec_nlookup(in_arg.nlookup);
        if inh.nlookup_zero() {
            error!("FUCK FORGET REMOVE {}", request.in_header.nodeid);
            self.ino_map.remove(request.in_header.nodeid);
        }

        Ok(0)
    }

    pub fn do_lookup(&mut self, request: &Request) -> Result<u32> {
        let guest_mem = request.memory;
        let mut buf = vec![0u8; request.in_arg_len as usize];

        guest_mem.read_slice_at_addr(&mut buf, request.in_arg_addr)?;

        let name = CStr::from_bytes_with_nul(&buf)?;

        let ino = request.in_header.nodeid;

        
        let ino_fd222 = self.ino_map.get(ino)?;
        
        let new_fd222 = ino_fd222.lookup(name)?;
        error!("FUCK LOOKUP {} {:?} {:?} {}", ino, name, ino_fd222, new_fd222.fd.fd_num());

        let cached_ino = self.ino_map.lookup333(new_fd222);
        error!("FUCK LOOKUP 22222 {}", cached_ino);

        let used_fd = self.ino_map.get222(cached_ino)?;

        error!("FUCK LOOKUP 33333 {}", used_fd.nlookup);

        let filestat = used_fd.metadata()?;

        let attr = fuse_attr {
            ino: cached_ino,
            size: filestat.st_size as u64,
            blocks: filestat.st_size as u64,
            atime: filestat.st_atime as u64,
            mtime: filestat.st_mtime as u64,
            ctime: filestat.st_ctime as u64,
            atimensec: filestat.st_atime_nsec as u32,
            mtimensec: filestat.st_mtime_nsec as u32,
            ctimensec: filestat.st_ctime_nsec as u32,
            mode: filestat.st_mode,
            nlink: filestat.st_nlink as u32,
            uid: filestat.st_uid,
            gid: filestat.st_gid,
            rdev: filestat.st_rdev as u32,
            blksize: filestat.st_blksize as u32,
            padding: 0,
        };

        let out_arg = fuse_entry_out {
            nodeid: attr.ino,
            generation: 0,
            entry_valid: 0,
            attr_valid: 0,
            entry_valid_nsec: 0,
            attr_valid_nsec: 0,
            attr: attr,
        };

        used_fd.inc_nlookup(1);

        error!("FUCK LOOKUP 22222 {} {}", cached_ino, used_fd.fd.fd_num());

        Ok(request.send_arg(out_arg))
    }

    pub fn do_readdir(&mut self, request: &Request) -> Result<u32> {
        let guest_mem = request.memory;
        let in_arg: fuse_read_in = guest_mem.read_obj_from_addr(request.in_arg_addr)?;

        let ddddd = self.dir_map.get_mut(in_arg.fh)?;
        let mut out_arg = Vec::new();
        for (i, entry) in ddddd.iter().enumerate().skip(in_arg.offset as usize) {
            let entry = entry?;
            out_arg.push(FuseDirent {
                offset: i as u64 + 1,
                entry: entry,
            });
        }

        Ok(request.send_dirent_vec(out_arg))
    }

    pub fn do_opendir(&mut self, request: &Request) -> Result<u32> {
        let ino = request.in_header.nodeid;
        let ino_fd = self.ino_map.get(ino)?;

        let dddd = ino_fd.opendir()?;

        let fh = self.dir_map.insert(dddd);

        let out_arg = fuse_open_out {
            fh: fh,
            open_flags: 0,
            padding: 0,
        };
        error!("FUCK OPENDIR {:?}", out_arg);
        Ok(request.send_arg(out_arg))
    }

    pub fn do_releasedir(&mut self, request: &Request) -> Result<u32> {
        let guest_mem = request.memory;
        let in_arg: fuse_release_in = guest_mem.read_obj_from_addr(request.in_arg_addr)?;

        let fh = in_arg.fh;
        self.dir_map.remove(fh);

        Ok(request.send_err(0))
    }

    pub fn do_statfs(&mut self, request: &Request) -> Result<u32> {
        let ino = request.in_header.nodeid;
        let ino_fd = self.ino_map.get(ino)?;

        let stat = ino_fd.fstatvfs()?;

        let out_arg = fuse_statfs_out {
            st: fuse_kstatfs {
                blocks: stat.f_blocks as u64,
                bfree: stat.f_bfree as u64,
                bavail: stat.f_bavail as u64,
                files: stat.f_files as u64,
                ffree: stat.f_ffree as u64,
                bsize: stat.f_bsize as u32,
                namelen: stat.f_namemax as u32,
                frsize: stat.f_frsize as u32,
                ..fuse_kstatfs::default()
            },
        };

        Ok(request.send_arg(out_arg))
    }

    pub fn do_access(&mut self, request: &Request) -> Result<u32> {
        Ok(request.send_err(libc::ENOSYS))
    }

    pub fn do_mknod(&mut self, request: &Request) -> Result<u32> {
        let guest_mem = request.memory;
        let in_arg: fuse_mknod_in = guest_mem.read_obj_from_addr(request.in_arg_addr)?;

        let pos = request.in_arg_addr.unchecked_add(mem::size_of_val(&in_arg));
        let name_len = request.in_arg_len as usize - mem::size_of_val(&in_arg);

        let mut buf = vec![0u8; name_len];

        guest_mem.read_slice_at_addr(&mut buf, pos)?;
        buf[name_len - 1] = 0u8;
        let name = CStr::from_bytes_with_nul(&buf)?;

        let ino_fd = self.ino_map.get(request.in_header.nodeid)?;

        error!("FUCK --MKNOD-- {:?} ", in_arg);

        ino_fd.mknod(name, in_arg.mode, in_arg.rdev as dev_t)?;

        let new_fd = ino_fd.lookup(name)?;
        let out_arg = self.cccc(&request.in_header, new_fd)?;
        let ino = out_arg.attr.ino;
        self.ino_map.inc_nlookup(ino, 1);
        Ok(request.send_arg(out_arg))
    }

    fn gen_ino_attr(&mut self, new_fd: InodeHandler) -> Result<fuse_entry_out> {
        let filestat = new_fd.metadata()?;
        let cached_ino = self.ino_map.identify(new_fd);

        let attr = fuse_attr {
            ino: cached_ino,
            size: filestat.st_size as u64,
            blocks: filestat.st_size as u64,
            atime: filestat.st_atime as u64,
            mtime: filestat.st_mtime as u64,
            ctime: filestat.st_ctime as u64,
            atimensec: filestat.st_atime_nsec as u32,
            mtimensec: filestat.st_mtime_nsec as u32,
            ctimensec: filestat.st_ctime_nsec as u32,
            mode: filestat.st_mode,
            nlink: filestat.st_nlink as u32,
            uid: filestat.st_uid,
            gid: filestat.st_gid,
            rdev: filestat.st_rdev as u32,
            blksize: filestat.st_blksize as u32,
            padding: 0,
        };

        Ok(fuse_entry_out {
            nodeid: attr.ino,
            generation: 0,
            entry_valid: 0,
            attr_valid: 0,
            entry_valid_nsec: 0,
            attr_valid_nsec: 0,
            attr: attr,
        })
    }

    fn get_ino_attr(&self, fd: &InodeHandler) -> Result<fuse_entry_out> {
        let filestat = fd.metadata()?;
        let cached_ino = self
            .ino_map
            .id22222(fd)
            .ok_or(ExecuteError::UnknownHandle)?;

        let attr = fuse_attr {
            ino: cached_ino,
            size: filestat.st_size as u64,
            blocks: filestat.st_size as u64,
            atime: filestat.st_atime as u64,
            mtime: filestat.st_mtime as u64,
            ctime: filestat.st_ctime as u64,
            atimensec: filestat.st_atime_nsec as u32,
            mtimensec: filestat.st_mtime_nsec as u32,
            ctimensec: filestat.st_ctime_nsec as u32,
            mode: filestat.st_mode,
            nlink: filestat.st_nlink as u32,
            uid: filestat.st_uid,
            gid: filestat.st_gid,
            rdev: filestat.st_rdev as u32,
            blksize: filestat.st_blksize as u32,
            padding: 0,
        };

        Ok(fuse_entry_out {
            nodeid: attr.ino,
            generation: 0,
            entry_valid: 0,
            attr_valid: 0,
            entry_valid_nsec: 0,
            attr_valid_nsec: 0,
            attr: attr,
        })
    }

    fn get_ino_fuse_attr(&self, fd: &InodeHandler) -> Result<fuse_attr_out> {
        println!("FUSE ATTR {:?}", fd);
        let filestat = fd.metadata()?;
        println!("ANSWER {:?}", filestat.st_ino);
        let cached_ino = self
            .ino_map
            .id22222(fd)
            .ok_or(ExecuteError::UnknownHandle)?;

        let attr = fuse_attr {
            ino: cached_ino,
            size: filestat.st_size as u64,
            blocks: filestat.st_size as u64,
            atime: filestat.st_atime as u64,
            mtime: filestat.st_mtime as u64,
            ctime: filestat.st_ctime as u64,
            atimensec: filestat.st_atime_nsec as u32,
            mtimensec: filestat.st_mtime_nsec as u32,
            ctimensec: filestat.st_ctime_nsec as u32,
            mode: filestat.st_mode,
            nlink: filestat.st_nlink as u32,
            uid: filestat.st_uid,
            gid: filestat.st_gid,
            rdev: filestat.st_rdev as u32,
            blksize: filestat.st_blksize as u32,
            padding: 0,
        };

        Ok(fuse_attr_out {
            attr_valid: 0,
            attr_valid_nsec: 0,
            dummy: 0,
            attr: attr,
        })
    }

    fn get_fh_fuse_attr(&self, fh: &Fd) -> Result<fuse_attr_out> {
        println!("FUSE FHHHHH ATTR {:?}", fh);
        let filestat = fh
            .fstatat(None, libc::AT_EMPTY_PATH)
            .map_err(|e| ExecuteError::from(e))?;
        println!("ANSWER {:?}", filestat.st_ino);
        // let cached_ino = fh.sn;

        let attr = fuse_attr {
            ino: fh.fd_num(),
            size: filestat.st_size as u64,
            blocks: filestat.st_size as u64,
            atime: filestat.st_atime as u64,
            mtime: filestat.st_mtime as u64,
            ctime: filestat.st_ctime as u64,
            atimensec: filestat.st_atime_nsec as u32,
            mtimensec: filestat.st_mtime_nsec as u32,
            ctimensec: filestat.st_ctime_nsec as u32,
            mode: filestat.st_mode,
            nlink: filestat.st_nlink as u32,
            uid: filestat.st_uid,
            gid: filestat.st_gid,
            rdev: filestat.st_rdev as u32,
            blksize: filestat.st_blksize as u32,
            padding: 0,
        };

        Ok(fuse_attr_out {
            attr_valid: 0,
            attr_valid_nsec: 0,
            dummy: 0,
            attr: attr,
        })
    }

    // fn get_fh_fuse_attr(&self, fh: &Handler) -> Result<fuse_attr_out> {
    //     println!("FUSE FHHHHH ATTR {:?}", fh.fd);
    //     let filestat = fh
    //         .fd
    //         .fstatat(None, libc::AT_EMPTY_PATH)
    //         .map_err(|e| ExecuteError::from(e))?;
    //     println!("ANSWER {:?}", filestat.st_ino);
    //     let cached_ino = fh.sn;

    //     let attr = fuse_attr {
    //         ino: cached_ino,
    //         size: filestat.st_size as u64,
    //         blocks: filestat.st_size as u64,
    //         atime: filestat.st_atime as u64,
    //         mtime: filestat.st_mtime as u64,
    //         ctime: filestat.st_ctime as u64,
    //         atimensec: filestat.st_atime_nsec as u32,
    //         mtimensec: filestat.st_mtime_nsec as u32,
    //         ctimensec: filestat.st_ctime_nsec as u32,
    //         mode: filestat.st_mode,
    //         nlink: filestat.st_nlink as u32,
    //         uid: filestat.st_uid,
    //         gid: filestat.st_gid,
    //         rdev: filestat.st_rdev as u32,
    //         blksize: filestat.st_blksize as u32,
    //         padding: 0,
    //     };

    //     Ok(fuse_attr_out {
    //         attr_valid: 0,
    //         attr_valid_nsec: 0,
    //         dummy: 0,
    //         attr: attr,
    //     })
    // }

    fn adjust_cred(req: &fuse_in_header, new_fd: &InodeHandler) -> Result<()> {
        let (uid, gid) = (req.uid, req.gid);
        if uid == 0 && gid == 0 {
            return Ok(());
        }
        new_fd.fd.fchown(uid, gid).map_err(|e| {
            let _ = new_fd.fd.unlinkat(None, libc::AT_REMOVEDIR);
            ExecuteError::from(e)
        })
    }

    fn cccc(&mut self, req: &fuse_in_header, new_fd: InodeHandler) -> Result<fuse_entry_out> {
        Self::adjust_cred(req, &new_fd)?;

        self.gen_ino_attr(new_fd)
    }

    pub fn do_mkdir(&mut self, request: &Request) -> Result<u32> {
        let guest_mem = request.memory;
        let in_arg: fuse_mkdir_in = guest_mem.read_obj_from_addr(request.in_arg_addr)?;

        let name_len = request.in_arg_len as usize - mem::size_of_val(&in_arg);

        let mut buf = vec![0u8; name_len];

        let pos = request.in_arg_addr.unchecked_add(mem::size_of_val(&in_arg));
        guest_mem.read_slice_at_addr(&mut buf, pos)?;
        let name = CStr::from_bytes_with_nul(&buf)?;

        let mode = in_arg.mode | libc::S_IFDIR;

        let ino_fd = self.ino_map.get(request.in_header.nodeid)?;
        ino_fd.fd.mkdirat(name, mode)?;
        let new_fd = ino_fd.lookup(name)?;
        let out_arg = self.cccc(&request.in_header, new_fd)?;

        let ino = out_arg.attr.ino;
        self.ino_map.inc_nlookup(ino, 1);

        Ok(request.send_arg(out_arg))
    }

    pub fn do_rmdir(&mut self, request: &Request) -> Result<u32> {
        let guest_mem = request.memory;
        let mut buf = vec![0u8; request.in_arg_len as usize];

        guest_mem.read_slice_at_addr(&mut buf, request.in_arg_addr)?;

        let name = CStr::from_bytes_with_nul(&buf)?;

        let ino = request.in_header.nodeid;
        let ino_fd = self.ino_map.get(ino)?;

        ino_fd.fd.unlinkat(Some(name), libc::AT_REMOVEDIR)?;

        // self.ino_map.remove(ino);
        Ok(request.send_err(0))
    }

    pub fn do_setattr(&mut self, request: &Request) -> Result<u32> {
        let guest_mem = request.memory;
        let in_arg: fuse_setattr_in = guest_mem.read_obj_from_addr(request.in_arg_addr)?;

        let valid = in_arg.valid;
        // TODO: FATTR_FH
        // in_arg.valid | FATTR_FH

        let ino = request.in_header.nodeid;
        // let ino_fd = self.ino_map.get(ino)?;

        // let fdh = if bit_intersect(valid, FATTR_FH) {
        //     self.fd_map.get(in_arg.fh)?
        // } else {
        //     &self.ino_map.get(ino)?.fd
        // };

        error!(
            "FUCK SETATTR {:?} {}",
            in_arg,
            bit_intersect(valid, FATTR_FH)
        );
        error!("FUCK SETATTR {:?} ", self.ino_map);
        let hdl = if bit_intersect(valid, FATTR_FH) {
            Handler::Fd(self.fd_map.get(in_arg.fh)?)
        } else {
            Handler::Inode(self.ino_map.get(ino)?)
        };

        error!("FUCK SETATTR HDL {:?}", hdl);

        if bit_intersect(valid, FATTR_MODE) {
            error!("FUCK SETATTR  MODE {:?}", hdl);

            match hdl {
                Handler::Fd(fd) => fd.fchmod(in_arg.mode)?,
                Handler::Inode(inh) => inh.fd.fchmod(in_arg.mode)?,
            }
        }

        if bit_intersect(valid, FATTR_UID | FATTR_GID) {
            error!("FUCK SETATTR  UIDGID {:?}", hdl);

            let uid: uid_t = if bit_intersect(valid, FATTR_UID) {
                in_arg.uid
            } else {
                std::u32::MAX
            };

            let gid: gid_t = if bit_intersect(valid, FATTR_GID) {
                in_arg.gid
            } else {
                std::u32::MAX
            };

            match hdl {
                Handler::Fd(fd) => fd.fchown(uid, gid)?,
                Handler::Inode(inh) => inh.fd.fchown(uid, gid)?,
            }
        }

        if bit_intersect(valid, FATTR_SIZE) {
            error!("FUCK SETATTR  SIZE {:?}", hdl);

            let size = in_arg.size as libc::off_t;
            match hdl {
                Handler::Fd(fd) => fd.ftruncate(size)?,
                Handler::Inode(inh) => {
                    let new_fd = inh.fd.reopen(libc::O_RDWR)?;
                    new_fd.ftruncate(size)?
                }
            }
        }

        if bit_intersect(valid, FATTR_ATIME | FATTR_MTIME) {
            let mut tv: [libc::timespec; 2] = [libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            }; 2];

            if bit_intersect(valid, FATTR_ATIME_NOW) {
                tv[0].tv_nsec = libc::UTIME_NOW;
            } else if bit_intersect(valid, FATTR_ATIME) {
                tv[0].tv_sec = in_arg.atime as libc::time_t;
                tv[0].tv_nsec = in_arg.atimensec as libc::c_long;
            }

            if bit_intersect(valid, FATTR_MTIME_NOW) {
                tv[1].tv_nsec = libc::UTIME_NOW;
            } else if bit_intersect(valid, FATTR_MTIME) {
                tv[1].tv_sec = in_arg.mtime as libc::time_t;
                tv[1].tv_nsec = in_arg.mtimensec as libc::c_long;
            }

            error!(
                "FUCK SETATTR  TIME  {:?} {} {} {} {}",
                hdl, tv[0].tv_sec, tv[0].tv_nsec, tv[1].tv_sec, tv[1].tv_nsec
            );
            match hdl {
                Handler::Fd(fd) => {
                    fd.futimens(&tv[0])?;
                }
                Handler::Inode(inh) => {
                    let new_fd = inh.fd.reopen(0)?;
                    new_fd.futimens(&tv[0])?;
                }
            }
        }

        let out_arg = match hdl {
            Handler::Fd(fd) => self.get_fh_fuse_attr(fd),
            Handler::Inode(inh) => self.get_ino_fuse_attr(inh),
        }?;

        // let filestat = ino_fd.metadata()?;

        // let attr = fuse_attr {
        //     ino: ino,
        //     size: filestat.st_size as u64,
        //     blocks: filestat.st_size as u64,
        //     atime: filestat.st_atime as u64,
        //     mtime: filestat.st_mtime as u64,
        //     ctime: filestat.st_ctime as u64,
        //     atimensec: filestat.st_atime_nsec as u32,
        //     mtimensec: filestat.st_mtime_nsec as u32,
        //     ctimensec: filestat.st_ctime_nsec as u32,
        //     mode: filestat.st_mode,
        //     nlink: filestat.st_nlink as u32,
        //     uid: filestat.st_uid,
        //     gid: filestat.st_gid,
        //     rdev: filestat.st_rdev as u32,
        //     blksize: filestat.st_blksize as u32,
        //     padding: 0,
        // };

        // let out_arg = fuse_attr_out {
        //     attr_valid: 0,
        //     attr_valid_nsec: 0,
        //     dummy: 0,
        //     attr: attr,
        // };

        Ok(request.send_arg(out_arg))
    }

    pub fn do_unlink(&mut self, request: &Request) -> Result<u32> {
        let guest_mem = request.memory;
        let mut buf = vec![0u8; request.in_arg_len as usize];

        guest_mem.read_slice_at_addr(&mut buf, request.in_arg_addr)?;

        let name = CStr::from_bytes_with_nul(&buf)?;

        let ino = request.in_header.nodeid;
        let ino_fd = self.ino_map.get(ino)?;

        ino_fd.fd.unlinkat(Some(name), 0)?;

        Ok(request.send_err(0))
    }

    pub fn do_symlink(&mut self, request: &Request) -> Result<u32> {
        let guest_mem = request.memory;
        let mut buf = vec![0u8; request.in_arg_len as usize];
        guest_mem.read_slice_at_addr(&mut buf, request.in_arg_addr)?;

        let (name_c, link_c) = get_c_string_slice(&buf);
        let name = CStr::from_bytes_with_nul(&name_c)?;
        let link = CStr::from_bytes_with_nul(&link_c)?;

        let ino_fd = self.ino_map.get(request.in_header.nodeid)?;

        ino_fd.fd.symlinkat(name, link)?;

        let new_fd = ino_fd.lookup(name)?;
        let out_arg = self.cccc(&request.in_header, new_fd)?;

        let ino = out_arg.attr.ino;
        self.ino_map.inc_nlookup(ino, 1);

        Ok(request.send_arg(out_arg))
    }

    pub fn do_readlink(&mut self, request: &Request) -> Result<u32> {
        let ino = request.in_header.nodeid;
        let ino_fd = self.ino_map.get(ino)?;

        let link = ino_fd.fd.readlinkat(None)?;
        Ok(request.send_slice(link.as_bytes_with_nul()))
    }

    pub fn do_link(&mut self, request: &Request) -> Result<u32> {
        let guest_mem = request.memory;
        let in_arg: fuse_link_in = guest_mem.read_obj_from_addr(request.in_arg_addr)?;

        let name_len = request.in_arg_len as usize - mem::size_of_val(&in_arg);
        let mut buf = vec![0u8; name_len];
        let pos = request.in_arg_addr.unchecked_add(mem::size_of_val(&in_arg));
        guest_mem.read_slice_at_addr(&mut buf, pos)?;
        let name = CStr::from_bytes_with_nul(&buf)?;

        let ino_fd = self.ino_map.get(request.in_header.nodeid)?;

        let old_fd = self.ino_map.get(in_arg.oldnodeid)?;

        old_fd
            .fd
            .linkat(None, &ino_fd.fd, name, libc::AT_EMPTY_PATH)?;

        let out_arg = self.get_ino_attr(old_fd)?;

        self.ino_map.inc_nlookup(in_arg.oldnodeid, 1);

        Ok(request.send_arg(out_arg))
        // Ok(0)
    }

    pub fn do_open(&mut self, request: &Request) -> Result<u32> {
        let guest_mem = request.memory;
        let in_arg: fuse_open_in = guest_mem.read_obj_from_addr(request.in_arg_addr)?;

        let ino_fd = self.ino_map.get(request.in_header.nodeid)?;

        error!("FUCK OPEN {:?} {:?}", ino_fd, in_arg);

        let flag = in_arg.flags as libc::c_int & !libc::O_NOFOLLOW;

        let fd = ino_fd.fd.reopen(flag)?;

        error!("FUCK OPEN222 {:?}", fd);

        let fd_num = self.fd_map.insert(fd);

        let out_arg = fuse_open_out {
            fh: fd_num,
            ..fuse_open_out::default()
        };

        Ok(request.send_arg(out_arg))
    }

    pub fn do_read(&mut self, request: &Request) -> Result<u32> {
        let guest_mem = request.memory;
        let in_arg: fuse_read_in = guest_mem.read_obj_from_addr(request.in_arg_addr)?;

        let mut fh = self.fd_map.get_mut(in_arg.fh)?;

        fh.lseek(in_arg.offset as libc::off_t, libc::SEEK_SET)?;

        error!("FUCK --READ-- {:?} {} {:?}", in_arg, fh.fd_num(), fh);

        Ok(request.send_data(&mut fh))
    }

    pub fn do_write(&mut self, request: &Request) -> Result<u32> {
        let guest_mem = request.memory;
        let in_arg: fuse_write_in = guest_mem.read_obj_from_addr(request.in_arg_addr)?;

        let mut fh = self.fd_map.get_mut(in_arg.fh)?;

        fh.lseek(in_arg.offset as libc::off_t, libc::SEEK_SET)?;

        error!("FUCK --WRITE-- {:?} {} {:?}", in_arg, fh.fd_num(), fh);

        let write_size = request.write_data(&mut fh);

        let out_arg = fuse_write_out {
            size: write_size,
            ..Default::default()
        };

        Ok(request.send_arg(out_arg))
    }

    pub fn do_release(&mut self, request: &Request) -> Result<u32> {
        let guest_mem = request.memory;
        let in_arg: fuse_release_in = guest_mem.read_obj_from_addr(request.in_arg_addr)?;

        let fh = in_arg.fh;
        error!("FUCK RELEASE {}", fh);
        self.fd_map.remove(fh);
        Ok(request.send_err(0))
    }

    // pub fn do_flush(&mut self, request: &Request) -> Result<u32> {
    // }
}

// fn bit_contains(token: u32, other: u32) -> bool {
//     (token & other) == other
// }

fn bit_intersect(token: u32, other: u32) -> bool {
    (token & other) != 0
}

fn get_c_string_slice(buf: &[u8]) -> (&[u8], &[u8]) {
    let pos = buf.iter().position(|&x| x == 0).unwrap();
    buf.split_at(pos + 1)
}
