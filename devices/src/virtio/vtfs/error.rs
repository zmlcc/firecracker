// Copyright 2019 UCloud.cn, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use memory_model::GuestMemoryError;
use std::ffi::FromBytesWithNulError;
use std::io;

#[derive(Debug)]
pub enum ExecuteError {
    InvalidMethod,
    IllegalParameter,
    MemoryError,
    UnknownHandle,
    OSError(i32),
    UnknownError,
}

impl From<FromBytesWithNulError> for ExecuteError {
    fn from(_: FromBytesWithNulError) -> ExecuteError {
        ExecuteError::IllegalParameter
    }
}

impl From<io::Error> for ExecuteError {
    fn from(e: io::Error) -> ExecuteError {
        match e.raw_os_error() {
            Some(i) => ExecuteError::OSError(i),
            None => ExecuteError::UnknownError,
        }
    }
}

impl From<GuestMemoryError> for ExecuteError {
    fn from(_: GuestMemoryError) -> ExecuteError {
        ExecuteError::MemoryError
    }
}

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
    // The fuse opcode could not be recognized
    // UnknownFuseOpcode,
}
