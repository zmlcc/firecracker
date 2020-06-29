pub mod block;
pub mod event_handler;
mod ucloud_ext;

use thiserror::Error;

use std::{io, result};
use vhost_rs::Error as VhostError;

use super::ActivateError;

pub use self::block::VhostUserBlock;
pub use self::event_handler::*;

pub const CONFIG_SPACE_SIZE: usize = 8;
pub const QUEUE_SIZE: u16 = 256;
pub const NUM_QUEUES: usize = 1;
pub const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];

pub const VHOST_RECOVERY_MEM_SIZE: usize = 8192;

#[derive(Error, Debug)]
pub enum VuError {
    #[error("falied to create event fd")]
    EventFd(io::Error),
    /// Failed to create master.
    #[error("errors when communicating with vhost user backend")]
    VhostUserBackend(VhostError),
    /// No memory region found.
    #[error("no memory region found")]
    NoMemoryRegion,
    /// Failed to get host address.
    #[error("failed to get host address")]
    GetHostAddress,
    #[error("failed to create shared memory")]
    SharedMemory(#[from] ucloud_ext::SharedMemoryError),
    #[error("failed to get momery map fd")]
    MemoryMapFD,
}

impl From<VuError> for ActivateError {
    fn from(_: VuError) -> ActivateError {
        ActivateError::BadActivate
    }
}

pub type Result<T> = result::Result<T, VuError>;
