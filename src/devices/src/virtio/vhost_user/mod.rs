pub mod block;

use std::{io, result};
use vhost_rs::Error as VhostError;


pub use self::block::VhostUserBlock;

pub const CONFIG_SPACE_SIZE: usize = 8;
pub const QUEUE_SIZE: u16 = 256;
pub const NUM_QUEUES: usize = 1;
pub const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE];

#[derive(Debug)]
pub enum Error {
    /// EventFd
    EventFd(io::Error),
    /// Failed to create master.
    VhostUserBackend(VhostError),
}



pub type Result<T> = result::Result<T, Error>;
