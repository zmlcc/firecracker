use utils::net::TapError;

use thiserror::Error;

pub mod net;

pub const QUEUE_SIZE: u16 = 256;
pub const NUM_QUEUES: usize = 2;
pub const QUEUE_SIZES: &[u16] = &[QUEUE_SIZE; NUM_QUEUES];

#[derive(Error, Debug)]
pub enum Error {
    /// Open tap device failed.
    #[error("Open tap device failed")]
    TapOpen(TapError),
    /// Setting tap interface offload flags failed.
    #[error("Setting tap interface offload flags failed")]
    TapSetOffload(TapError),
    /// Setting vnet header size failed.
    #[error("Setting vnet header size failed")]
    TapSetVnetHdrSize(TapError),
    /// Enabling tap interface failed.
    #[error("Enabling tap interface failed")]
    TapEnable(TapError),
    /// EventFd
    #[error("EventFd failed")]
    EventFd(std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;