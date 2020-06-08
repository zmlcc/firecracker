use memfd;
use vm_memory::{FileOffset, MmapRegion, mmap::MmapRegionError};

use std::result::Result;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SharedMemoryError {
    #[error("failed to create memory fd")]
    CreateMemoryFd(#[from] memfd::Error),
    #[error("io error")]
    IO(#[from] std::io::Error),
    #[error("failed to create memory map")]
    MemoryMap(#[from] MmapRegionError),
}

pub(crate) fn create_shared_mem(name: &str, size: usize) -> Result<MmapRegion, SharedMemoryError>{
    let opt = memfd::MemfdOptions::default().allow_sealing(true).close_on_exec(true);
    let mem = opt.create(name)?;
    mem.as_file().set_len(size as u64)?;
    
    let mut seals = memfd::SealsHashSet::new();
    seals.insert(memfd::FileSeal::SealShrink);
    seals.insert(memfd::FileSeal::SealGrow);
    seals.insert(memfd::FileSeal::SealSeal);
    mem.add_seals(&seals)?;
    
    let file_offset = FileOffset::new(mem.into_file(), 0);

    Ok(MmapRegion::from_file(file_offset, size)?)
}