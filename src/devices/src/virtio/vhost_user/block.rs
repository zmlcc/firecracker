use super::super::{ActivateResult, DeviceState, Queue, VirtioDevice, TYPE_BLOCK};
use super::{QUEUE_SIZES, CONFIG_SPACE_SIZE, Result, Error};
use utils::eventfd::EventFd;

use std::sync::atomic::AtomicUsize;

use std::cmp;
use std::io::Write;
use std::sync::Arc;

use vm_memory::GuestMemoryMmap;

pub struct VhostUserBlock {
    // Virtio fields.
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    config_space: Vec<u8>,

    // Transport related fields.
    pub(crate) queues: Vec<Queue>,
    pub(crate) interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,
    pub(crate) queue_evts: Vec<EventFd>,
    pub(crate) device_state: DeviceState,

    // Implementation specific fields.
    pub(crate) id: String,
}

impl VhostUserBlock {
    pub fn new(
        id: String
    ) -> Result<VhostUserBlock> {
        let queues = QUEUE_SIZES.iter().map(|&s| Queue::new(s)).collect();
        let mut queue_evts = Vec::new();
        for _ in QUEUE_SIZES.iter() {
            queue_evts.push(EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?);
        }

        Ok(VhostUserBlock {
            avail_features: 0u64,
            acked_features: 0u64,
            config_space: vec![0u8, CONFIG_SPACE_SIZE as u8],
            queues,
            interrupt_status: Arc::new(AtomicUsize::new(0)),
            interrupt_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?,
            queue_evts,
            device_state: DeviceState::Inactive,
            id,
        })
    }

    /// Provides the ID of this device.
    pub fn id(&self) -> &String {
        &self.id
    }
}

impl VirtioDevice for VhostUserBlock {
    fn device_type(&self) -> u32 {
        TYPE_BLOCK
    }

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_evts
    }

    fn interrupt_evt(&self) -> &EventFd {
        &self.interrupt_evt
    }

    /// Returns the current device interrupt status.
    fn interrupt_status(&self) -> Arc<AtomicUsize> {
        self.interrupt_status.clone()
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_len = self.config_space.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&self.config_space[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let data_len = data.len() as u64;
        let config_len = self.config_space.len() as u64;
        if offset + data_len > config_len {
            error!("Failed to write config space");
            return;
        }
        let (_, right) = self.config_space.split_at_mut(offset as usize);
        right.copy_from_slice(&data[..]);
    }

    fn is_activated(&self) -> bool {
        match self.device_state {
            DeviceState::Inactive => false,
            DeviceState::Activated(_) => true,
        }
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> ActivateResult {
        self.device_state = DeviceState::Activated(mem);
        Ok(())
    }
}
