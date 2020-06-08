use super::super::{
    ActivateError, ActivateResult, DeviceState, Queue, VirtioDevice, TYPE_BLOCK,
    VIRTIO_MMIO_INT_VRING,
};
use super::{
    Result, VuError as Error, CONFIG_SPACE_SIZE, NUM_QUEUES, QUEUE_SIZES, VHOST_RECOVERY_MEM_SIZE,
};
use utils::eventfd::EventFd;

use std::sync::atomic::{AtomicUsize, Ordering};

use super::ucloud_ext::create_shared_mem;

use std::cmp;
use std::io::Write;
use std::sync::Arc;

use std::result;

use crate::Error as DeviceError;
use vm_memory::GuestMemory;
use vm_memory::{Address, GuestMemoryMmap, GuestMemoryRegion, MmapRegion};

use std::os::unix::io::AsRawFd;

use vhost_rs::vhost_user::{Master, VhostUserMaster};

use vhost_rs::vhost_user::message::VhostUserConfigFlags;
use vhost_rs::vhost_user::message::VHOST_USER_CONFIG_OFFSET;
use vhost_rs::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};

use vhost_rs::UCloudExt;
use vhost_rs::{VhostBackend, VhostUserMemoryRegionInfo, VringConfigData};
use virtio_gen::virtio_blk::*;

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
    pub(crate) vhost_user_master: Master,
    vhost_user_socket_path: String,
    pub(crate) call_evts: Vec<EventFd>,
    recovery_fds: Vec<MmapRegion>,
}

impl std::fmt::Debug for VhostUserBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VhostUserBlock id:{}", self.id)
    }
}

impl VhostUserBlock {
    pub fn new(id: String, socket_path: &str) -> Result<VhostUserBlock> {
        let mut master =
            Master::connect(socket_path, NUM_QUEUES as u64).map_err(Error::VhostUserBackend)?;
        master.set_owner().map_err(Error::VhostUserBackend)?;

        // only minimal features
        let mut avail_features = 1u64 << VIRTIO_F_VERSION_1
            | 1u64 << VIRTIO_BLK_F_FLUSH
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

        let backend_features = master.get_features().map_err(Error::VhostUserBackend)?;

        println!("FUCK {:#x}", backend_features);

        println!(
            "FUCK2 {:?}",
            backend_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
        );

        avail_features &= backend_features;

        master
            .set_features(avail_features)
            .map_err(Error::VhostUserBackend)?;

        let mut acked_features = 0u64;
        if backend_features & VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits() != 0 {
            println!("FUCK 3");

            acked_features |= VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();

            let mut protocol_features = master
                .get_protocol_features()
                .map_err(Error::VhostUserBackend)?;
            println!("FUCK protocol_features {:#x}", protocol_features);
            protocol_features &= !VhostUserProtocolFeatures::MQ;
            protocol_features &= !VhostUserProtocolFeatures::INFLIGHT_SHMFD;

            protocol_features &= !VhostUserProtocolFeatures::NO_RECOVERY;

            master
                .set_protocol_features(protocol_features)
                .map_err(Error::VhostUserBackend)?;
        }

        // config_space only support 'capacity', sizeof(le64)
        let (_, config_space) = master
            .get_config(
                VHOST_USER_CONFIG_OFFSET,
                CONFIG_SPACE_SIZE as u32,
                VhostUserConfigFlags::WRITABLE,
                &[0u8; CONFIG_SPACE_SIZE],
            )
            .map_err(Error::VhostUserBackend)?;

        println!("FUCKK config_space {:?}", config_space);

        // master
        //     .set_vring_base(0, 0)
        //     .map_err(Error::VhostUserBackend)?;

        let queues = QUEUE_SIZES.iter().map(|&s| Queue::new(s)).collect();
        let mut queue_evts = Vec::new();
        for _ in QUEUE_SIZES.iter() {
            queue_evts.push(EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?);
        }

        let mut call_evts = Vec::new();
        let mut recovery_fds = Vec::new();
        for i in QUEUE_SIZES.iter() {
            call_evts.push(EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?);
            recovery_fds.push(create_shared_mem(
                &format!("vhost-recovery-{}-{}", id, i),
                VHOST_RECOVERY_MEM_SIZE,
            )?);
        }

        Ok(VhostUserBlock {
            avail_features,
            acked_features,
            config_space,
            queues,
            interrupt_status: Arc::new(AtomicUsize::new(0)),
            interrupt_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?,
            queue_evts,
            device_state: DeviceState::Inactive,
            id,
            vhost_user_master: master,
            call_evts,
            vhost_user_socket_path: String::from(socket_path),
            recovery_fds,
        })
    }

    /// Provides the ID of this device.
    pub fn id(&self) -> &String {
        &self.id
    }

    pub(crate) fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);

        self.interrupt_evt.write(1).map_err(|e| {
            error!("Failed to signal used queue: {:?}", e);
            DeviceError::FailedSignalingUsedQueue(e)
        })?;
        Ok(())
    }

    pub(crate) fn reconnect(&mut self) {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        let mut master = self.reconnect_master();
        self.reset_backend(&mut master, &mem);

        self.vhost_user_master = master;
    }

    fn reconnect_master(&self) -> Master {
        let master = loop {
            match Master::connect(&self.vhost_user_socket_path, NUM_QUEUES as u64) {
                Ok(m) => break m,
                Err(_) => {
                    // should record connection error in metrics
                    println!("FUCK RECONNECT FAILED");
                    std::thread::sleep(std::time::Duration::from_secs(10));
                    continue;
                }
            }
        };

        master
    }

    fn reset_backend(&self, master: &mut Master, mem: &GuestMemoryMmap) -> Result<()> {
        let queues = &self.queues;
        // let master = &mut self.vhost_user_master;




        master
            .set_features(self.acked_features)
            .map_err(Error::VhostUserBackend)?;

        // master.set_protocol_features(features: VhostUserProtocolFeatures)

        master.set_owner().map_err(Error::VhostUserBackend)?;

        println!("FUCK activate 2");

        update_mem_table(master, &mem)?;

        println!("FUCK activate 222");

        for (queue_index, queue) in queues.into_iter().enumerate() {
            master
            .get_vring_base(queue_index)
            .map_err(Error::VhostUserBackend)?;

            master
                .set_vring_num(queue_index, queue.actual_size())
                .map_err(Error::VhostUserBackend)?;

            println!("FUCK activate 3");

            println!(
                "FUCK FDINFO queue_evt {}",
                self.queue_evts[queue_index].as_raw_fd()
            );
            println!(
                "FUCK FDINFO call_evt {}",
                self.call_evts[queue_index].as_raw_fd()
            );

            let data = &VringConfigData {
                queue_max_size: queue.get_max_size(),
                queue_size: queue.actual_size(),
                flags: 0u32,
                desc_table_addr: mem
                    .get_host_address(queue.desc_table)
                    .or(Err(Error::GetHostAddress))? as u64,
                used_ring_addr: mem
                    .get_host_address(queue.used_ring)
                    .or(Err(Error::GetHostAddress))? as u64,
                avail_ring_addr: mem
                    .get_host_address(queue.avail_ring)
                    .or(Err(Error::GetHostAddress))? as u64,
                log_addr: None,
            };

            master
                .set_vring_addr(queue_index, data)
                .map_err(Error::VhostUserBackend)?;

            println!("FUCK activate 4");

            master
                .set_vring_base(queue_index, 0u16)
                .map_err(Error::VhostUserBackend)?;

            println!("FUCK activate 5");

            master
                .set_vring_call(queue_index, &self.call_evts[queue_index])
                .map_err(Error::VhostUserBackend)?;

            println!("FUCK activate 6");

            let recovery_fd = self.recovery_fds[queue_index]
                .file_offset()
                .ok_or(Error::MemoryMapFD)?
                .file()
                .as_raw_fd();
            master
                .set_recovery_fd(queue_index, recovery_fd)
                .map_err(Error::VhostUserBackend)?;

                println!("FUCK activate 666");

            master
                .set_vring_kick(queue_index, &self.queue_evts[queue_index])
                .map_err(Error::VhostUserBackend)?;

            println!("FUCK activate 7");

            master
                .set_vring_enable(queue_index, true)
                .map_err(Error::VhostUserBackend)?;

            println!("FUCK activate 8");
        }

        Ok(())
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
        println!("FUCK activate acked_features {:#x}", self.acked_features);

        println!(
            "FUCK FDINFO interrupt_evt {}",
            self.interrupt_evt.as_raw_fd()
        );

        let queues = &self.queues;
        let master = &mut self.vhost_user_master;

        master
            .set_features(self.acked_features)
            .or(Err(ActivateError::BadActivate))?;

        println!("FUCK activate 2");

        update_mem_table(master, &mem)?;

        println!("FUCK activate 222");

        // master.set_vring_num(0, num: u16)

        for (queue_index, queue) in queues.into_iter().enumerate() {
            master
                .set_vring_num(queue_index, queue.actual_size())
                .or(Err(ActivateError::BadActivate))?;

            println!("FUCK activate 3");

            println!(
                "FUCK FDINFO queue_evt {}",
                self.queue_evts[queue_index].as_raw_fd()
            );
            println!(
                "FUCK FDINFO call_evt {}",
                self.call_evts[queue_index].as_raw_fd()
            );

            let data = &VringConfigData {
                queue_max_size: queue.get_max_size(),
                queue_size: queue.actual_size(),
                flags: 0u32,
                desc_table_addr: mem
                    .get_host_address(queue.desc_table)
                    .or(Err(ActivateError::BadActivate))? as u64,
                used_ring_addr: mem
                    .get_host_address(queue.used_ring)
                    .or(Err(ActivateError::BadActivate))? as u64,
                avail_ring_addr: mem
                    .get_host_address(queue.avail_ring)
                    .or(Err(ActivateError::BadActivate))? as u64,
                log_addr: None,
            };

            master
                .set_vring_addr(queue_index, data)
                .or(Err(ActivateError::BadActivate))?;

            println!("FUCK activate 4");

            master
                .set_vring_base(queue_index, 0u16)
                .or(Err(ActivateError::BadActivate))?;

            println!("FUCK activate 5");

            master
                .set_vring_call(queue_index, &self.call_evts[queue_index])
                .or(Err(ActivateError::BadActivate))?;

            println!("FUCK activate 6");

            let recovery_fd = self.recovery_fds[queue_index]
                .file_offset()
                .ok_or(Error::MemoryMapFD)?
                .file()
                .as_raw_fd();
            master
                .set_recovery_fd(queue_index, recovery_fd)
                .map_err(Error::VhostUserBackend)?;

            println!("FUCK activate 666");


            master
                .set_vring_kick(queue_index, &self.queue_evts[queue_index])
                .or(Err(ActivateError::BadActivate))?;

            println!("FUCK activate 7");

            master
                .set_vring_enable(queue_index, true)
                .or(Err(ActivateError::BadActivate))?;

            println!("FUCK activate 8");
        }

        self.device_state = DeviceState::Activated(mem);
        Ok(())
    }
}

pub fn update_mem_table(vu: &mut Master, mem: &GuestMemoryMmap) -> Result<()> {
    let mut regions: Vec<VhostUserMemoryRegionInfo> = Vec::new();
    mem.with_regions_mut(|_, region| {
        println!("FUCK activate {:?}", region);

        let (mmap_handle, mmap_offset) = match region.file_offset() {
            Some(_file_offset) => (_file_offset.file().as_raw_fd(), _file_offset.start()),
            None => return Err(Error::NoMemoryRegion),
        };

        let vhost_user_net_reg = VhostUserMemoryRegionInfo {
            guest_phys_addr: region.start_addr().raw_value(),
            memory_size: region.len() as u64,
            userspace_addr: region.as_ptr() as u64,
            mmap_offset,
            mmap_handle,
        };

        regions.push(vhost_user_net_reg);

        Ok(())
    })?;

    println!("FUCK activate 211");

    vu.set_mem_table(regions.as_slice())
        .map_err(Error::VhostUserBackend)?;

    println!("FUCK activate 212");

    Ok(())
}
