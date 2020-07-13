use crate::virtio::{
    ActivateError, ActivateResult, DeviceState, Queue, VirtioDevice, TYPE_NET, RX_INDEX, TX_INDEX,
    VIRTIO_MMIO_INT_VRING,
};

use crate::virtio::vhost::QUEUE_SIZES;
use crate::virtio::vhost::{Error, Result};

use utils::eventfd::EventFd;
use utils::net::Tap;

use std::cmp;
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use polly::event_manager::{EventManager, Subscriber};
use utils::epoll::{EpollEvent, EventSet};

use crate::Error as DeviceError;

use dumbo::{EthernetFrame, MacAddr, MAC_ADDR_LEN};

use crate::virtio::net::device::ConfigSpace;
use crate::vm_memory::{Address, ByteValued, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

use std::os::unix::io::AsRawFd;

use virtio_gen::virtio_net::{
    virtio_net_hdr_v1, VIRTIO_F_VERSION_1, VIRTIO_NET_F_CSUM, VIRTIO_NET_F_GUEST_CSUM,
    VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_UFO, VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_UFO,
    VIRTIO_NET_F_MAC, VIRTIO_NET_F_MRG_RXBUF
};

use vhost_aaa::vhost_kern::net::VhostNet;
use vhost_aaa::{VhostBackend, VhostUserMemoryRegionInfo, VringConfigData};

const VNET_HDR_LEN: usize = std::mem::size_of::<virtio_net_hdr_v1>();

pub struct VhostNetDevice {
    // Virtio fields.
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    config_space: ConfigSpace,

    // Transport related fields.
    pub(crate) queues: Vec<Queue>,
    pub(crate) interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,
    pub(crate) queue_evts: Vec<EventFd>,
    pub(crate) device_state: DeviceState,

    // Impl fields
    id: String,
    tap: Tap,
    guest_mac: Option<MacAddr>,
    call_evts: Vec<EventFd>,
    backend: Option<VhostNet>,
}

impl VhostNetDevice {
    pub fn new_with_tap(
        id: String,
        tap_if_name: &str,
        guest_mac: Option<&MacAddr>,
    ) -> Result<Self> {
        let tap = Tap::open_named(&tap_if_name).map_err(Error::TapOpen)?;
        // Set offload flags to match the virtio features below.
        tap.set_offload(
            net_gen::TUN_F_CSUM | net_gen::TUN_F_UFO | net_gen::TUN_F_TSO4 | net_gen::TUN_F_TSO6,
        )
        .map_err(Error::TapSetOffload)?;

        let vnet_hdr_size = VNET_HDR_LEN as i32;
        tap.set_vnet_hdr_size(vnet_hdr_size)
            .map_err(Error::TapSetVnetHdrSize)?;

        let mut avail_features = 1 << VIRTIO_F_VERSION_1
        | 1 << VIRTIO_NET_F_CSUM
        | 1 << VIRTIO_NET_F_HOST_TSO4
        | 1 << VIRTIO_NET_F_HOST_UFO
        | 1 << VIRTIO_NET_F_MRG_RXBUF;

        let mut config_space = ConfigSpace::default();
        if let Some(mac) = guest_mac {
            config_space.guest_mac.copy_from_slice(mac.get_bytes());
            // When this feature isn't available, the driver generates a random MAC address.
            // Otherwise, it should attempt to read the device MAC address from the config space.
            avail_features |= 1 << VIRTIO_NET_F_MAC;
        }

        let mut queue_evts = Vec::new();
        let mut call_evts = Vec::new();
        for _ in QUEUE_SIZES.iter() {
            queue_evts.push(EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?);
            call_evts.push(EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?);
        }

        let queues = QUEUE_SIZES.iter().map(|&s| Queue::new(s)).collect();

        Ok(VhostNetDevice {
            id,
            tap,
            guest_mac: guest_mac.copied(),
            avail_features,
            acked_features: 0u64,
            config_space,
            queues,
            queue_evts,
            interrupt_status: Arc::new(AtomicUsize::new(0)),
            interrupt_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?,
            device_state: DeviceState::Inactive,
            call_evts,
            backend: None,
            // activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?,
        })
    }

    /// Provides the ID of this net device.
    pub fn id(&self) -> &String {
        &self.id
    }

    pub(crate) fn signal_used_queue(&self) -> std::result::Result<(), DeviceError> {
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);

        self.interrupt_evt.write(1).map_err(|e| {
            error!("Failed to signal used queue: {:?}", e);
            DeviceError::FailedSignalingUsedQueue(e)
        })?;
        Ok(())
    }
}

impl VirtioDevice for VhostNetDevice {
    fn device_type(&self) -> u32 {
        TYPE_NET
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

    fn interrupt_status(&self) -> Arc<AtomicUsize> {
        self.interrupt_status.clone()
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        println!("FUCK acked_features: {}", self.acked_features);
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        println!("FUCK set_acked_features: {}", acked_features);
        self.acked_features = acked_features;
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_space_bytes = self.config_space.as_slice();
        let config_len = config_space_bytes.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(
                &config_space_bytes[offset as usize..cmp::min(end, config_len) as usize],
            )
            .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let data_len = data.len() as u64;
        let config_space_bytes = self.config_space.as_mut_slice();
        let config_len = config_space_bytes.len() as u64;
        if offset + data_len > config_len {
            error!("Failed to write config space");
            return;
        }

        config_space_bytes[offset as usize..(offset + data_len) as usize].copy_from_slice(data);
        self.guest_mac = Some(MacAddr::from_bytes_unchecked(
            &self.config_space.guest_mac[..MAC_ADDR_LEN],
        ));
    }

    fn is_activated(&self) -> bool {
        match self.device_state {
            DeviceState::Inactive => false,
            DeviceState::Activated(_) => true,
        }
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> ActivateResult {
        // if self.activate_evt.write(1).is_err() {
        //     error!("Net: Cannot write to activate_evt");
        //     return Err(super::super::ActivateError::BadActivate);
        // }
        const VIRTIO_NET_F_MRG_RXBUF: u32 =	15;
        const VIRTIO_F_NOTIFY_ON_EMPTY: u32 =	24;
        const VHOST_F_LOG_ALL:u32 = 26;
        const VHOST_NET_F_VIRTIO_NET_HDR: u32 = 27;
        const VIRTIO_F_ANY_LAYOUT: u32 =		27;
        const VIRTIO_RING_F_INDIRECT_DESC:u32 =	28;
        const VIRTIO_RING_F_EVENT_IDX: u32 =		29;
        const VIRTIO_F_IOMMU_PLATFORM: u32 = 33;
        const VIRTIO_F_RING_PACKED: u32 =		34;
        const VIRTIO_F_VERSION_1: u32 =		32;


        let mut backend = VhostNet::new().or(Err(ActivateError::BadActivate))?;

        backend.set_owner().or(Err(ActivateError::BadActivate))?;
        let backend_features = backend.get_features().or(Err(ActivateError::BadActivate))?;
        println!("FUCK {}", backend_features);

        // let ffff = backend_features & !(1u64 << 33 | 1u64 << 27);
        let ffff = backend_features & (
            1 << VIRTIO_NET_F_MRG_RXBUF
            | 1 << VIRTIO_F_VERSION_1
        );

        backend
            .set_features(ffff)
            .or(Err(ActivateError::BadActivate))?;

        let mut regions: Vec<VhostUserMemoryRegionInfo> = Vec::new();
        mem.with_regions_mut::<_, ()>(|_, region| {
            let (mmap_handle, mmap_offset) = match region.file_offset() {
                Some(_file_offset) => (_file_offset.file().as_raw_fd(), _file_offset.start()),
                None => (-1, 0),
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
        })
        .expect("mem region error");

        backend
            .set_mem_table(regions.as_slice())
            .expect("set_mem_table error");

        println!("FUCK 2");

        let queues = &self.queues;
        for (queue_index, queue) in queues.into_iter().enumerate() {
            backend
                .set_vring_num(queue_index, queue.actual_size())
                .expect("FUCK ERRR");

            println!("FUCK 3");

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

            println!("FUCK 4");

            backend
                .set_vring_addr(queue_index, data)
                .or(Err(ActivateError::BadActivate))?;
            println!("FUCK 5");

            backend
                .set_vring_base(queue_index, 0u16)
                .or(Err(ActivateError::BadActivate))?;
            println!("FUCK 6");

            let ret = backend.set_backend(queue_index, self.tap.as_raw_fd());
            println!("FUCK 9 {:?}", ret);
            if ret.is_err() {
                return Err(ActivateError::BadActivate);
            }

            backend
                .set_vring_call(queue_index, &self.call_evts[queue_index])
                .or(Err(ActivateError::BadActivate))?;
            println!("FUCK 7");

            backend
                .set_vring_kick(queue_index, &self.queue_evts[queue_index])
                .or(Err(ActivateError::BadActivate))?;
            println!("FUCK 8");
        }

        println!("FUCK 81 {}", self.tap.as_raw_fd());
        // for (queue_index, _) in queues.into_iter().enumerate() {
        // }
        self.backend = Some(backend);
        // self.interrupt_status
        //     .fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);
        self.device_state = DeviceState::Activated(mem);
        Ok(())
    }
}

impl Subscriber for VhostNetDevice {
    fn process(&mut self, event: &EpollEvent, evmgr: &mut EventManager) {
        // let source = event.fd();
        // let event_set = event.event_set();
        // println!("FUCK EVENT {} {:?}", source, event_set);
        self.signal_used_queue();
    }
    fn interest_list(&self) -> Vec<EpollEvent> {
        vec![
            // EpollEvent::new(EventSet::IN, self.queue_evts[RX_INDEX].as_raw_fd() as u64),
            // EpollEvent::new(EventSet::IN, self.queue_evts[TX_INDEX].as_raw_fd() as u64),
            EpollEvent::new(EventSet::IN | EventSet::EDGE_TRIGGERED, self.call_evts[TX_INDEX].as_raw_fd() as u64),
            EpollEvent::new(EventSet::IN | EventSet::EDGE_TRIGGERED, self.call_evts[RX_INDEX].as_raw_fd() as u64),
        ]
    }
}
