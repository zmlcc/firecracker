// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use crate::virtio::net::Error;
use crate::virtio::net::Result;
use crate::virtio::net::{MAX_BUFFER_SIZE, QUEUE_SIZE, QUEUE_SIZES, RX_INDEX, TX_INDEX};
use crate::virtio::{
    ActivateResult, DeviceState, Queue, VirtioDevice, TYPE_NET, VIRTIO_MMIO_INT_VRING,
};
use crate::{report_net_event_fail, Error as DeviceError};
use dumbo::ns::MmdsNetworkStack;
use dumbo::{EthernetFrame, MacAddr, MAC_ADDR_LEN};
use libc::EAGAIN;
use logger::{Metric, METRICS};
use rate_limiter::{BucketUpdate, RateLimiter, TokenType};

use std::io::Write;
#[cfg(not(test))]
use std::io::{self, Read};
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::{cmp, mem, result};
use utils::eventfd::EventFd;
use utils::net::Tap;
use virtio_gen::virtio_net::{
    virtio_net_hdr_v1, VIRTIO_F_VERSION_1, VIRTIO_NET_F_CSUM, VIRTIO_NET_F_GUEST_CSUM,
    VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_UFO, VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_UFO,
    VIRTIO_NET_F_MAC,
};
use vm_memory::GuestMemory;
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemoryError, GuestMemoryMmap};

fn vnet_hdr_len() -> usize {
    mem::size_of::<virtio_net_hdr_v1>()
}

// Frames being sent/received through the network device model have a VNET header. This
// function returns a slice which holds the L2 frame bytes without this header.
fn frame_bytes_from_buf(buf: &[u8]) -> Result<&[u8]> {
    if buf.len() < vnet_hdr_len() {
        Err(Error::VnetHeaderMissing)
    } else {
        Ok(&buf[vnet_hdr_len()..])
    }
}

fn frame_bytes_from_buf_mut(buf: &mut [u8]) -> Result<&mut [u8]> {
    if buf.len() < vnet_hdr_len() {
        Err(Error::VnetHeaderMissing)
    } else {
        Ok(&mut buf[vnet_hdr_len()..])
    }
}

// This initializes to all 0 the VNET hdr part of a buf.
fn init_vnet_hdr(buf: &mut [u8]) {
    // The buffer should be larger than vnet_hdr_len.
    // TODO: any better way to set all these bytes to 0? Or is this optimized by the compiler?
    for i in &mut buf[0..vnet_hdr_len()] {
        *i = 0;
    }
}

#[derive(Clone, Copy)]
pub struct ConfigSpace {
    pub guest_mac: [u8; MAC_ADDR_LEN],
}

impl Default for ConfigSpace {
    fn default() -> ConfigSpace {
        ConfigSpace {
            guest_mac: [0; MAC_ADDR_LEN],
        }
    }
}

unsafe impl ByteValued for ConfigSpace {}

pub struct Net {
    pub(crate) id: String,

    pub(crate) tap: Tap,
    pub(crate) tap_if_name: String,

    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,

    pub(crate) queues: Vec<Queue>,
    pub(crate) queue_evts: Vec<EventFd>,

    pub(crate) rx_rate_limiter: RateLimiter,
    pub(crate) tx_rate_limiter: RateLimiter,

    rx_deferred_frame: bool,
    rx_deferred_irqs: bool,

    rx_bytes_read: usize,
    rx_frame_buf: [u8; MAX_BUFFER_SIZE],

    tx_iovec: Vec<(GuestAddress, usize)>,
    tx_frame_buf: [u8; MAX_BUFFER_SIZE],

    pub(crate) interrupt_status: Arc<AtomicUsize>,
    interrupt_evt: EventFd,

    pub(crate) config_space: ConfigSpace,
    pub(crate) guest_mac: Option<MacAddr>,

    pub(crate) device_state: DeviceState,
    pub(crate) activate_evt: EventFd,

    pub(crate) mmds_ns: Option<MmdsNetworkStack>,

    defer_tx_count: usize,

    #[cfg(test)]
    test_mutators: tests::TestMutators,
}

impl Net {
    /// Create a new virtio network device with the given TAP interface.
    pub fn new_with_tap(
        id: String,
        tap_if_name: String,
        guest_mac: Option<&MacAddr>,
        rx_rate_limiter: RateLimiter,
        tx_rate_limiter: RateLimiter,
        allow_mmds_requests: bool,
    ) -> Result<Self> {
        let tap = Tap::open_named(&tap_if_name).map_err(Error::TapOpen)?;

        // Set offload flags to match the virtio features below.
        tap.set_offload(
            net_gen::TUN_F_CSUM | net_gen::TUN_F_UFO | net_gen::TUN_F_TSO4 | net_gen::TUN_F_TSO6,
        )
        .map_err(Error::TapSetOffload)?;

        let vnet_hdr_size = vnet_hdr_len() as i32;
        tap.set_vnet_hdr_size(vnet_hdr_size)
            .map_err(Error::TapSetVnetHdrSize)?;

        let mut avail_features = 1 << VIRTIO_NET_F_GUEST_CSUM
            | 1 << VIRTIO_NET_F_CSUM
            | 1 << VIRTIO_NET_F_GUEST_TSO4
            | 1 << VIRTIO_NET_F_GUEST_UFO
            | 1 << VIRTIO_NET_F_HOST_TSO4
            | 1 << VIRTIO_NET_F_HOST_UFO
            | 1 << VIRTIO_F_VERSION_1;

        let mut config_space = ConfigSpace::default();
        if let Some(mac) = guest_mac {
            config_space.guest_mac.copy_from_slice(mac.get_bytes());
            // When this feature isn't available, the driver generates a random MAC address.
            // Otherwise, it should attempt to read the device MAC address from the config space.
            avail_features |= 1 << VIRTIO_NET_F_MAC;
        }

        let mut queue_evts = Vec::new();
        for _ in QUEUE_SIZES.iter() {
            queue_evts.push(EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?);
        }

        let queues = QUEUE_SIZES.iter().map(|&s| Queue::new(s)).collect();

        let mmds_ns = if allow_mmds_requests {
            Some(MmdsNetworkStack::new_with_defaults(None))
        } else {
            None
        };
        Ok(Net {
            id,
            tap,
            tap_if_name,
            avail_features,
            acked_features: 0u64,
            queues,
            queue_evts,
            rx_rate_limiter,
            tx_rate_limiter,
            rx_deferred_frame: false,
            rx_deferred_irqs: false,
            rx_bytes_read: 0,
            rx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            tx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            tx_iovec: Vec::with_capacity(QUEUE_SIZE as usize),
            interrupt_status: Arc::new(AtomicUsize::new(0)),
            interrupt_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?,
            device_state: DeviceState::Inactive,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(Error::EventFd)?,
            config_space,
            mmds_ns,
            guest_mac: guest_mac.copied(),

            defer_tx_count: 0,
            #[cfg(test)]
            test_mutators: tests::TestMutators::default(),
        })
    }

    /// Provides the ID of this net device.
    pub fn id(&self) -> &String {
        &self.id
    }

    /// Provides the MAC of this net device.
    pub fn guest_mac(&self) -> Option<&MacAddr> {
        self.guest_mac.as_ref()
    }

    /// Provides a mutable reference to the `MmdsNetworkStack`.
    pub fn mmds_ns_mut(&mut self) -> Option<&mut MmdsNetworkStack> {
        self.mmds_ns.as_mut()
    }

    fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);
        self.interrupt_evt.write(1).map_err(|e| {
            error!("Failed to signal used queue: {:?}", e);
            METRICS.net.event_fails.inc();
            DeviceError::FailedSignalingUsedQueue(e)
        })
    }

    // Attempts to copy a single frame into the guest if there is enough
    // rate limiting budget.
    // Returns true on successful frame delivery.
    fn rate_limited_rx_single_frame(&mut self) -> bool {
        // If limiter.consume() fails it means there is no more TokenType::Ops
        // budget and rate limiting is in effect.
        if !self.rx_rate_limiter.consume(1, TokenType::Ops) {
            return false;
        }
        // If limiter.consume() fails it means there is no more TokenType::Bytes
        // budget and rate limiting is in effect.
        if !self
            .rx_rate_limiter
            .consume(self.rx_bytes_read as u64, TokenType::Bytes)
        {
            // revert the OPS consume()
            self.rx_rate_limiter.manual_replenish(1, TokenType::Ops);
            return false;
        }

        // Attempt frame delivery.
        let success = self.rx_single_frame();

        // Undo the tokens consumption if guest delivery failed.
        if !success {
            // revert the OPS consume()
            self.rx_rate_limiter.manual_replenish(1, TokenType::Ops);
            // revert the BYTES consume()
            self.rx_rate_limiter
                .manual_replenish(self.rx_bytes_read as u64, TokenType::Bytes);
        }
        success
    }

    // Copies a single frame from `self.rx_frame_buf` into the guest. Returns true
    // if a buffer was used, and false if the frame must be deferred until a buffer
    // is made available by the driver.
    fn rx_single_frame(&mut self) -> bool {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };
        let rx_queue = &mut self.queues[RX_INDEX];
        let mut next_desc = rx_queue.pop(mem);
        if next_desc.is_none() {
            METRICS.net.no_rx_avail_buffer.inc();
            return false;
        }

        // We just checked that the head descriptor exists.
        let head_index = next_desc.as_ref().unwrap().index;
        let mut write_count = 0;

        // Copy from frame into buffer, which may span multiple descriptors.
        loop {
            match next_desc {
                Some(desc) => {
                    if !desc.is_write_only() {
                        break;
                    }

                    let limit = cmp::min(write_count + desc.len as usize, self.rx_bytes_read);
                    let source_slice = &self.rx_frame_buf[write_count..limit];
                    let write_result = mem.write_slice(source_slice, desc.addr);

                    match write_result {
                        Ok(()) => {
                            METRICS.net.rx_count.inc();
                            write_count += source_slice.len();
                        }
                        Err(e) => {
                            error!("Failed to write slice: {:?}", e);
                            METRICS.net.rx_fails.inc();
                            if let GuestMemoryError::PartialBuffer { completed, .. } = e {
                                write_count += completed;
                            }
                            break;
                        }
                    };

                    if write_count >= self.rx_bytes_read {
                        break;
                    }
                    next_desc = desc.next_descriptor();
                }
                None => {
                    warn!("Receiving buffer is too small to hold frame of current size");
                    METRICS.net.rx_fails.inc();
                    break;
                }
            }
        }

        rx_queue.add_used(mem, head_index, write_count as u32);

        // Mark that we have at least one pending packet and we need to interrupt the guest.
        self.rx_deferred_irqs = true;

        if write_count >= self.rx_bytes_read {
            METRICS.net.rx_bytes_count.add(write_count);
            METRICS.net.rx_packets_count.inc();
            true
        } else {
            false
        }
    }

    // Tries to detour the frame to MMDS and if MMDS doesn't accept it, sends it on the host TAP.
    //
    // `frame_buf` should contain the frame bytes in a slice of exact length.
    // Returns whether MMDS consumed the frame.
    fn write_to_mmds_or_tap(
        mmds_ns: Option<&mut MmdsNetworkStack>,
        rate_limiter: &mut RateLimiter,
        frame_buf: &[u8],
        tap: &mut Tap,
        guest_mac: Option<MacAddr>,
    ) -> Result<bool> {
        let checked_frame = |frame_buf| {
            frame_bytes_from_buf(frame_buf).map_err(|e| {
                error!("VNET header missing in the TX frame.");
                METRICS.net.tx_malformed_frames.inc();
                e
            })
        };
        if let Some(ns) = mmds_ns {
            if ns.detour_frame(checked_frame(frame_buf)?) {
                METRICS.mmds.rx_accepted.inc();

                // MMDS frames are not accounted by the rate limiter.
                rate_limiter.manual_replenish(frame_buf.len() as u64, TokenType::Bytes);
                rate_limiter.manual_replenish(1, TokenType::Ops);

                // MMDS consumed the frame.
                return Ok(true);
            }
        }

        // This frame goes to the TAP.

        // Check for guest MAC spoofing.
        if let Some(mac) = guest_mac {
            let _ = EthernetFrame::from_bytes(checked_frame(frame_buf)?).and_then(|eth_frame| {
                if mac != eth_frame.src_mac() {
                    METRICS.net.tx_spoofed_mac_count.inc();
                }
                Ok(())
            });
        }

        match tap.write(frame_buf) {
            Ok(_) => {
                METRICS.net.tx_bytes_count.add(frame_buf.len());
                METRICS.net.tx_packets_count.inc();
                METRICS.net.tx_count.inc();
            }
            Err(e) => {
                error!("Failed to write to tap: {:?}", e);
                METRICS.net.tx_fails.inc();
            }
        };
        Ok(false)
    }

    // We currently prioritize packets from the MMDS over regular network packets.
    fn read_from_mmds_or_tap(&mut self) -> Result<usize> {
        if let Some(ns) = self.mmds_ns.as_mut() {
            if let Some(len) =
                ns.write_next_frame(frame_bytes_from_buf_mut(&mut self.rx_frame_buf)?)
            {
                let len = len.get();
                METRICS.mmds.tx_frames.inc();
                METRICS.mmds.tx_bytes.add(len);
                init_vnet_hdr(&mut self.rx_frame_buf);
                return Ok(vnet_hdr_len() + len);
            }
        }

        self.read_tap().map_err(Error::IO)
    }

    fn process_rx(&mut self) -> result::Result<(), DeviceError> {
        // Read as many frames as possible.
        loop {
            match self.read_from_mmds_or_tap() {
                Ok(count) => {
                    self.rx_bytes_read = count;
                    METRICS.net.rx_count.inc();
                    if !self.rate_limited_rx_single_frame() {
                        self.rx_deferred_frame = true;
                        break;
                    }
                }
                Err(Error::IO(e)) => {
                    // The tap device is non-blocking, so any error aside from EAGAIN is
                    // unexpected.
                    match e.raw_os_error() {
                        Some(err) if err == EAGAIN => (),
                        _ => {
                            error!("Failed to read tap: {:?}", e);
                            METRICS.net.rx_fails.inc();
                            return Err(DeviceError::FailedReadTap);
                        }
                    };
                    break;
                }
                Err(e) => {
                    error!("Spurious error in network RX: {:?}", e);
                }
            }
        }

        if self.rx_deferred_irqs {
            self.rx_deferred_irqs = false;
            self.signal_used_queue()
        } else {
            Ok(())
        }
    }

    fn resume_rx(&mut self) -> result::Result<(), DeviceError> {
        if self.rx_deferred_frame {
            if self.rate_limited_rx_single_frame() {
                self.rx_deferred_frame = false;
                // process_rx() was interrupted possibly before consuming all
                // packets in the tap; try continuing now.
                self.process_rx()
            } else if self.rx_deferred_irqs {
                self.rx_deferred_irqs = false;
                self.signal_used_queue()
            } else {
                Ok(())
            }
        } else {
            Ok(())
        }
    }

    fn process_tx(&mut self) -> result::Result<(), DeviceError> {
        METRICS.net.process_tx_count.inc();
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        // The MMDS network stack works like a state machine, based on synchronous calls, and
        // without being added to any event loop. If any frame is accepted by the MMDS, we also
        // trigger a process_rx() which checks if there are any new frames to be sent, starting
        // with the MMDS network stack.
        let mut process_rx_for_mmds = false;
        let mut raise_irq = false;
        let tx_queue = &mut self.queues[TX_INDEX];

        if tx_queue.len(mem) == 0 {
            METRICS.net.empty_tx_queue_count.inc();
        }

        tx_queue.enable_notification(mem, false);
        while let Some(head) = tx_queue.pop(mem) {
            self.defer_tx_count += 1;
            // If limiter.consume() fails it means there is no more TokenType::Ops
            // budget and rate limiting is in effect.
            // if !self.tx_rate_limiter.consume(1, TokenType::Ops) {
            //     // Stop processing the queue and return this descriptor chain to the
            //     // avail ring, for later processing.
            //     tx_queue.undo_pop();
            //     break;
            // }

            let head_index = head.index;
            let mut read_count = 0;
            let mut next_desc = Some(head);

            self.tx_iovec.clear();
            while let Some(desc) = next_desc {
                if desc.is_write_only() {
                    break;
                }
                self.tx_iovec.push((desc.addr, desc.len as usize));
                read_count += desc.len as usize;
                next_desc = desc.next_descriptor();
            }

            // If limiter.consume() fails it means there is no more TokenType::Bytes
            // budget and rate limiting is in effect.
            // if !self
            //     .tx_rate_limiter
            //     .consume(read_count as u64, TokenType::Bytes)
            // {
            //     // revert the OPS consume()
            //     self.tx_rate_limiter.manual_replenish(1, TokenType::Ops);
            //     // Stop processing the queue and return this descriptor chain to the
            //     // avail ring, for later processing.
            //     tx_queue.undo_pop();
            //     break;
            // }

            read_count = 0;
            match self.mmds_ns.as_mut() {
                Some(ns) => unimplemented!(),
                _ => {
                    let mut frame_num = 0;
                    let mut frame_len = 0;
                    let mut segments = vec![];
                    for (desc_addr, desc_len) in self.tx_iovec.drain(..) {
                        frame_len += desc_len;

                        // // read src MAC
                        // if frame_num == 0 {
                        //     if let Some(mac) = self.guest_mac {
                        //         let mut src_mac: [u8; 6] = [0; 6];
                        //         let read_result = self.mem.read_slice_at_addr(
                        //             &mut src_mac,
                        //             desc_addr.unchecked_add(vnet_hdr_len() + 6),
                        //         );
                        //         match read_result {
                        //             Ok(_) => {
                        //                 if mac != MacAddr::from_bytes_unchecked(&src_mac) {
                        //                     METRICS.net.tx_spoofed_mac_count.inc();
                        //                     warn!("tx_spoofed_mac_count");
                        //                 }
                        //             }
                        //             Err(e) => {
                        //                 error!("Failed to read src mac: {:?}", e);
                        //                 METRICS.net.tx_fails.inc();
                        //                 break;
                        //             }
                        //         }
                        //     }
                        // }

                        let maybe_ptr = mem.get_host_address(desc_addr);
                        match maybe_ptr {
                            Ok(ptr) => segments.push(libc::iovec {
                                iov_base: ptr as *mut libc::c_void,
                                iov_len: desc_len,
                            }),
                            Err(e) => {
                                error!("Failed to get host addr: {:?}", e);
                                METRICS.net.tx_fails.inc();
                                break;
                            }
                        }

                        frame_num += 1;
                    }

                    match self.tap.writev(&segments) {
                        Ok(_) => {
                            METRICS.net.tx_bytes_count.add(frame_len);
                            METRICS.net.tx_packets_count.inc();
                            METRICS.net.tx_count.inc();
                        }
                        Err(e) => {
                            error!("Failed to write to tap: {:?}", e);
                            METRICS.net.tx_fails.inc();
                        }
                    };
                }
            }
            // Copy buffer from across multiple descriptors.
            // TODO(performance - Issue #420): change this to use `writev()` instead of `write()`
            // and get rid of the intermediate buffer.
            // for (desc_addr, desc_len) in self.tx_iovec.drain(..) {
            //     let limit = cmp::min((read_count + desc_len) as usize, self.tx_frame_buf.len());

            //     let read_result = mem.read_slice(
            //         &mut self.tx_frame_buf[read_count..limit as usize],
            //         desc_addr,
            //     );
            //     match read_result {
            //         Ok(()) => {
            //             read_count += limit - read_count;
            //             METRICS.net.tx_count.inc();
            //         }
            //         Err(e) => {
            //             error!("Failed to read slice: {:?}", e);
            //             METRICS.net.tx_fails.inc();
            //             if let GuestMemoryError::PartialBuffer { completed, .. } = e {
            //                 read_count += completed;
            //             }
            //             break;
            //         }
            //     }
            // }

            // let frame_consumed_by_mmds = Self::write_to_mmds_or_tap(
            //     self.mmds_ns.as_mut(),
            //     &mut self.tx_rate_limiter,
            //     &self.tx_frame_buf[..read_count],
            //     &mut self.tap,
            //     self.guest_mac,
            // )
            // .unwrap_or_else(|_| false);
            // if frame_consumed_by_mmds && !self.rx_deferred_frame {
            //     // MMDS consumed this frame/request, let's also try to process the response.
            //     process_rx_for_mmds = true;
            // }

            tx_queue.add_used(mem, head_index, 0);
            raise_irq = true;
        }
        tx_queue.enable_notification(mem, true);

        if raise_irq {
            if tx_queue.should_interrupt(mem) & (self.defer_tx_count > 50) {
                METRICS.net.trigger_tx_signal_count.inc();
                self.defer_tx_count = 0;
                self.signal_used_queue()?;
            } else {
                METRICS.net.skip_trigger_tx_signal_count.inc();
            }
        } else {
            METRICS.net.no_tx_avail_buffer.inc();
        }

        // An incoming frame for the MMDS may trigger the transmission of a new message.
        if process_rx_for_mmds {
            self.process_rx()
        } else {
            Ok(())
        }
    }

    /// Updates the parameters for the rate limiters
    pub fn patch_rate_limiters(
        &mut self,
        rx_bytes: BucketUpdate,
        rx_ops: BucketUpdate,
        tx_bytes: BucketUpdate,
        tx_ops: BucketUpdate,
    ) {
        self.rx_rate_limiter.update_buckets(rx_bytes, rx_ops);
        self.tx_rate_limiter.update_buckets(tx_bytes, tx_ops);
    }

    #[cfg(not(test))]
    fn read_tap(&mut self) -> io::Result<usize> {
        self.tap.read(&mut self.rx_frame_buf)
    }

    pub fn process_rx_queue_event(&mut self) {
        METRICS.net.rx_queue_event_count.inc();

        if let Err(e) = self.queue_evts[RX_INDEX].read() {
            // rate limiters present but with _very high_ allowed rate
            error!("Failed to get rx queue event: {:?}", e);
            METRICS.net.event_fails.inc();
        } else {
            // If the limiter is not blocked, resume the receiving of bytes.
            if !self.rx_rate_limiter.is_blocked() {
                self.resume_rx().unwrap_or_else(report_net_event_fail);
            }
        }
    }

    pub fn process_tap_rx_event(&mut self) {
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };
        METRICS.net.rx_tap_event_count.inc();
        if self.queues[RX_INDEX].is_empty(mem) && self.rx_deferred_frame {
            METRICS.net.no_rx_avail_buffer.inc();
            return;
        }

        // While limiter is blocked, don't process any more incoming.
        if self.rx_rate_limiter.is_blocked() {
            return;
        }

        if self.rx_deferred_frame
        // Process a deferred frame first if available. Don't read from tap again
        // until we manage to receive this deferred frame.
        {
            if self.rate_limited_rx_single_frame() {
                self.rx_deferred_frame = false;
                self.process_rx().unwrap_or_else(report_net_event_fail);
            } else if self.rx_deferred_irqs {
                self.rx_deferred_irqs = false;
                self.signal_used_queue()
                    .unwrap_or_else(report_net_event_fail);
            }
        } else {
            self.process_rx().unwrap_or_else(report_net_event_fail);
        }
    }

    pub fn process_tx_queue_event(&mut self) {
        METRICS.net.tx_queue_event_count.inc();
        if let Err(e) = self.queue_evts[TX_INDEX].read() {
            error!("Failed to get tx queue event: {:?}", e);
            METRICS.net.event_fails.inc();
        } else if !self.tx_rate_limiter.is_blocked()
        // If the limiter is not blocked, continue transmitting bytes.
        {
            self.process_tx().unwrap_or_else(report_net_event_fail);
        }
    }

    pub fn process_rx_rate_limiter_event(&mut self) {
        METRICS.net.rx_event_rate_limiter_count.inc();
        // Upon rate limiter event, call the rate limiter handler
        // and restart processing the queue.

        match self.rx_rate_limiter.event_handler() {
            Ok(_) => {
                // There might be enough budget now to receive the frame.
                self.resume_rx().unwrap_or_else(report_net_event_fail);
            }
            Err(e) => {
                error!("Failed to get rx rate-limiter event: {:?}", e);
                METRICS.net.event_fails.inc();
            }
        }
    }

    pub fn process_tx_rate_limiter_event(&mut self) {
        METRICS.net.tx_rate_limiter_event_count.inc();
        // Upon rate limiter event, call the rate limiter handler
        // and restart processing the queue.
        match self.tx_rate_limiter.event_handler() {
            Ok(_) => {
                // There might be enough budget now to send the frame.
                self.process_tx().unwrap_or_else(report_net_event_fail);
            }
            Err(e) => {
                error!("Failed to get tx rate-limiter event: {:?}", e);
                METRICS.net.event_fails.inc();
            }
        }
    }
}

impl VirtioDevice for Net {
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
        println!("FUCK WHAT acked_features {}", self.acked_features);
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_space_bytes = self.config_space.as_slice();
        let config_len = config_space_bytes.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            METRICS.net.cfg_fails.inc();
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
            METRICS.net.cfg_fails.inc();
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
        if self.activate_evt.write(1).is_err() {
            error!("Net: Cannot write to activate_evt");
            return Err(super::super::ActivateError::BadActivate);
        }
        self.device_state = DeviceState::Activated(mem);
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::net::Ipv4Addr;
    use std::os::unix::io::AsRawFd;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::Duration;
    use std::{io, mem, thread};

    use super::*;
    use crate::virtio::net::device::{
        frame_bytes_from_buf, frame_bytes_from_buf_mut, init_vnet_hdr, vnet_hdr_len,
    };

    use crate::virtio::net::QUEUE_SIZES;
    use crate::virtio::queue::tests::VirtQueue;
    use crate::virtio::{
        Net, Queue, VirtioDevice, MAX_BUFFER_SIZE, RX_INDEX, TX_INDEX, TYPE_NET,
        VIRTIO_MMIO_INT_VRING, VIRTQ_DESC_F_WRITE,
    };
    use dumbo::{
        EthIPv4ArpFrame, EthernetFrame, MacAddr, ETHERTYPE_ARP, ETH_IPV4_FRAME_LEN, MAC_ADDR_LEN,
    };
    use logger::{Metric, METRICS};
    use polly::event_manager::{EventManager, Subscriber};
    use rate_limiter::{RateLimiter, TokenBucket, TokenType};
    use utils::epoll::{EpollEvent, EventSet};
    use virtio_gen::virtio_net::{
        virtio_net_hdr_v1, VIRTIO_F_VERSION_1, VIRTIO_NET_F_CSUM, VIRTIO_NET_F_GUEST_CSUM,
        VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_UFO, VIRTIO_NET_F_HOST_TSO4,
        VIRTIO_NET_F_HOST_UFO, VIRTIO_NET_F_MAC,
    };

    static NEXT_INDEX: AtomicUsize = AtomicUsize::new(1);

    macro_rules! check_metric_after_block {
        ($metric:expr, $delta:expr, $block:expr) => {{
            let before = $metric.count();
            let _ = $block;
            assert_eq!($metric.count(), before + $delta, "unexpected metric value");
        }};
    }

    // Used to simulate tap read fails in tests.
    pub struct TestMutators {
        pub tap_read_fail: bool,
    }

    impl Default for TestMutators {
        fn default() -> TestMutators {
            TestMutators {
                tap_read_fail: false,
            }
        }
    }

    impl Net {
        pub fn default_net(test_mutators: TestMutators) -> Net {
            let next_tap = NEXT_INDEX.fetch_add(1, Ordering::SeqCst);
            let tap_dev_name = format!("net-device{}", next_tap);

            let guest_mac = Net::default_guest_mac();

            let mut net = Net::new_with_tap(
                format!("net-device{}", next_tap),
                tap_dev_name.clone(),
                Some(&guest_mac),
                RateLimiter::default(),
                RateLimiter::default(),
                true,
            )
            .unwrap();
            net.tap.enable().unwrap();
            net.test_mutators = test_mutators;

            net
        }

        pub fn default_guest_mac() -> MacAddr {
            MacAddr::parse_str("11:22:33:44:55:66").unwrap()
        }

        pub fn default_guest_memory() -> GuestMemoryMmap {
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap()
        }

        pub fn rx_single_frame_no_irq_coalescing(&mut self) -> bool {
            let ret = self.rx_single_frame();
            if self.rx_deferred_irqs {
                self.rx_deferred_irqs = false;
                let _ = self.signal_used_queue();
            }
            ret
        }

        // Returns handles to virtio queues creation/activation and manipulation.
        pub fn virtqueues(mem: &GuestMemoryMmap) -> (VirtQueue, VirtQueue) {
            let rxq = VirtQueue::new(GuestAddress(0), mem, 16);
            let txq = VirtQueue::new(GuestAddress(0x1000), mem, 16);
            assert!(rxq.end().0 < txq.start().0);

            (rxq, txq)
        }

        pub fn set_mac(&mut self, mac: MacAddr) {
            self.guest_mac = Some(mac);
            self.config_space.guest_mac.copy_from_slice(mac.get_bytes());
        }

        // Assigns "guest virtio driver" activated queues to the net device.
        pub fn assign_queues(&mut self, rxq: Queue, txq: Queue) {
            self.queues.clear();
            self.queues.push(rxq);
            self.queues.push(txq);
        }
    }

    impl Net {
        // This needs to be public to be accessible from the non-cfg-test `impl Net`.
        pub fn read_tap(&mut self) -> io::Result<usize> {
            use std::cmp::min;

            let count = min(1234, self.rx_frame_buf.len());

            for i in 0..count {
                self.rx_frame_buf[i] = 5;
            }

            if self.test_mutators.tap_read_fail {
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Read tap synthetically failed.",
                ))
            } else {
                Ok(count)
            }
        }
    }

    #[test]
    fn test_vnet_helpers() {
        let mut frame_buf = vec![42u8; vnet_hdr_len() - 1];
        assert_eq!(
            format!("{:?}", frame_bytes_from_buf(&frame_buf)),
            "Err(VnetHeaderMissing)"
        );
        assert_eq!(
            format!("{:?}", frame_bytes_from_buf_mut(&mut frame_buf)),
            "Err(VnetHeaderMissing)"
        );

        let mut frame_buf: [u8; MAX_BUFFER_SIZE] = [42u8; MAX_BUFFER_SIZE];

        let vnet_hdr_len_ = mem::size_of::<virtio_net_hdr_v1>();
        assert_eq!(vnet_hdr_len_, vnet_hdr_len());

        init_vnet_hdr(&mut frame_buf);
        let zero_vnet_hdr = vec![0u8; vnet_hdr_len_];
        assert_eq!(zero_vnet_hdr, &frame_buf[..vnet_hdr_len_]);

        let payload = vec![42u8; MAX_BUFFER_SIZE - vnet_hdr_len_];
        assert_eq!(payload, frame_bytes_from_buf(&frame_buf).unwrap());

        {
            let payload = frame_bytes_from_buf_mut(&mut frame_buf).unwrap();
            payload[0] = 15;
        }
        assert_eq!(frame_buf[vnet_hdr_len_], 15);
    }

    #[test]
    fn test_virtio_device_type() {
        let mut net = Net::default_net(TestMutators::default());
        net.set_mac(MacAddr::parse_str("11:22:33:44:55:66").unwrap());
        assert_eq!(net.device_type(), TYPE_NET);
    }

    #[test]
    fn test_virtio_device_features() {
        let mut net = Net::default_net(TestMutators::default());
        net.set_mac(MacAddr::parse_str("11:22:33:44:55:66").unwrap());

        // Test `features()` and `ack_features()`.
        let features = 1 << VIRTIO_NET_F_GUEST_CSUM
            | 1 << VIRTIO_NET_F_CSUM
            | 1 << VIRTIO_NET_F_GUEST_TSO4
            | 1 << VIRTIO_NET_F_MAC
            | 1 << VIRTIO_NET_F_GUEST_UFO
            | 1 << VIRTIO_NET_F_HOST_TSO4
            | 1 << VIRTIO_NET_F_HOST_UFO
            | 1 << VIRTIO_F_VERSION_1;

        assert_eq!(net.avail_features_by_page(0), features as u32);
        assert_eq!(net.avail_features_by_page(1), (features >> 32) as u32);
        for i in 2..10 {
            assert_eq!(net.avail_features_by_page(i), 0u32);
        }

        for i in 0..10 {
            net.ack_features_by_page(i, std::u32::MAX);
        }

        assert_eq!(net.acked_features, features);
    }

    #[test]
    fn test_virtio_device_read_config() {
        let mut net = Net::default_net(TestMutators::default());
        net.set_mac(MacAddr::parse_str("11:22:33:44:55:66").unwrap());

        // Test `read_config()`. This also validates the MAC was properly configured.
        let mac = MacAddr::parse_str("11:22:33:44:55:66").unwrap();
        let mut config_mac = [0u8; MAC_ADDR_LEN];
        net.read_config(0, &mut config_mac);
        assert_eq!(config_mac, mac.get_bytes());

        // Invalid read.
        config_mac = [0u8; MAC_ADDR_LEN];
        net.read_config(MAC_ADDR_LEN as u64 + 1, &mut config_mac);
        assert_eq!(config_mac, [0u8, 0u8, 0u8, 0u8, 0u8, 0u8]);
    }

    #[test]
    fn test_virtio_device_rewrite_config() {
        let mut net = Net::default_net(TestMutators::default());
        net.set_mac(MacAddr::parse_str("11:22:33:44:55:66").unwrap());

        let new_config: [u8; 6] = [0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
        net.write_config(0, &new_config);
        let mut new_config_read = [0u8; 6];
        net.read_config(0, &mut new_config_read);
        assert_eq!(new_config, new_config_read);

        // Check that the guest MAC was updated.
        let expected_guest_mac = MacAddr::from_bytes_unchecked(&new_config);
        assert_eq!(expected_guest_mac, net.guest_mac.unwrap());

        // Partial write (this is how the kernel sets a new mac address) - byte by byte.
        let new_config = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        for i in 0..new_config.len() {
            net.write_config(i as u64, &new_config[i..=i]);
        }
        net.read_config(0, &mut new_config_read);
        assert_eq!(new_config, new_config_read);

        // Invalid write.
        net.write_config(5, &new_config);
        // Verify old config was untouched.
        new_config_read = [0u8; 6];
        net.read_config(0, &mut new_config_read);
        assert_eq!(new_config, new_config_read);
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_event_processing() {
        let mut event_manager = EventManager::new().unwrap();
        let mut net = Net::default_net(TestMutators::default());
        let mem = Net::default_guest_memory();
        let (rxq, txq) = Net::virtqueues(&mem);
        net.assign_queues(rxq.create_queue(), txq.create_queue());
        net.activate(mem.clone()).unwrap();

        let daddr = 0x2000;
        assert!(daddr > txq.end().0);

        // Some corner cases for rx_single_frame().
        {
            assert_eq!(net.rx_bytes_read, 0);

            // Let's imagine we received some data.
            net.rx_bytes_read = MAX_BUFFER_SIZE;
            {
                // a read only descriptor
                rxq.avail.ring[0].set(0);
                rxq.avail.idx.set(1);
                rxq.dtable[0].set(daddr, 0x1000, 0, 0);
                assert!(!net.rx_single_frame_no_irq_coalescing());
                assert_eq!(rxq.used.idx.get(), 1);

                // resetting values
                rxq.used.idx.set(0);
                net.queues[RX_INDEX] = rxq.create_queue();
                net.interrupt_evt.write(1).unwrap();
                // The prev rx_single_frame_no_irq_coalescing() call should have written one more.
                assert_eq!(net.interrupt_evt.read().unwrap(), 2);
            }

            {
                // We make the prev desc write_only (with no other flag) to get a chain which is
                // writable, but too short.
                rxq.dtable[0].flags.set(VIRTQ_DESC_F_WRITE);
                check_metric_after_block!(
                    &METRICS.net.rx_fails,
                    1,
                    assert!(!net.rx_single_frame_no_irq_coalescing())
                );
                assert_eq!(rxq.used.idx.get(), 1);

                rxq.used.idx.set(0);
                net.queues[RX_INDEX] = rxq.create_queue();
                net.interrupt_evt.write(1).unwrap();
                assert_eq!(net.interrupt_evt.read().unwrap(), 2);
            }

            // set rx_count back to 0
            net.rx_bytes_read = 0;
        }

        {
            // Send an invalid frame (too small, VNET header missing).
            txq.avail.idx.set(1);
            txq.avail.ring[0].set(0);
            txq.dtable[0].set(daddr, 1, 0, 0);

            // Trigger the TX handler.
            net.queue_evts[TX_INDEX].write(1).unwrap();
            let event = EpollEvent::new(EventSet::IN, net.queue_evts[TX_INDEX].as_raw_fd() as u64);
            check_metric_after_block!(
                &METRICS.net.tx_malformed_frames,
                1,
                net.process(&event, &mut event_manager)
            );

            // Make sure the data queue advanced.
            assert_eq!(txq.used.idx.get(), 1);
        }

        // Now let's move on to the actual device events.
        {
            // testing TX_QUEUE_EVENT
            txq.avail.idx.set(2);
            txq.avail.ring[1].set(1);
            txq.dtable[1].set(daddr, 0x1000, 0, 0);

            net.queue_evts[TX_INDEX].write(1).unwrap();
            let event = EpollEvent::new(EventSet::IN, net.queue_evts[TX_INDEX].as_raw_fd() as u64);
            net.process(&event, &mut event_manager);
            // Make sure the data queue advanced.
            assert_eq!(txq.used.idx.get(), 2);
        }

        {
            // testing RX_TAP_EVENT

            assert!(!net.rx_deferred_frame);

            // this should work just fine
            rxq.avail.idx.set(1);
            rxq.avail.ring[0].set(0);
            rxq.dtable[0].set(daddr, 0x1000, VIRTQ_DESC_F_WRITE, 0);

            net.interrupt_evt.write(1).unwrap();
            let tap_event = EpollEvent::new(EventSet::IN, net.tap.as_raw_fd() as u64);
            net.process(&tap_event, &mut event_manager);
            assert!(net.rx_deferred_frame);
            assert_eq!(net.interrupt_evt.read().unwrap(), 4);
            // The #cfg(test) enabled version of read_tap always returns 1234 bytes (or the len of
            // the buffer, whichever is smaller).
            assert_eq!(rxq.used.ring[0].get().len, 1234);

            // Since deferred_frame is now true, activating the same event again will trigger
            // a different execution path.

            // reset some parts of the queue first
            net.queues[RX_INDEX] = rxq.create_queue();
            rxq.used.idx.set(0);

            // this should also be successful
            net.interrupt_evt.write(1).unwrap();
            net.process(&tap_event, &mut event_manager);
            assert!(net.rx_deferred_frame);
            assert_eq!(net.interrupt_evt.read().unwrap(), 2);

            // ... but the following shouldn't, because we emulate receiving much more data than
            // we can fit inside a single descriptor

            net.rx_bytes_read = MAX_BUFFER_SIZE;
            net.queues[RX_INDEX] = rxq.create_queue();
            rxq.used.idx.set(0);

            net.interrupt_evt.write(1).unwrap();
            check_metric_after_block!(
                &METRICS.net.rx_fails,
                1,
                net.process(&tap_event, &mut event_manager)
            );
            assert!(net.rx_deferred_frame);
            assert_eq!(net.interrupt_evt.read().unwrap(), 2);

            // A mismatch shows the reception was unsuccessful.
            assert_ne!(rxq.used.ring[0].get().len as usize, net.rx_bytes_read);

            // We set this back to a manageable size, for the following test.
            net.rx_bytes_read = 1234;
        }

        {
            // now also try an RX_QUEUE_EVENT
            rxq.avail.idx.set(2);
            rxq.avail.ring[1].set(1);
            rxq.dtable[1].set(daddr + 0x1000, 0x1000, VIRTQ_DESC_F_WRITE, 0);

            net.queue_evts[RX_INDEX].write(1).unwrap();
            net.interrupt_evt.write(1).unwrap();

            // rx_count increments 1 from rx_single_frame() and 1 from process_rx()
            let rx_event =
                EpollEvent::new(EventSet::IN, net.queue_evts[RX_INDEX].as_raw_fd() as u64);
            check_metric_after_block!(
                &METRICS.net.rx_count,
                2,
                net.process(&rx_event, &mut event_manager)
            );
            assert_eq!(net.interrupt_evt.read().unwrap(), 2);
        }

        {
            let test_mutators = TestMutators {
                tap_read_fail: true,
            };

            let mut net = Net::default_net(test_mutators);
            check_metric_after_block!(&METRICS.net.rx_fails, 1, net.process_rx());
        }
    }

    #[test]
    fn test_mmds_detour_and_injection() {
        let mut net = Net::default_net(TestMutators::default());

        let sha = MacAddr::parse_str("11:11:11:11:11:11").unwrap();
        let spa = Ipv4Addr::new(10, 1, 2, 3);
        let tha = MacAddr::parse_str("22:22:22:22:22:22").unwrap();
        let tpa = Ipv4Addr::new(169, 254, 169, 254);

        let packet_len;
        {
            // Create an ethernet frame.
            let eth_frame_i = EthernetFrame::write_incomplete(
                frame_bytes_from_buf_mut(&mut net.tx_frame_buf).unwrap(),
                tha,
                sha,
                ETHERTYPE_ARP,
            )
            .ok()
            .unwrap();
            // Set its length to hold an ARP request.
            let mut eth_frame_complete = eth_frame_i.with_payload_len_unchecked(ETH_IPV4_FRAME_LEN);

            // Save the total frame length.
            packet_len = vnet_hdr_len() + eth_frame_complete.payload_offset() + ETH_IPV4_FRAME_LEN;

            // Create the ARP request.
            let arp_req = EthIPv4ArpFrame::write_request(
                eth_frame_complete.payload_mut(),
                sha,
                spa,
                tha,
                tpa,
            );
            // Validate success.
            assert!(arp_req.is_ok());
        }

        // Call the code which sends the packet to the host or MMDS.
        // Validate the frame was consumed by MMDS and that the metrics reflect that.
        check_metric_after_block!(
            &METRICS.mmds.rx_accepted,
            1,
            assert!(Net::write_to_mmds_or_tap(
                net.mmds_ns.as_mut(),
                &mut net.tx_rate_limiter,
                &net.tx_frame_buf[..packet_len],
                &mut net.tap,
                Some(sha),
            )
            .unwrap())
        );

        // Validate that MMDS has a response and we can retrieve it.
        check_metric_after_block!(
            &METRICS.mmds.tx_frames,
            1,
            net.read_from_mmds_or_tap().unwrap()
        );
    }

    #[test]
    fn test_mac_spoofing_detection() {
        let mut net = Net::default_net(TestMutators::default());

        let guest_mac = MacAddr::parse_str("11:11:11:11:11:11").unwrap();
        let not_guest_mac = MacAddr::parse_str("33:33:33:33:33:33").unwrap();
        let guest_ip = Ipv4Addr::new(10, 1, 2, 3);
        let dst_mac = MacAddr::parse_str("22:22:22:22:22:22").unwrap();
        let dst_ip = Ipv4Addr::new(10, 1, 1, 1);

        let packet_len;
        {
            // Create an ethernet frame.
            let eth_frame_i = EthernetFrame::write_incomplete(
                frame_bytes_from_buf_mut(&mut net.tx_frame_buf).unwrap(),
                dst_mac,
                guest_mac,
                ETHERTYPE_ARP,
            )
            .ok()
            .unwrap();
            // Set its length to hold an ARP request.
            let mut eth_frame_complete = eth_frame_i.with_payload_len_unchecked(ETH_IPV4_FRAME_LEN);

            // Save the total frame length.
            packet_len = vnet_hdr_len() + eth_frame_complete.payload_offset() + ETH_IPV4_FRAME_LEN;

            // Create the ARP request.
            let arp_req = EthIPv4ArpFrame::write_request(
                eth_frame_complete.payload_mut(),
                guest_mac,
                guest_ip,
                dst_mac,
                dst_ip,
            );
            // Validate success.
            assert!(arp_req.is_ok());
        }

        // Check that a legit MAC doesn't affect the spoofed MAC metric.
        check_metric_after_block!(
            &METRICS.net.tx_spoofed_mac_count,
            0,
            Net::write_to_mmds_or_tap(
                net.mmds_ns.as_mut(),
                &mut net.tx_rate_limiter,
                &net.tx_frame_buf[..packet_len],
                &mut net.tap,
                Some(guest_mac),
            )
        );

        // Check that a spoofed MAC increases our spoofed MAC metric.
        check_metric_after_block!(
            &METRICS.net.tx_spoofed_mac_count,
            1,
            Net::write_to_mmds_or_tap(
                net.mmds_ns.as_mut(),
                &mut net.tx_rate_limiter,
                &net.tx_frame_buf[..packet_len],
                &mut net.tap,
                Some(not_guest_mac),
            )
        );
    }

    #[test]
    fn test_process_error_cases() {
        let mut event_manager = EventManager::new().unwrap();
        let mut net = Net::default_net(TestMutators::default());
        let mem = Net::default_guest_memory();
        let (rxq, txq) = Net::virtqueues(&mem);
        net.assign_queues(rxq.create_queue(), txq.create_queue());
        net.activate(mem.clone()).unwrap();

        // RX rate limiter events should error since the limiter is not blocked.
        // Validate that the event failed and failure was properly accounted for.
        let rx_rate_limiter_ev =
            EpollEvent::new(EventSet::IN, net.rx_rate_limiter.as_raw_fd() as u64);
        check_metric_after_block!(
            &METRICS.net.event_fails,
            1,
            net.process(&rx_rate_limiter_ev, &mut event_manager)
        );

        // TX rate limiter events should error since the limiter is not blocked.
        // Validate that the event failed and failure was properly accounted for.
        let tx_rate_limiter_ev =
            EpollEvent::new(EventSet::IN, net.tx_rate_limiter.as_raw_fd() as u64);
        check_metric_after_block!(
            &METRICS.net.event_fails,
            1,
            net.process(&tx_rate_limiter_ev, &mut event_manager)
        );
    }

    #[test]
    fn test_invalid_event() {
        let mut event_manager = EventManager::new().unwrap();
        let mut net = Net::default_net(TestMutators::default());

        let mem = Net::default_guest_memory();
        let (rxq, txq) = Net::virtqueues(&mem);
        net.assign_queues(rxq.create_queue(), txq.create_queue());
        net.activate(mem.clone()).unwrap();

        let net = Arc::new(Mutex::new(net));
        event_manager.add_subscriber(net.clone()).unwrap();

        // Process the activate event.
        let ev_count = event_manager.run_with_timeout(50).unwrap();
        assert_eq!(ev_count, 1);

        // Inject invalid event.
        let invalid_event = EpollEvent::new(EventSet::IN, 1000);
        check_metric_after_block!(
            &METRICS.net.event_fails,
            1,
            net.lock()
                .unwrap()
                .process(&invalid_event, &mut event_manager)
        );
    }

    // Cannot easily test failures for:
    //  * queue_evt.read (rx and tx)
    //  * interrupt_evt.write
    #[test]
    fn test_read_tap_fail_event_handler() {
        let mut event_manager = EventManager::new().unwrap();
        let test_mutators = TestMutators {
            tap_read_fail: true,
        };

        let mut net = Net::default_net(test_mutators);
        let mem = Net::default_guest_memory();
        let (rxq, txq) = Net::virtqueues(&mem);
        net.assign_queues(rxq.create_queue(), txq.create_queue());
        net.activate(mem.clone()).unwrap();

        // The RX queue is empty.
        let tap_event = EpollEvent::new(EventSet::IN, net.tap.as_raw_fd() as u64);
        net.rx_deferred_frame = true;
        check_metric_after_block!(
            &METRICS.net.no_rx_avail_buffer,
            1,
            net.process(&tap_event, &mut event_manager)
        );

        // Fake an avail buffer; this time, tap reading should error out.
        rxq.avail.idx.set(1);
        check_metric_after_block!(
            &METRICS.net.rx_fails,
            1,
            net.process(&tap_event, &mut event_manager)
        );
    }

    #[test]
    fn test_rx_rate_limiter_handling() {
        let mut event_manager = EventManager::new().unwrap();
        let mut net = Net::default_net(TestMutators::default());
        let mem = Net::default_guest_memory();
        let (rxq, txq) = Net::virtqueues(&mem);
        net.assign_queues(rxq.create_queue(), txq.create_queue());
        net.activate(mem.clone()).unwrap();

        net.rx_rate_limiter = RateLimiter::new(0, None, 0, 0, None, 0).unwrap();
        let rate_limiter_event =
            EpollEvent::new(EventSet::IN, net.rx_rate_limiter.as_raw_fd() as u64);
        check_metric_after_block!(
            &METRICS.net.event_fails,
            1,
            net.process(&rate_limiter_event, &mut event_manager)
        );
    }

    #[test]
    fn test_tx_rate_limiter_handling() {
        let mut event_manager = EventManager::new().unwrap();
        let mut net = Net::default_net(TestMutators::default());
        let mem = Net::default_guest_memory();
        let (rxq, txq) = Net::virtqueues(&mem);
        net.assign_queues(rxq.create_queue(), txq.create_queue());
        net.activate(mem.clone()).unwrap();

        net.tx_rate_limiter = RateLimiter::new(0, None, 0, 0, None, 0).unwrap();
        let rate_limiter_event =
            EpollEvent::new(EventSet::IN, net.tx_rate_limiter.as_raw_fd() as u64);
        net.process(&rate_limiter_event, &mut event_manager);
        check_metric_after_block!(
            &METRICS.net.event_fails,
            1,
            net.process(&rate_limiter_event, &mut event_manager)
        );
    }

    #[test]
    fn test_bandwidth_rate_limiter() {
        let mut event_manager = EventManager::new().unwrap();
        let mut net = Net::default_net(TestMutators::default());
        let mem = Net::default_guest_memory();
        let (rxq, txq) = Net::virtqueues(&mem);
        net.assign_queues(rxq.create_queue(), txq.create_queue());
        net.activate(mem.clone()).unwrap();

        let daddr = 0x2000;
        assert!(daddr > txq.end().0);

        // Test TX bandwidth rate limiting
        {
            // create bandwidth rate limiter that allows 40960 bytes/s with bucket size 4096 bytes
            let mut rl = RateLimiter::new(0x1000, None, 100, 0, None, 0).unwrap();
            // use up the budget
            assert!(rl.consume(0x1000, TokenType::Bytes));

            // set this tx rate limiter to be used
            net.tx_rate_limiter = rl;

            // try doing TX
            txq.avail.idx.set(1);
            txq.avail.ring[0].set(0);
            txq.dtable[0].set(daddr, 0x1000, 0, 0);

            // following TX procedure should fail because of bandwidth rate limiting
            {
                // trigger the TX handler
                net.queue_evts[TX_INDEX].write(1).unwrap();
                let tx_event =
                    EpollEvent::new(EventSet::IN, net.queue_evts[TX_INDEX].as_raw_fd() as u64);
                net.process(&tx_event, &mut event_manager);

                // assert that limiter is blocked
                assert!(net.tx_rate_limiter.is_blocked());
                // make sure the data is still queued for processing
                assert_eq!(txq.used.idx.get(), 0);
            }

            // wait for 100ms to give the rate-limiter timer a chance to replenish
            // wait for an extra 100ms to make sure the timerfd event makes its way from the kernel
            thread::sleep(Duration::from_millis(200));

            // following TX procedure should succeed because bandwidth should now be available
            {
                // tx_count increments 1 from process_tx() and 1 from write_to_mmds_or_tap()
                let tx_limiter_event =
                    EpollEvent::new(EventSet::IN, net.tx_rate_limiter.as_raw_fd() as u64);
                check_metric_after_block!(
                    &METRICS.net.tx_count,
                    2,
                    net.process(&tx_limiter_event, &mut event_manager)
                );
                // validate the rate_limiter is no longer blocked
                assert!(!net.tx_rate_limiter.is_blocked());
                // make sure the data queue advanced
                assert_eq!(txq.used.idx.get(), 1);
            }
        }

        // Test RX bandwidth rate limiting
        {
            // create bandwidth rate limiter that allows 40960 bytes/s with bucket size 4096 bytes
            let mut rl = RateLimiter::new(0x1000, None, 100, 0, None, 0).unwrap();
            // use up the budget
            assert!(rl.consume(0x1000, TokenType::Bytes));

            // set this rx rate limiter to be used
            net.rx_rate_limiter = rl;

            // set up RX
            assert!(!net.rx_deferred_frame);
            rxq.avail.idx.set(1);
            rxq.avail.ring[0].set(0);
            rxq.dtable[0].set(daddr, 0x1000, VIRTQ_DESC_F_WRITE, 0);

            // following RX procedure should fail because of bandwidth rate limiting
            {
                // leave at least one event here so that reading it later won't block
                net.interrupt_evt.write(1).unwrap();
                // trigger the RX handler
                let rx_event = EpollEvent::new(EventSet::IN, net.tap.as_raw_fd() as u64);
                net.process(&rx_event, &mut event_manager);

                // assert that limiter is blocked
                assert!(net.rx_rate_limiter.is_blocked());
                assert!(net.rx_deferred_frame);
                // assert that no operation actually completed (limiter blocked it)
                assert_eq!(net.interrupt_evt.read().unwrap(), 2);
                // make sure the data is still queued for processing
                assert_eq!(rxq.used.idx.get(), 0);
            }

            // wait for 100ms to give the rate-limiter timer a chance to replenish
            // wait for an extra 100ms to make sure the timerfd event makes its way from the kernel
            thread::sleep(Duration::from_millis(200));

            // following RX procedure should succeed because bandwidth should now be available
            {
                // leave at least one event here so that reading it later won't block
                net.interrupt_evt.write(1).unwrap();
                let rx_limiter_event =
                    EpollEvent::new(EventSet::IN, net.rx_rate_limiter.as_raw_fd() as u64);
                net.process(&rx_limiter_event, &mut event_manager);
                // validate the rate_limiter is no longer blocked
                assert!(!net.rx_rate_limiter.is_blocked());
                // make sure the virtio queue operation completed this time
                assert_eq!(net.interrupt_evt.read().unwrap(), 2);
                // make sure the data queue advanced
                assert_eq!(rxq.used.idx.get(), 1);
                // The #cfg(test) enabled version of read_tap always returns 1234 bytes
                // (or the len of the buffer, whichever is smaller).
                assert_eq!(rxq.used.ring[0].get().len, 1234);
            }
        }
    }

    #[test]
    fn test_ops_rate_limiter() {
        let mut event_manager = EventManager::new().unwrap();
        let mut net = Net::default_net(TestMutators::default());
        let mem = Net::default_guest_memory();
        let (rxq, txq) = Net::virtqueues(&mem);
        net.assign_queues(rxq.create_queue(), txq.create_queue());
        net.activate(mem.clone()).unwrap();

        let daddr = 0x2000;
        assert!(daddr > txq.end().0);

        // Test TX ops rate limiting
        {
            // create ops rate limiter that allows 10 ops/s with bucket size 1 ops
            let mut rl = RateLimiter::new(0, None, 0, 1, None, 100).unwrap();
            // use up the budget
            assert!(rl.consume(1, TokenType::Ops));

            // set this tx rate limiter to be used
            net.tx_rate_limiter = rl;

            // try doing TX
            txq.avail.idx.set(1);
            txq.avail.ring[0].set(0);
            txq.dtable[0].set(daddr, 0x1000, 0, 0);

            // following TX procedure should fail because of ops rate limiting
            {
                // trigger the TX handler
                net.queue_evts[TX_INDEX].write(1).unwrap();
                let tx_event =
                    EpollEvent::new(EventSet::IN, net.queue_evts[TX_INDEX].as_raw_fd() as u64);
                net.process(&tx_event, &mut event_manager);

                // assert that limiter is blocked
                assert!(net.tx_rate_limiter.is_blocked());
                // make sure the data is still queued for processing
                assert_eq!(txq.used.idx.get(), 0);
            }

            // wait for 100ms to give the rate-limiter timer a chance to replenish
            // wait for an extra 100ms to make sure the timerfd event makes its way from the kernel
            thread::sleep(Duration::from_millis(200));

            // following TX procedure should succeed because ops should now be available
            {
                let tx_rate_limiter_event =
                    EpollEvent::new(EventSet::IN, net.tx_rate_limiter.as_raw_fd() as u64);
                net.process(&tx_rate_limiter_event, &mut event_manager);
                // validate the rate_limiter is no longer blocked
                assert!(!net.tx_rate_limiter.is_blocked());
                // make sure the data queue advanced
                assert_eq!(txq.used.idx.get(), 1);
            }
        }

        // Test RX ops rate limiting
        {
            // create ops rate limiter that allows 10 ops/s with bucket size 1 ops
            let mut rl = RateLimiter::new(0, None, 0, 1, None, 100).unwrap();
            // use up the budget
            assert!(rl.consume(0x800, TokenType::Ops));

            // set this rx rate limiter to be used
            net.rx_rate_limiter = rl;

            // set up RX
            assert!(!net.rx_deferred_frame);
            rxq.avail.idx.set(1);
            rxq.avail.ring[0].set(0);
            rxq.dtable[0].set(daddr, 0x1000, VIRTQ_DESC_F_WRITE, 0);

            // following RX procedure should fail because of ops rate limiting
            {
                // leave at least one event here so that reading it later won't block
                net.interrupt_evt.write(1).unwrap();
                // trigger the RX handler
                let rx_event = EpollEvent::new(EventSet::IN, net.tap.as_raw_fd() as u64);
                net.process(&rx_event, &mut event_manager);

                // assert that limiter is blocked
                assert!(net.rx_rate_limiter.is_blocked());
                assert!(net.rx_deferred_frame);
                // assert that no operation actually completed (limiter blocked it)
                assert_eq!(net.interrupt_evt.read().unwrap(), 2);
                // make sure the data is still queued for processing
                assert_eq!(rxq.used.idx.get(), 0);

                // leave at least one event here so that reading it later won't block
                net.interrupt_evt.write(1).unwrap();
                // trigger the RX handler again, this time it should do the limiter fast path exit
                net.process(&rx_event, &mut event_manager);
                // assert that no operation actually completed, that the limiter blocked it
                assert_eq!(net.interrupt_evt.read().unwrap(), 1);
                // make sure the data is still queued for processing
                assert_eq!(rxq.used.idx.get(), 0);
            }

            // wait for 100ms to give the rate-limiter timer a chance to replenish
            // wait for an extra 100ms to make sure the timerfd event makes its way from the kernel
            thread::sleep(Duration::from_millis(200));

            // following RX procedure should succeed because ops should now be available
            {
                // leave at least one event here so that reading it later won't block
                net.interrupt_evt.write(1).unwrap();
                let rx_rate_limiter_event =
                    EpollEvent::new(EventSet::IN, net.rx_rate_limiter.as_raw_fd() as u64);
                net.process(&rx_rate_limiter_event, &mut event_manager);
                // make sure the virtio queue operation completed this time
                assert_eq!(net.interrupt_evt.read().unwrap(), 2);
                // make sure the data queue advanced
                assert_eq!(rxq.used.idx.get(), 1);
                // The #cfg(test) enabled version of read_tap always returns 1234 bytes
                // (or the len of the buffer, whichever is smaller).
                assert_eq!(rxq.used.ring[0].get().len, 1234);
            }
        }
    }

    #[test]
    fn test_patch_rate_limiters() {
        let mut net = Net::default_net(TestMutators::default());
        let mem = Net::default_guest_memory();
        let (rxq, txq) = Net::virtqueues(&mem);
        net.assign_queues(rxq.create_queue(), txq.create_queue());
        net.activate(mem.clone()).unwrap();

        net.rx_rate_limiter = RateLimiter::new(10, None, 10, 2, None, 2).unwrap();
        net.tx_rate_limiter = RateLimiter::new(10, None, 10, 2, None, 2).unwrap();

        let rx_bytes = TokenBucket::new(1000, Some(1001), 1002).unwrap();
        let rx_ops = TokenBucket::new(1003, Some(1004), 1005).unwrap();
        let tx_bytes = TokenBucket::new(1006, Some(1007), 1008).unwrap();
        let tx_ops = TokenBucket::new(1009, Some(1010), 1011).unwrap();

        net.patch_rate_limiters(
            BucketUpdate::Update(rx_bytes.clone()),
            BucketUpdate::Update(rx_ops.clone()),
            BucketUpdate::Update(tx_bytes.clone()),
            BucketUpdate::Update(tx_ops.clone()),
        );
        let compare_buckets = |a: &TokenBucket, b: &TokenBucket| {
            assert_eq!(a.capacity(), b.capacity());
            assert_eq!(a.one_time_burst(), b.one_time_burst());
            assert_eq!(a.refill_time_ms(), b.refill_time_ms());
        };
        compare_buckets(net.rx_rate_limiter.bandwidth().unwrap(), &rx_bytes);
        compare_buckets(net.rx_rate_limiter.ops().unwrap(), &rx_ops);
        compare_buckets(net.tx_rate_limiter.bandwidth().unwrap(), &tx_bytes);
        compare_buckets(net.tx_rate_limiter.ops().unwrap(), &tx_ops);

        net.patch_rate_limiters(
            BucketUpdate::Disabled,
            BucketUpdate::Disabled,
            BucketUpdate::Disabled,
            BucketUpdate::Disabled,
        );
        assert!(net.rx_rate_limiter.bandwidth().is_none());
        assert!(net.rx_rate_limiter.ops().is_none());
        assert!(net.tx_rate_limiter.bandwidth().is_none());
        assert!(net.tx_rate_limiter.ops().is_none());
    }

    #[test]
    fn test_tx_queue_interrupt() {
        // Regression test for https://github.com/firecracker-microvm/firecracker/issues/1436 .
        let mut event_manager = EventManager::new().unwrap();
        let mut net = Net::default_net(TestMutators::default());
        let mem = Net::default_guest_memory();
        let (rxq, txq) = Net::virtqueues(&mem);
        net.assign_queues(rxq.create_queue(), txq.create_queue());
        net.activate(mem.clone()).unwrap();

        let daddr = 0x2000;
        assert!(daddr > txq.end().0);

        // Do some TX.
        txq.avail.idx.set(1);
        txq.avail.ring[0].set(0);
        txq.dtable[0].set(daddr, 0x1000, 0, 0);

        // trigger the TX handler
        net.queue_evts[TX_INDEX].write(1).unwrap();
        let tx_event = EpollEvent::new(EventSet::IN, net.queue_evts[TX_INDEX].as_raw_fd() as u64);
        net.process(&tx_event, &mut event_manager);

        // Verify if TX queue was processed.
        assert_eq!(txq.used.idx.get(), 1);
        // Check if interrupt was triggered.
        assert_eq!(net.interrupt_evt.read().unwrap(), 1);
    }

    #[test]
    fn test_virtio_device() {
        let mut net = Net::default_net(TestMutators::default());
        let mem = Net::default_guest_memory();
        let (rxq, txq) = Net::virtqueues(&mem);
        net.assign_queues(rxq.create_queue(), txq.create_queue());
        net.activate(mem.clone()).unwrap();

        // Test queues count (TX and RX).
        let queues = net.queues();
        assert_eq!(queues.len(), QUEUE_SIZES.len());
        assert_eq!(queues[RX_INDEX].size, rxq.size());
        assert_eq!(queues[TX_INDEX].size, txq.size());

        // Test corresponding queues events.
        assert_eq!(net.queue_events().len(), QUEUE_SIZES.len());

        // Test interrupts.
        let interrupt_status = net.interrupt_status();
        interrupt_status.fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);
        assert_eq!(
            interrupt_status.load(Ordering::SeqCst),
            VIRTIO_MMIO_INT_VRING as usize
        );

        net.interrupt_evt().write(1).unwrap();
        assert_eq!(net.interrupt_evt().read().unwrap() as usize, 1);
    }
}
