// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::result;
/// This is the `VirtioDevice` implementation for our vsock device. It handles the virtio-level
/// device logic: feature negociation, device configuration, and device activation.
///
/// We aim to conform to the VirtIO v1.1 spec:
/// https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html
///
/// The vsock device has two input parameters: a CID to identify the device, and a `VsockBackend`
/// to use for offloading vsock traffic.
///
/// Upon its activation, the vsock device registers handlers for the following events/FDs:
/// - an RX queue FD;
/// - a TX queue FD;
/// - an event queue FD; and
/// - a backend FD.
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use logger::{Metric, METRICS};
use utils::byte_order;
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryMmap;

use super::super::super::Error as DeviceError;
use super::super::{
    ActivateError, ActivateResult, DeviceState, Queue as VirtQueue, VirtioDevice, VsockError,
    VIRTIO_MMIO_INT_VRING,
};
use super::packet::VsockPacket;
use super::VsockBackend;
use super::{defs, defs::uapi};

pub(crate) const RXQ_INDEX: usize = 0;
pub(crate) const TXQ_INDEX: usize = 1;
pub(crate) const EVQ_INDEX: usize = 2;

/// The virtio features supported by our vsock device:
/// - VIRTIO_F_VERSION_1: the device conforms to at least version 1.0 of the VirtIO spec.
/// - VIRTIO_F_IN_ORDER: the device returns used buffers in the same order that the driver makes
///   them available.
pub(crate) const AVAIL_FEATURES: u64 =
    1 << uapi::VIRTIO_F_VERSION_1 as u64 | 1 << uapi::VIRTIO_F_IN_ORDER as u64;

pub struct Vsock<B> {
    cid: u64,
    pub(crate) queues: Vec<VirtQueue>,
    pub(crate) queue_events: Vec<EventFd>,
    pub(crate) backend: B,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) interrupt_status: Arc<AtomicUsize>,
    pub(crate) interrupt_evt: EventFd,
    // This EventFd is the only one initially registered for a vsock device, and is used to convert
    // a VirtioDevice::activate call into an EventHandler read event which allows the other events
    // (queue and backend related) to be registered post virtio device activation. That's
    // mostly something we wanted to happen for the backend events, to prevent (potentially)
    // continuous triggers from happening before the device gets activated.
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,
}

// TODO: Detect / handle queue deadlock:
// 1. If the driver halts RX queue processing, we'll need to notify `self.backend`, so that it
//    can unregister any EPOLLIN listeners, since otherwise it will keep spinning, unable to consume
//    its EPOLLIN events.

impl<B> Vsock<B>
where
    B: VsockBackend,
{
    pub(crate) fn with_queues(
        cid: u64,
        backend: B,
        queues: Vec<VirtQueue>,
    ) -> super::Result<Vsock<B>> {
        let mut queue_events = Vec::new();
        for _ in 0..queues.len() {
            queue_events.push(EventFd::new(libc::EFD_NONBLOCK).map_err(VsockError::EventFd)?);
        }

        Ok(Vsock {
            cid,
            queues,
            queue_events,
            backend,
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            interrupt_status: Arc::new(AtomicUsize::new(0)),
            interrupt_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(VsockError::EventFd)?,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(VsockError::EventFd)?,
            device_state: DeviceState::Inactive,
        })
    }

    /// Create a new virtio-vsock device with the given VM CID and vsock backend.
    pub fn new(cid: u64, backend: B) -> super::Result<Vsock<B>> {
        let queues: Vec<VirtQueue> = defs::QUEUE_SIZES
            .iter()
            .map(|&max_size| VirtQueue::new(max_size))
            .collect();
        Self::with_queues(cid, backend, queues)
    }

    pub fn id(&self) -> &str {
        defs::VSOCK_DEV_ID
    }

    pub fn cid(&self) -> u64 {
        self.cid
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Signal the guest driver that we've used some virtio buffers that it had previously made
    /// available.
    pub fn signal_used_queue(&self) -> result::Result<(), DeviceError> {
        debug!("vsock: raising IRQ");
        self.interrupt_status
            .fetch_or(VIRTIO_MMIO_INT_VRING as usize, Ordering::SeqCst);
        self.interrupt_evt.write(1).map_err(|e| {
            error!("Failed to signal used queue: {:?}", e);
            DeviceError::FailedSignalingUsedQueue(e)
        })
    }

    /// Walk the driver-provided RX queue buffers and attempt to fill them up with any data that we
    /// have pending. Return `true` if descriptors have been added to the used ring, and `false`
    /// otherwise.
    pub fn process_rx(&mut self) -> bool {
        debug!("vsock: process_rx()");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        let mut have_used = false;

        while let Some(head) = self.queues[RXQ_INDEX].pop(mem) {
            let used_len = match VsockPacket::from_rx_virtq_head(&head) {
                Ok(mut pkt) => {
                    if self.backend.recv_pkt(&mut pkt).is_ok() {
                        pkt.hdr().len() as u32 + pkt.len()
                    } else {
                        // We are using a consuming iterator over the virtio buffers, so, if we can't
                        // fill in this buffer, we'll need to undo the last iterator step.
                        self.queues[RXQ_INDEX].undo_pop();
                        break;
                    }
                }
                Err(e) => {
                    warn!("vsock: RX queue error: {:?}", e);
                    0
                }
            };

            have_used = true;
            self.queues[RXQ_INDEX].add_used(mem, head.index, used_len);
        }

        have_used
    }

    /// Walk the driver-provided TX queue buffers, package them up as vsock packets, and send them
    /// to the backend for processing. Return `true` if descriptors have been added to the used
    /// ring, and `false` otherwise.
    pub fn process_tx(&mut self) -> bool {
        debug!("vsock::process_tx()");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        let mut have_used = false;

        while let Some(head) = self.queues[TXQ_INDEX].pop(mem) {
            let pkt = match VsockPacket::from_tx_virtq_head(&head) {
                Ok(pkt) => pkt,
                Err(e) => {
                    error!("vsock: error reading TX packet: {:?}", e);
                    have_used = true;
                    self.queues[TXQ_INDEX].add_used(mem, head.index, 0);
                    continue;
                }
            };

            if self.backend.send_pkt(&pkt).is_err() {
                self.queues[TXQ_INDEX].undo_pop();
                break;
            }

            have_used = true;
            self.queues[TXQ_INDEX].add_used(mem, head.index, 0);
        }

        have_used
    }
}

impl<B> VirtioDevice for Vsock<B>
where
    B: VsockBackend + 'static,
{
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
    }

    fn device_type(&self) -> u32 {
        uapi::VIRTIO_ID_VSOCK
    }

    fn queues(&self) -> &[VirtQueue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [VirtQueue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_events
    }

    fn interrupt_evt(&self) -> &EventFd {
        &self.interrupt_evt
    }

    fn interrupt_status(&self) -> Arc<AtomicUsize> {
        self.interrupt_status.clone()
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        match offset {
            0 if data.len() == 8 => byte_order::write_le_u64(data, self.cid()),
            0 if data.len() == 4 => {
                byte_order::write_le_u32(data, (self.cid() & 0xffff_ffff) as u32)
            }
            4 if data.len() == 4 => {
                byte_order::write_le_u32(data, ((self.cid() >> 32) & 0xffff_ffff) as u32)
            }
            _ => {
                METRICS.vsock.cfg_fails.inc();
                warn!(
                    "vsock: virtio-vsock received invalid read request of {} bytes at offset {}",
                    data.len(),
                    offset
                )
            }
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        METRICS.vsock.cfg_fails.inc();
        warn!(
            "vsock: guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(&mut self, mem: GuestMemoryMmap) -> ActivateResult {
        if self.queues.len() != defs::NUM_QUEUES {
            METRICS.vsock.activate_fails.inc();
            error!(
                "Cannot perform activate. Expected {} queue(s), got {}",
                defs::NUM_QUEUES,
                self.queues.len()
            );
            return Err(ActivateError::BadActivate);
        }

        if self.activate_evt.write(1).is_err() {
            METRICS.vsock.activate_fails.inc();
            error!("Cannot write to activate_evt",);
            return Err(ActivateError::BadActivate);
        }

        self.device_state = DeviceState::Activated(mem);

        Ok(())
    }

    fn is_activated(&self) -> bool {
        match self.device_state {
            DeviceState::Inactive => false,
            DeviceState::Activated(_) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::TestContext;
    use super::*;
    use crate::virtio::vsock::defs::uapi;

    #[test]
    fn test_virtio_device() {
        let mut ctx = TestContext::new();
        let device_features = AVAIL_FEATURES;
        let driver_features: u64 = AVAIL_FEATURES | 1 | (1 << 32);
        let device_pages = [
            (device_features & 0xffff_ffff) as u32,
            (device_features >> 32) as u32,
        ];
        let driver_pages = [
            (driver_features & 0xffff_ffff) as u32,
            (driver_features >> 32) as u32,
        ];
        assert_eq!(ctx.device.device_type(), uapi::VIRTIO_ID_VSOCK);
        assert_eq!(ctx.device.avail_features_by_page(0), device_pages[0]);
        assert_eq!(ctx.device.avail_features_by_page(1), device_pages[1]);
        assert_eq!(ctx.device.avail_features_by_page(2), 0);

        // Ack device features, page 0.
        ctx.device.ack_features_by_page(0, driver_pages[0]);
        // Ack device features, page 1.
        ctx.device.ack_features_by_page(1, driver_pages[1]);
        // Ack some bogus page (i.e. 2). This should have no side effect.
        ctx.device.ack_features_by_page(2, 0);
        // Attempt to un-ack the first feature page. This should have no side effect.
        ctx.device.ack_features_by_page(0, !driver_pages[0]);
        // Check that no side effect are present, and that the acked features are exactly the same
        // as the device features.
        assert_eq!(ctx.device.acked_features, device_features & driver_features);

        // Test reading 32-bit chunks.
        let mut data = [0u8; 8];
        ctx.device.read_config(0, &mut data[..4]);
        assert_eq!(
            u64::from(byte_order::read_le_u32(&data[..])),
            ctx.cid & 0xffff_ffff
        );
        ctx.device.read_config(4, &mut data[4..]);
        assert_eq!(
            u64::from(byte_order::read_le_u32(&data[4..])),
            (ctx.cid >> 32) & 0xffff_ffff
        );

        // Test reading 64-bit.
        let mut data = [0u8; 8];
        ctx.device.read_config(0, &mut data);
        assert_eq!(byte_order::read_le_u64(&data), ctx.cid);

        // Check that out-of-bounds reading doesn't mutate the destination buffer.
        let mut data = [0u8, 1, 2, 3, 4, 5, 6, 7];
        ctx.device.read_config(2, &mut data);
        assert_eq!(data, [0u8, 1, 2, 3, 4, 5, 6, 7]);

        // Just covering lines here, since the vsock device has no writable config.
        // A warning is, however, logged, if the guest driver attempts to write any config data.
        ctx.device.write_config(0, &data[..4]);

        // Test a bad activation.
        // let bad_activate = ctx.device.activate(
        //     ctx.mem.clone(),
        // );
        // match bad_activate {
        //     Err(ActivateError::BadActivate) => (),
        //     other => panic!("{:?}", other),
        // }

        // Test a correct activation.
        ctx.device.activate(ctx.mem.clone()).unwrap();
    }
}
