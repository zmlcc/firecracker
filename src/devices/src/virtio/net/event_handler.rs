// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::io::AsRawFd;

use logger::{Metric, METRICS};
use polly::event_manager::{EventManager, Subscriber};
use utils::epoll::{EpollEvent, EventSet};

use crate::virtio::net::device::Net;
use crate::virtio::{VirtioDevice, RX_INDEX, TX_INDEX};

impl Net {
    fn process_activate_event(&self, event_manager: &mut EventManager) {
        debug!("net: activate event");
        if let Err(e) = self.activate_evt.read() {
            error!("Failed to consume net activate event: {:?}", e);
        }
        let activate_fd = self.activate_evt.as_raw_fd();
        // The subscriber must exist as we previously registered activate_evt via
        // `interest_list()`.
        let self_subscriber = match event_manager.subscriber(activate_fd) {
            Ok(subscriber) => subscriber,
            Err(e) => {
                error!("Failed to process block activate evt: {:?}", e);
                return;
            }
        };

        // Interest list changes when the device is activated.
        let interest_list = self.interest_list();
        for event in interest_list {
            event_manager
                .register(event.data() as i32, event, self_subscriber.clone())
                .unwrap_or_else(|e| {
                    error!("Failed to register net events: {:?}", e);
                });
        }

        event_manager.unregister(activate_fd).unwrap_or_else(|e| {
            error!("Failed to unregister net activate evt: {:?}", e);
        });
    }
}

impl Subscriber for Net {
    fn process(&mut self, event: &EpollEvent, evmgr: &mut EventManager) {
        let source = event.fd();
        let event_set = event.event_set();

        // TODO: also check for errors. Pending high level discussions on how we want
        // to handle errors in devices.
        let supported_events = EventSet::IN;
        if !supported_events.contains(event_set) {
            warn!(
                "Received unknown event: {:?} from source: {:?}",
                event_set, source
            );
            return;
        }

        if self.is_activated() {
            let virtq_rx_ev_fd = self.queue_evts[RX_INDEX].as_raw_fd();
            let virtq_tx_ev_fd = self.queue_evts[TX_INDEX].as_raw_fd();
            let rx_rate_limiter_fd = self.rx_rate_limiter.as_raw_fd();
            let tx_rate_limiter_fd = self.tx_rate_limiter.as_raw_fd();
            let tap_fd = self.tap.as_raw_fd();
            let activate_fd = self.activate_evt.as_raw_fd();

            // Looks better than C style if/else if/else.
            match source {
                _ if source == virtq_rx_ev_fd => self.process_rx_queue_event(),
                _ if source == tap_fd => self.process_tap_rx_event(),
                _ if source == virtq_tx_ev_fd => self.process_tx_queue_event(),
                _ if source == rx_rate_limiter_fd => self.process_rx_rate_limiter_event(),
                _ if source == tx_rate_limiter_fd => self.process_tx_rate_limiter_event(),
                _ if activate_fd == source => self.process_activate_event(evmgr),
                _ => {
                    warn!("Net: Spurious event received: {:?}", source);
                    METRICS.net.event_fails.inc();
                }
            }
        } else {
            warn!(
                "Net: The device is not yet activated. Spurious event received: {:?}",
                source
            );
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        // This function can be called during different points in the device lifetime:
        //  - shortly after device creation,
        //  - on device activation (is-activated already true at this point),
        //  - on device restore from snapshot.
        if self.is_activated() {
            vec![
                EpollEvent::new(EventSet::IN, self.queue_evts[RX_INDEX].as_raw_fd() as u64),
                EpollEvent::new(EventSet::IN, self.queue_evts[TX_INDEX].as_raw_fd() as u64),
                EpollEvent::new(EventSet::IN, self.rx_rate_limiter.as_raw_fd() as u64),
                EpollEvent::new(EventSet::IN, self.tx_rate_limiter.as_raw_fd() as u64),
                EpollEvent::new(
                    EventSet::IN | EventSet::EDGE_TRIGGERED,
                    self.tap.as_raw_fd() as u64,
                ),
            ]
        } else {
            vec![EpollEvent::new(
                EventSet::IN,
                self.activate_evt.as_raw_fd() as u64,
            )]
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::virtio::net::device::tests::*;

    #[test]
    fn test_event_handler() {
        let mut event_manager = EventManager::new().unwrap();
        let mut net = Net::default_net(TestMutators::default());
        let mem = Net::default_guest_memory();
        let (rxq, txq) = Net::virtqueues(&mem);
        net.assign_queues(rxq.create_queue(), txq.create_queue());

        let net = Arc::new(Mutex::new(net));
        event_manager.add_subscriber(net.clone()).unwrap();

        // Push a queue event, use the TX_QUEUE_EVENT in this test.
        {
            let daddr = 0x2000;
            assert!(daddr > txq.end().0);

            txq.avail.idx.set(1);
            txq.avail.ring[0].set(0);
            txq.dtable[0].set(daddr, 0x1000, 0, 0);

            net.lock().unwrap().queue_evts[TX_INDEX].write(1).unwrap();
        }

        // EventManager should report no events since net has only registered
        // its activation event so far (even though there is also a queue event pending).
        let ev_count = event_manager.run_with_timeout(50).unwrap();
        assert_eq!(ev_count, 0);

        // Manually force a queue event and check it's ignored pre-activation.
        {
            let mut n = net.lock().unwrap();
            let raw_txq_evt = n.queue_evts[TX_INDEX].as_raw_fd() as u64;
            // Artificially push event.
            n.process(
                &EpollEvent::new(EventSet::IN, raw_txq_evt),
                &mut event_manager,
            );
            // Validate there was no queue operation.
            assert_eq!(txq.used.idx.get(), 0);
        }

        // Now activate the device.
        net.lock().unwrap().activate(mem.clone()).unwrap();
        // Process the activate event.
        let ev_count = event_manager.run_with_timeout(50).unwrap();
        assert_eq!(ev_count, 1);

        // Handle the previously pushed queue event through EventManager.
        event_manager
            .run_with_timeout(100)
            .expect("Metrics event timeout or error.");
        // Make sure the data queue advanced.
        assert_eq!(txq.used.idx.get(), 1);
    }
}
