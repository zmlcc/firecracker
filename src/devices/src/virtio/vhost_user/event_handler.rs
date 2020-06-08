use polly::event_manager::{EventManager, Subscriber};
use utils::epoll::{EpollEvent, EventSet};

use crate::virtio::vhost_user::block::VhostUserBlock;

use std::os::unix::io::AsRawFd;

use crate::virtio::device::VirtioDevice;

impl Subscriber for VhostUserBlock {
    fn process(&mut self, event: &EpollEvent, event_manager: &mut EventManager) {
        let source = event.fd();
        let event_set = event.event_set();

        // TODO: also check for errors. Pending high level discussions on how we want
        // to handle errors in devices.
        // let supported_events = EventSet::IN;
        // if !supported_events.contains(event_set) {
        //     warn!(
        //         "Block: Received unknown event: {:?} from source: {:?}",
        //         event_set, source
        //     );
        //     return;
        // }

        if self.is_activated() {
            // just send irq.

            let vu_master_fd = self.vhost_user_master.as_raw_fd();

            match source {
                _ if source == vu_master_fd => {
                    println!("FUCK MASTER IS LOST {:?}", event_set);
                    self.reconnect();
                    let self_subscriber = event_manager.subscriber(source).unwrap();
                    event_manager
                        .register(
                            self.vhost_user_master.as_raw_fd(),
                            EpollEvent::new(
                                EventSet::READ_HANG_UP | EventSet::ONE_SHOT,
                                self.vhost_user_master.as_raw_fd() as u64,
                            ),
                            self_subscriber
                        )
                        .unwrap_or_else(|e| {
                            error!("Failed to register block queue with event manager: {:?}", e);
                        });
                    event_manager.unregister(source).unwrap_or_else(|e| {
                        error!("Failed to unregister block activate evt: {:?}", e);
                    })
                }
                _ if self.call_evts.iter().any(|x| source == x.as_raw_fd()) => {
                    println!("FUCK call signal {:?}", event_set);
                    if event_set.contains(EventSet::IN) {
                        let _ = self.signal_used_queue();
                    }
                }
                _ => warn!("VhostUserBlock: Spurious event received: {:?}", source),
            }
        } else {
            warn!(
                "Block: The device is not yet activated. Spurious event received: {:?}",
                source
            );
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        let mut vec: Vec<_> = self
            .call_evts
            .iter()
            .map(|evt| {
                EpollEvent::new(
                    EventSet::IN | EventSet::EDGE_TRIGGERED,
                    evt.as_raw_fd() as u64,
                )
            })
            .collect();
        vec.push(EpollEvent::new(
            EventSet::READ_HANG_UP | EventSet::ONE_SHOT,
            self.vhost_user_master.as_raw_fd() as u64,
        ));
        vec
    }
}
