use polly::event_manager::{EventManager, Subscriber};
use utils::epoll::{EpollEvent, EventSet};

use crate::virtio::vhost_user::block::VhostUserBlock;

use std::os::unix::io::AsRawFd;

use crate::virtio::device::VirtioDevice;

impl Subscriber for VhostUserBlock {
    fn process(&mut self, event: &EpollEvent, _event_manager: &mut EventManager) {
        let source = event.fd();
        let event_set = event.event_set();

        // TODO: also check for errors. Pending high level discussions on how we want
        // to handle errors in devices.
        let supported_events = EventSet::IN;
        if !supported_events.contains(event_set) {
            warn!(
                "Block: Received unknown event: {:?} from source: {:?}",
                event_set, source
            );
            return;
        }

        if self.is_activated() {
            // just send irq.
            let _ = self.signal_used_queue();
        } else {
            warn!(
                "Block: The device is not yet activated. Spurious event received: {:?}",
                source
            );
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        self.call_evts
            .iter()
            .map(|evt| {
                EpollEvent::new(
                    EventSet::IN | EventSet::EDGE_TRIGGERED,
                    evt.as_raw_fd() as u64,
                )
            })
            .collect()
    }
}
