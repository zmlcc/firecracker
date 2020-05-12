
use polly::event_manager::{EventManager, Subscriber};
use utils::epoll::{EpollEvent, EventSet};

use crate::virtio::vhost_user::block::VhostUserBlock;

use std::os::unix::io::AsRawFd;

use crate::virtio::device::VirtioDevice;

impl Subscriber for VhostUserBlock {
    fn process(&mut self, event: &EpollEvent, event_manager: &mut EventManager){
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
            // let queue_evt = self.queue_evts[0].as_raw_fd();
            // let rate_limiter_evt = self.rate_limiter.as_raw_fd();
            // let activate_fd = self.activate_evt.as_raw_fd();

            // // Looks better than C style if/else if/else.
            // match source {
            //     _ if queue_evt == source => self.process_queue_event(),
            //     _ if rate_limiter_evt == source => self.process_rate_limiter_event(),
            //     _ if activate_fd == source => self.process_activate_event(evmgr),
            //     _ => warn!("Block: Spurious event received: {:?}", source),
            // }

            self.signal_used_queue();

        } else {
            warn!(
                "Block: The device is not yet activated. Spurious event received: {:?}",
                source
            );
        }
    }

    fn interest_list(&self) -> Vec<EpollEvent> {
        // vec![EpollEvent::new(
        //     EventSet::IN,
        //     self.interrupt_evt.as_raw_fd() as u64,
        // )]
        self.call_evts.iter().map(|evt| {
            EpollEvent::new(EventSet::IN, evt.as_raw_fd() as u64)
        }).collect()
    }
}