use std::result;
use std::fmt::{Display, Formatter};
use std::sync::{Arc, Mutex};

use devices::virtio::vhost::net::VhostNetDevice;

use dumbo::MacAddr;

type Result<T> = result::Result<T, VhostNetError>;

/// Errors associated with the operations allowed on a vublock.
#[derive(Debug)]
pub enum VhostNetError {
    /// Unable to create block device
    CreateVhostNetDevice(devices::virtio::vhost::Error)

}

impl Display for VhostNetError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::VhostNetError::*;
        match *self {
            CreateVhostNetDevice(ref e) => write!(
                f,
                "Unable to create vhost net device: {:?}",
                e
            )
        }
    }
}

/// This struct represents the strongly typed equivalent of the json body
/// from vhost user block related requests.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VhostNetConfig {
    /// ID of the guest network interface.
    pub iface_id: String,
    /// Host level path for the guest network interface.
    pub host_dev_name: String,
    /// Guest MAC address.
    pub guest_mac: Option<MacAddr>,
}



/// Wrapper for the collection that holds all the vhost user block  Devices
#[derive(Default)]
pub struct VhostNetBuilder {
    /// devices list
    pub list: Vec<Arc<Mutex<VhostNetDevice>>>,
}


impl VhostNetBuilder {

    /// Gets the index of the device with the specified `vublock_id` if it exists in the list.
    fn get_index_of_iface_id(&self, vublock_id: &str) -> Option<usize> {
        self.list
            .iter()
            .position(|b| b.lock().unwrap().id().eq(vublock_id))
    }

    /// Returns a immutable iterator over the vhost user block devices.
    pub fn iter(&self) -> ::std::slice::Iter<Arc<Mutex<VhostNetDevice>>> {
        self.list.iter()
    }

    /// Inserts a `Block` in the vhost user block devices list using the specified configuration.
    /// If a block with the same id already exists, it will overwrite it.
    pub fn insert(&mut self, config: VhostNetConfig) -> Result<()> {
        let position = self.get_index_of_iface_id(&config.iface_id);
        let block_dev = Arc::new(Mutex::new(Self::create_block(config)?));
        match position {
            // New block device
            None => {
                self.list.push(block_dev)
            }
             // Update existing block device.
             Some(index) => {
                self.list[index]  = block_dev;
             }
        }
        Ok(())
    }

    /// Creates a Block device from a VhostNetConfig.
    pub fn create_block(config: VhostNetConfig) -> Result<VhostNetDevice> {
        let ret = devices::virtio::vhost::net::VhostNetDevice::new_with_tap(config.iface_id, &config.host_dev_name, config.guest_mac.as_ref());
        ret.map_err(VhostNetError::CreateVhostNetDevice)
    }
}
