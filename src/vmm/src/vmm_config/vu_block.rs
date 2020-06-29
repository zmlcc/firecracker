use std::result;
use std::fmt::{Display, Formatter};
use std::sync::{Arc, Mutex};

use devices::virtio::VhostUserBlock;

type Result<T> = result::Result<T, VuBlockError>;

/// Errors associated with the operations allowed on a drive.
#[derive(Debug)]
pub enum VuBlockError {
    /// Unable to create block device
    CreateBlockDevice(devices::virtio::vhost_user::VuError)

}

impl Display for VuBlockError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::VuBlockError::*;
        match *self {
            CreateBlockDevice(ref e) => write!(
                f,
                "Unable to create vhost user block device: {:?}",
                e
            )
        }
    }
}

/// This struct represents the strongly typed equivalent of the json body
/// from vhost user block related requests.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VuBlockConfig {
    /// ID of the vtfs device.
    pub drive_id: String,
    /// Path of the drive.
    pub socket_path: String,
}



/// Wrapper for the collection that holds all the vhost user block  Devices
#[derive(Default)]
pub struct VuBlockBuilder {
    /// devices list
    pub list: Vec<Arc<Mutex<VhostUserBlock>>>,
}


impl VuBlockBuilder {

    /// Gets the index of the device with the specified `drive_id` if it exists in the list.
    fn get_index_of_drive_id(&self, drive_id: &str) -> Option<usize> {
        self.list
            .iter()
            .position(|b| b.lock().unwrap().id().eq(drive_id))
    }

    /// Returns a immutable iterator over the vhost user block devices.
    pub fn iter(&self) -> ::std::slice::Iter<Arc<Mutex<VhostUserBlock>>> {
        self.list.iter()
    }

    /// Inserts a `Block` in the vhost user block devices list using the specified configuration.
    /// If a block with the same id already exists, it will overwrite it.
    pub fn insert(&mut self, config: VuBlockConfig) -> Result<()> {
        let position = self.get_index_of_drive_id(&config.drive_id);
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

    /// Creates a Block device from a VuBlockConfig.
    pub fn create_block(config: VuBlockConfig) -> Result<VhostUserBlock> {
        let ret = devices::virtio::VhostUserBlock::new(config.drive_id, &config.socket_path);
        ret.map_err(VuBlockError::CreateBlockDevice)
    }
}
