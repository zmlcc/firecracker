use super::super::VmmAction;
use request::{Body, StatusCode};
use parsed_request::{checked_id, Error, ParsedRequest};
use vmm::vmm_config::vhost_net::VhostNetConfig;

pub fn parse_put_vhost_net(body: &Body, id_from_path: Option<&&str>) -> Result<ParsedRequest, Error> {
    let id = match id_from_path {
        Some(&id) => checked_id(id)?,
        None => {
            return Err(Error::EmptyID);
        }
    };

    let config = serde_json::from_slice::<VhostNetConfig>(body.raw()).map_err(|e| {
        Error::SerdeJson(e)
    })?;
    if id != config.iface_id.as_str() {
        return Err(Error::Generic(
            StatusCode::BadRequest,
            "The id from the path does not match the id from the body!".to_string(),
        ));
    }
    Ok(ParsedRequest::Sync(Box::new(VmmAction::InsertVhostNetDevice(config))))
}
