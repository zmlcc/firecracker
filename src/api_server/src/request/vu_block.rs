use super::super::VmmAction;
use request::{Body, StatusCode};
use parsed_request::{checked_id, Error, ParsedRequest};
use vmm::vmm_config::vu_block::VuBlockConfig;

pub fn parse_put_vublock(body: &Body, id_from_path: Option<&&str>) -> Result<ParsedRequest, Error> {
    let id = match id_from_path {
        Some(&id) => checked_id(id)?,
        None => {
            return Err(Error::EmptyID);
        }
    };

    let config = serde_json::from_slice::<VuBlockConfig>(body.raw()).map_err(|e| {
        Error::SerdeJson(e)
    })?;
    if id != config.vublock_id.as_str() {
        return Err(Error::Generic(
            StatusCode::BadRequest,
            "The id from the path does not match the id from the body!".to_string(),
        ));
    }
    Ok(ParsedRequest::Sync(Box::new(VmmAction::InsertVuBlockDevice(config))))
}
