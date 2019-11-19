// Copyright 2019 UCloud.cn, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::VmmAction;
use request::{checked_id, Body, Error, ParsedRequest, StatusCode};
use vmm::vmm_config::vtfs::VtfsDeviceConfig;

pub fn parse_put_vtfs(body: &Body, id_from_path: Option<&&str>) -> Result<ParsedRequest, Error> {
    let id = match id_from_path {
        Some(&id) => checked_id(id)?,
        None => {
            return Err(Error::EmptyID);
        }
    };

    let vtfs_cfg = serde_json::from_slice::<VtfsDeviceConfig>(body.raw()).map_err(|e| {
        Error::SerdeJson(e)
    })?;
    if id != vtfs_cfg.drive_id.as_str() {
        return Err(Error::Generic(
            StatusCode::BadRequest,
            "The id from the path does not match the id from the body!".to_string(),
        ));
    }
    Ok(ParsedRequest::Sync(VmmAction::InsertVtfsDevice(vtfs_cfg)))
}

