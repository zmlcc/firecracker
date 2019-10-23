// Copyright 2019 UCloud.cn, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::result;

use futures::sync::oneshot;
use hyper::Method;

use request::{IntoParsedRequest, ParsedRequest};
use vmm::vmm_config::vtfs::VtfsDeviceConfig;
use super::{VmmAction, VmmRequest};

impl IntoParsedRequest for VtfsDeviceConfig {
    fn into_parsed_request(
        self,
        id_from_path: Option<String>,
        _: Method,
    ) -> result::Result<ParsedRequest, String> {
        let id_from_path = id_from_path.unwrap_or_default();
        if id_from_path != self.drive_id.as_str() {
            return Err(String::from(
                "The id from the path does not match the id from the body!",
            ));
        }

        let (sender, receiver) = oneshot::channel();
        Ok(ParsedRequest::Sync(
            VmmRequest::new(
            VmmAction::InsertVtfsDevice(self), sender),
            receiver,
        ))
    }
}

#[cfg(test)]
mod tests {

}
