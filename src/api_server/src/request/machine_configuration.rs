// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0<Paste>

use super::super::VmmAction;
use logger::{Metric, METRICS};
use parsed_request::{method_to_error, Error, ParsedRequest};
use request::{Body, Method, StatusCode};
use vmm::vmm_config::machine_config::VmConfig;

pub fn parse_get_machine_config() -> Result<ParsedRequest, Error> {
    METRICS.get_api_requests.machine_cfg_count.inc();
    Ok(ParsedRequest::new_sync(VmmAction::GetVmConfiguration))
}

pub fn parse_put_machine_config(body: &Body) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.machine_cfg_count.inc();
    let vm_config = serde_json::from_slice::<VmConfig>(body.raw()).map_err(|e| {
        METRICS.put_api_requests.machine_cfg_fails.inc();
        Error::SerdeJson(e)
    })?;
    if vm_config.vcpu_count.is_none()
        || vm_config.mem_size_mib.is_none()
        || vm_config.ht_enabled.is_none()
    {
        return Err(Error::Generic(
            StatusCode::BadRequest,
            "Missing mandatory fields.".to_string(),
        ));
    }
    Ok(ParsedRequest::new_sync(VmmAction::SetVmConfiguration(
        vm_config,
    )))
}

pub fn parse_patch_machine_config(body: &Body) -> Result<ParsedRequest, Error> {
    METRICS.patch_api_requests.machine_cfg_count.inc();
    let vm_config = serde_json::from_slice::<VmConfig>(body.raw()).map_err(|e| {
        METRICS.patch_api_requests.machine_cfg_fails.inc();
        Error::SerdeJson(e)
    })?;
    if vm_config.vcpu_count.is_none()
        && vm_config.mem_size_mib.is_none()
        && vm_config.cpu_template.is_none()
        && vm_config.ht_enabled.is_none()
    {
        return method_to_error(Method::Patch);
    }
    Ok(ParsedRequest::new_sync(VmmAction::SetVmConfiguration(
        vm_config,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsed_request::tests::vmm_action_from_request;

    use vmm::vmm_config::machine_config::CpuFeaturesTemplate;

    #[test]
    fn test_parse_get_machine_config_request() {
        assert!(parse_get_machine_config().is_ok());
    }

    #[test]
    fn test_parse_put_machine_config_request() {
        assert!(parse_put_machine_config(&Body::new("invalid_payload")).is_err());

        let mut body = r#"{
                "vcpu_count": 8,
                "mem_size_mib": 1024,
                "ht_enabled": true,
                "cpu_template": "T2",
                "track_dirty_pages": true
              }"#;

        let mut expected_config = VmConfig {
            vcpu_count: Some(8),
            mem_size_mib: Some(1024),
            ht_enabled: Some(true),
            cpu_template: Some(CpuFeaturesTemplate::T2),
            track_dirty_pages: true,
        };
        match vmm_action_from_request(parse_put_machine_config(&Body::new(body)).unwrap()) {
            VmmAction::SetVmConfiguration(config) => assert_eq!(config, expected_config),
            _ => panic!("Test failed."),
        }

        body = r#"{
                "vcpu_count": 8,
                "mem_size_mib": 1024,
                "ht_enabled": true
              }"#;
        expected_config = VmConfig {
            vcpu_count: Some(8),
            mem_size_mib: Some(1024),
            ht_enabled: Some(true),
            cpu_template: None,
            track_dirty_pages: false,
        };
        match vmm_action_from_request(parse_put_machine_config(&Body::new(body)).unwrap()) {
            VmmAction::SetVmConfiguration(config) => assert_eq!(config, expected_config),
            _ => panic!("Test failed."),
        }

        body = r#"{
                "vcpu_count": 8,
                "mem_size_mib": 1024
              }"#;
        assert!(parse_put_machine_config(&Body::new(body)).is_err());
    }

    #[test]
    fn test_parse_patch_machine_config_request() {
        assert!(parse_patch_machine_config(&Body::new("invalid_payload")).is_err());

        let body = r#"{}"#;
        assert!(parse_patch_machine_config(&Body::new(body)).is_err());

        let body = r#"{
                "vcpu_count": 8,
                "mem_size_mib": 1024
              }"#;
        assert!(parse_patch_machine_config(&Body::new(body)).is_ok());
        let body = r#"{
                "vcpu_count": 8,
                "mem_size_mib": 1024,
                "ht_enabled": false
              }"#;
        assert!(parse_patch_machine_config(&Body::new(body)).is_ok());
    }
}
