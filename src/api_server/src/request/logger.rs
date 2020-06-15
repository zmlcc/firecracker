// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::super::VmmAction;
use logger::{Metric, METRICS};
use parsed_request::{Error, ParsedRequest};
use request::Body;
use vmm::vmm_config::logger::LoggerConfig;

pub fn parse_put_logger(body: &Body) -> Result<ParsedRequest, Error> {
    METRICS.put_api_requests.logger_count.inc();
    Ok(ParsedRequest::new_sync(VmmAction::ConfigureLogger(
        serde_json::from_slice::<LoggerConfig>(body.raw()).map_err(|e| {
            METRICS.put_api_requests.logger_fails.inc();
            Error::SerdeJson(e)
        })?,
    )))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::parsed_request::tests::vmm_action_from_request;
    use vmm::vmm_config::logger::LoggerLevel;

    #[test]
    fn test_parse_put_logger_request() {
        let body = r#"{
                "log_path": "log",
                "level": "Warning",
                "show_level": false,
                "show_log_origin": false
              }"#;

        let expected_cfg = LoggerConfig {
            log_path: PathBuf::from("log"),
            level: LoggerLevel::Warning,
            show_level: false,
            show_log_origin: false,
        };
        match vmm_action_from_request(parse_put_logger(&Body::new(body)).unwrap()) {
            VmmAction::ConfigureLogger(cfg) => assert_eq!(cfg, expected_cfg),
            _ => panic!("Test failed."),
        }

        let invalid_body = r#"{
                "invalid_field": "log",
                "level": "Warning",
                "show_level": false,
                "show_log_origin": false
              }"#;

        assert!(parse_put_logger(&Body::new(invalid_body)).is_err());
    }
}
