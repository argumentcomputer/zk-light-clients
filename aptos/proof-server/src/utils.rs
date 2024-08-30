// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: BUSL-1.1

use anyhow::Result;
use url::Url;

/// Validates and formats a URL. If the URL is relative, it will be prefixed
/// with `http://`.
pub fn validate_and_format_url(url: &str) -> Result<String, url::ParseError> {
    let parsed_url = match Url::parse(url) {
        Ok(parsed_url) => parsed_url,
        Err(url::ParseError::RelativeUrlWithoutBase) => Url::parse(&format!("http://{}", url))?,
        Err(e) => return Err(e),
    };

    if !parsed_url.has_host() {
        return Err(url::ParseError::EmptyHost);
    }

    Ok(parsed_url.into())
}
