use std::collections::HashMap;

use ureq::unversioned::multipart::{Form, Part};

use crate::error::{Error, Result};

/// Upload bytes to a paste service via multipart form upload.
/// Returns the URL of the uploaded paste.
pub fn send(data: &[u8], url: &str, headers: &HashMap<String, String>) -> Result<String> {
    let form = Form::new()
        .part("file", Part::bytes(data).file_name("envstash-share.env"));

    let mut req = ureq::post(url);
    for (key, value) in headers {
        req = req.header(key.as_str(), value.as_str());
    }

    let mut response = req
        .send(form)
        .map_err(|e| Error::Other(format!("upload failed: {e}")))?;

    let body = response
        .body_mut()
        .read_to_string()
        .map_err(|e| Error::Other(format!("failed to read response: {e}")))?;

    let url = body.trim().to_string();
    if url.is_empty() {
        return Err(Error::Other(
            "paste service returned empty response".to_string(),
        ));
    }

    Ok(url)
}

/// Fetch bytes from a URL via HTTP GET.
pub fn fetch(url: &str, headers: &HashMap<String, String>) -> Result<Vec<u8>> {
    let mut req = ureq::get(url);
    for (key, value) in headers {
        req = req.header(key.as_str(), value.as_str());
    }

    let mut response = req
        .call()
        .map_err(|e| Error::Other(format!("fetch failed: {e}")))?;

    let buf = response
        .body_mut()
        .read_to_vec()
        .map_err(|e| Error::Other(format!("failed to read response: {e}")))?;

    Ok(buf)
}
