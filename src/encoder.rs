use crate::signature::{SignatureClass, SignatureTypes};
use crate::JwtHeader;
use anyhow::{anyhow, Result};
use base64::URL_SAFE_NO_PAD;
use serde_json::Value;

pub fn encode_payload(header: &str, claims: &str) -> String {
    // Try minifying the JSONs - if it fails due to invalid JSON syntax
    // then just b64 encode what we're given
    let encoded_header =
        if let Ok(parsed) = serde_json::from_str::<Value>(header) {
            base64::encode_config(parsed.to_string(), URL_SAFE_NO_PAD)
        } else {
            base64::encode_config(header, URL_SAFE_NO_PAD)
        };
    let encoded_claims =
        if let Ok(parsed) = serde_json::from_str::<Value>(claims) {
            base64::encode_config(parsed.to_string(), URL_SAFE_NO_PAD)
        } else {
            base64::encode_config(claims, URL_SAFE_NO_PAD)
        };

    format!(
        "{}.{}",
        encoded_header.trim_end_matches('='),
        encoded_claims.trim_end_matches('=')
    )
}

pub fn encode_and_sign(
    header: &str,
    claims: &str,
    secret: &str,
    private_key: &str,
    original_signature: &str,
    mut hash_type: SignatureTypes,
) -> Result<String> {
    // If hash type is auto then try to parse the header and pick the
    // correct hash type
    if hash_type == SignatureTypes::Auto {
        let jwt_header: JwtHeader = serde_json::from_str(header)?;
        hash_type =
            SignatureTypes::from_header(&jwt_header).ok_or_else(|| {
                anyhow!("Unrecognised signature type `{}`", jwt_header.alg)
            })?;
    }
    let key = match hash_type.class(header) {
        SignatureClass::Hmac => secret,
        SignatureClass::Pubkey => private_key,
        SignatureClass::Other => "",
    };
    let payload = encode_payload(header, claims);
    let signature = crate::signature::calc_signature(
        &payload,
        key,
        original_signature,
        hash_type,
    )?;

    Ok(format!("{}.{}", payload, signature))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test::init;

    #[test]
    fn encode_payload_invalid_json() {
        init();

        let header = "this isn't json";
        let claims = "also not json";
        let target = "dGhpcyBpc24ndCBqc29u.YWxzbyBub3QganNvbg";

        let encoded = encode_payload(header, claims);
        assert_eq!(encoded, target);
    }

    #[test]
    fn encode_payload_valid_json() {
        init();

        let header = r#"{
    		"alg": "none",
    		"typ": "JWT"
    	}"#;
        let claims = r#"{
    		"hello": "world"
    	}"#;
        let target =
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJoZWxsbyI6IndvcmxkIn0";

        let encoded = encode_payload(header, claims);
        assert_eq!(encoded, target);
    }

    #[test]
    fn encode_and_sign_hs384() {
        init();

        let header = r#"{
    		"alg": "HS384",
    		"typ": "JWT"
    	}"#;
        let claims = r#"{
    		"hello": "world"
    	}"#;
        let secret = "password";
        let target = concat!(
            "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9",
            ".",
            "eyJoZWxsbyI6IndvcmxkIn0",
            ".",
            "tpOT8CJlT9_BgojqRtFypZt2yIbh0rPzO1hGlUloe4fVz4wdIq3pdGejx1cY3Yt8"
        );

        let encoded =
            encode_and_sign(header, claims, secret, "", SignatureTypes::Auto)
                .unwrap();
        assert_eq!(encoded, target);
    }
}
