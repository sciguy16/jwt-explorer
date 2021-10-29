use crate::newtypes::*;
use crate::signature::{SignatureClass, SignatureTypes};
use crate::JwtHeader;
use anyhow::{anyhow, Result};
use base64::URL_SAFE_NO_PAD;
use serde_json::Value;

pub fn encode_payload(header: &Header, claims: &Claims) -> String {
    // Try minifying the JSONs - if it fails due to invalid JSON syntax
    // then just b64 encode what we're given
    let encoded_header =
        if let Ok(parsed) = serde_json::from_str::<Value>(header.as_ref()) {
            base64::encode_config(parsed.to_string(), URL_SAFE_NO_PAD)
        } else {
            base64::encode_config(header, URL_SAFE_NO_PAD)
        };
    let encoded_claims =
        if let Ok(parsed) = serde_json::from_str::<Value>(claims.as_ref()) {
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
    header: &Header,
    claims: &Claims,
    secret: &Secret,
    private_key: &PrivKey,
    original_signature: &str,
    mut hash_type: SignatureTypes,
) -> Result<String> {
    // If hash type is auto then try to parse the header and pick the
    // correct hash type
    if hash_type == SignatureTypes::Auto {
        let jwt_header: JwtHeader = serde_json::from_str(header.as_ref())?;
        hash_type =
            SignatureTypes::from_header(&jwt_header).ok_or_else(|| {
                anyhow!("Unrecognised signature type `{}`", jwt_header.alg)
            })?;
    }
    let key = match hash_type.class(header) {
        SignatureClass::Hmac => secret.as_str(),
        SignatureClass::Pubkey => private_key.as_str(),
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

        let header = "this isn't json".into();
        let claims = "also not json".into();
        let target = "dGhpcyBpc24ndCBqc29u.YWxzbyBub3QganNvbg";

        let encoded = encode_payload(&header, &claims);
        assert_eq!(encoded, target);
    }

    #[test]
    fn encode_payload_valid_json() {
        init();

        let header = r#"{
    		"alg": "none",
    		"typ": "JWT"
    	}"#
        .into();
        let claims = r#"{
    		"hello": "world"
    	}"#
        .into();
        let target =
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJoZWxsbyI6IndvcmxkIn0";

        let encoded = encode_payload(&header, &claims);
        assert_eq!(encoded, target);
    }

    #[test]
    fn encode_and_sign_hs384() {
        init();

        let header = r#"{
    		"alg": "HS384",
    		"typ": "JWT"
    	}"#
        .into();
        let claims = r#"{
    		"hello": "world"
    	}"#
        .into();
        let secret = "password".into();
        let target = concat!(
            "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9",
            ".",
            "eyJoZWxsbyI6IndvcmxkIn0",
            ".",
            "tpOT8CJlT9_BgojqRtFypZt2yIbh0rPzO1hGlUloe4fVz4wdIq3pdGejx1cY3Yt8"
        );

        let encoded = encode_and_sign(
            &header,
            &claims,
            &secret,
            &Default::default(),
            "",
            SignatureTypes::Auto,
        )
        .unwrap();
        assert_eq!(encoded, target);
    }
}
