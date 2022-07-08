//use jwt::VerifyWithKey;
use crate::newtypes::*;
use crate::{
    signature::{self, SignatureClass, SignatureTypes},
    JwtHeader,
};
use base64::URL_SAFE_NO_PAD;
use serde::Deserialize;

#[derive(Default, Deserialize)]
pub struct IatAndExp {
    pub iat: i64,
    pub exp: i64,
}

#[derive(Default)]
pub struct Jwt {
    pub header: Header,
    pub claims: Claims,
    pub signature: String,
    pub signature_valid: bool,
    pub times: Option<IatAndExp>,
}

pub(crate) fn decode_jwt(
    inp: &str,
    secret: &Secret,
    public_key: &PubKey,
) -> Jwt {
    let mut jwt = Jwt::default();
    if inp.is_empty() {
        warn!("{}", "Empty input");
        return jwt;
    }

    // If proper decoding fails then decode the base64 chunks separately
    let mut parts = inp.split('.');
    let header = parts.next().unwrap_or_default();
    let claims = parts.next().unwrap_or_default();
    let signature = parts.next().unwrap_or_default();
    let signing_payload = format!("{}.{}", header, claims);
    jwt.signature = signature.to_string();

    // Verify signature if present
    if let Ok(header) = decode_base64(header) {
        // verify it
        debug!("header: {}", header);
        match serde_json::from_str::<JwtHeader>(&header) {
            Ok(header_decoded) => {
                if let Some(sig_type) =
                    SignatureTypes::from_header(&header_decoded)
                {
                    let key = match sig_type.class(&header.into()) {
                        SignatureClass::Hmac => secret.as_str(),
                        SignatureClass::Pubkey => public_key.as_str(),
                        SignatureClass::Other => "",
                    };

                    // Header decoded successfully
                    match signature::verify_signature(
                        &signing_payload,
                        signature,
                        key,
                        sig_type,
                    ) {
                        Ok(valid) => {
                            jwt.signature_valid = valid;
                        }
                        Err(e) => warn!("Error validating signature: {}", e),
                    }
                }
            }
            Err(e) => {
                info!("Invalid header: {}", e);
            }
        }
    } else {
        info!("No signature present");
    }

    // decode them
    debug!("Decoding header: {}", header);
    match decode_base64(header) {
        Ok(h) => jwt.header = format_json_string(&h).into(),
        Err(e) => warn!("{}", e),
    }
    debug!("Decoded: {:?}", jwt.header);

    debug!("Decoding claims: {}", claims);
    match decode_base64(claims) {
        Ok(c) => jwt.claims = format_json_string(&c).into(),
        Err(e) => warn!("{}", e),
    }
    debug!("Decoded: {:?}", jwt.claims);

    debug!("Decoding iat & exp times");

    // Try to parse the jwt claims string into a json object
    if let Ok(times) = serde_json::from_str::<IatAndExp>(jwt.claims.as_ref()) {
        jwt.times = Some(times);
    } else {
        error!("Can't decode times from {claims}");
    }

    jwt
}

fn decode_base64(inp: &str) -> Result<String, String> {
    let decoded = base64::decode_config(inp, URL_SAFE_NO_PAD)
        .map_err(|e| e.to_string())?;
    Ok(match String::from_utf8(decoded) {
        Ok(parsed) => parsed,
        Err(e) => {
            warn!("Input contains invalid UTF-8");
            String::from_utf8_lossy(e.as_bytes()).to_string()
        }
    })
}

fn format_json_string(inp: &str) -> String {
    use crate::json_formatter::Prettifier;

    let mut p = Prettifier::new();
    p.process(inp)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test::init;

    #[test]
    fn format_json() {
        init();
        let inp = r#"{"hello":"world","something":2}"#;
        let target = r#"{
  "hello": "world",
  "something": 2
}"#;
        let out = format_json_string(inp);
        info!("Formatted:\n{}", out);
        assert_eq!(out, target);
    }

    #[test]
    fn decode_jwt_no_signature() {
        init();
        let inp =
            "eyJhbGciOiJub25lIiwidHlwZSI6IkpXVCJ9.eyJoZWxsbyI6IndvcmxkIn0";
        let header = "{\n  \"alg\": \"none\",\n  \"type\": \"JWT\"\n}";
        let claims = "{\n  \"hello\": \"world\"\n}";

        let decoded = decode_jwt(inp, &Default::default(), &Default::default());
        assert_eq!(decoded.header.as_str(), header);
        assert_eq!(decoded.claims.as_str(), claims);
        assert!(decoded.signature_valid);
    }

    #[test]
    fn decode_jwt_with_signature() {
        init();
        let inp = concat!(
            "eyJhbGciOiJIUzM4NCIsInR5cGUiOiJKV1QifQ.",
            "eyJoZWxsbyI6IndvcmxkIn0.",
            "atUQ3QNbGaBYU27YAs-Bc9nmkGyUDqb8PM_Qg8THWWcaaIU9S5U8WlvDe6restjn",
        );
        let header = "{\n  \"alg\": \"HS384\",\n  \"type\": \"JWT\"\n}";
        let claims = "{\n  \"hello\": \"world\"\n}";

        let decoded = decode_jwt(inp, &"password".into(), &Default::default());
        assert_eq!(decoded.header.as_str(), header);
        assert_eq!(decoded.claims.as_str(), claims);
        assert!(decoded.signature_valid);
    }

    #[test]
    fn decode_jwt_with_invalid_signature() {
        init();
        let inp = concat!(
            "eyJhbGciOiJIUzM4NCIsInR5cGUiOiJKV1QifQ.",
            "eyJoZWxsbyI6IndvcmxkIn0.",
            "THIS DOES NOT LOOK LIKE A VALID SIGNATURE",
        );
        let header = "{\n  \"alg\": \"HS384\",\n  \"type\": \"JWT\"\n}";
        let claims = "{\n  \"hello\": \"world\"\n}";

        let decoded = decode_jwt(inp, &"password".into(), &Default::default());
        assert_eq!(decoded.header.as_str(), header);
        assert_eq!(decoded.claims.as_str(), claims);
        assert!(!decoded.signature_valid);
    }
}
