//use jwt::VerifyWithKey;
use crate::{
    signature::{self, SignatureTypes},
    JwtHeader,
};
use base64::URL_SAFE_NO_PAD;

#[derive(Default)]
pub struct Jwt {
    pub header: String,
    pub claims: String,
    pub status: Vec<String>,
}

pub(crate) fn decode_jwt(inp: &str, secret: &str) -> Jwt {
    let mut jwt = Jwt::default();
    if inp.is_empty() {
        jwt.status.push("Empty input".to_string());
        return jwt;
    }

    // Try decoding it "properly"
    //let claims: BTreeMap<String, String> = inp.verify_with_key(&key).unwrap();

    // If proper decoding fails then decode the base64 chunks separately
    let mut parts = inp.split('.');
    let header = parts.next();
    let claims = parts.next();
    let signature = parts.next();

    // Verify signature if present
    if let Some(signature) = signature {
        // verify it
        if let Ok(header_decoded) = serde_json::from_str::<JwtHeader>(signature)
        {
            if let Some(sig_type) = SignatureTypes::from_header(&header_decoded)
            {
                // Header decoded successfully
                if let Ok(signature_to_compare) = signature::calc_signature(
                    &format!(
                        "{}.{}",
                        header.unwrap_or_default(),
                        claims.unwrap_or_default()
                    ),
                    secret,
                    sig_type,
                ) {
                    if signature_to_compare == signature {
                        info!("Valid signature!");
                        jwt.status.push("Signature valid".to_string());
                    } else {
                        info!("Signature verification failed");
                        jwt.status
                            .push("Signature verification failed".to_string());
                    }
                }
            }
        } else {
            jwt.status.push("Invalid header".to_string());
        }
    } else {
        jwt.status.push("No signature present".to_string());
    }

    match (header, claims) {
        (Some(header), Some(claims)) => {
            // decode them
            info!("Decoding header: {}", header);
            match decode_base64(header) {
                Ok(h) => jwt.header = format_json_string(&h),
                Err(e) => jwt.status.push(e),
            }
            info!("Decoded: {:?}", jwt.header);

            info!("Decoding claims: {}", claims);
            match decode_base64(claims) {
                Ok(c) => jwt.claims = format_json_string(&c),
                Err(e) => jwt.status.push(e),
            }
            info!("Decoded: {:?}", claims);
        }
        (None, None) => jwt
            .status
            .push("Missing header and claims sections".to_string()),
        (None, _) => jwt.status.push("Missing header section".to_string()),
        (_, None) => jwt.status.push("Missing claims section".to_string()),
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

        let decoded = decode_jwt(inp, "");
        assert_eq!(decoded.header, header);
        assert_eq!(decoded.claims, claims);
    }

    #[test]
    fn decide_jwt_with_signature() {
        init();
        let inp = concat!(
            "eyJhbGciOiJIUzM4NCIsInR5cGUiOiJKV1QifQ.",
            "eyJoZWxsbyI6IndvcmxkIn0.",
            "atUQ3QNbGaBYU27YAs-Bc9nmkGyUDqb8PM_Qg8THWWcaaIU9S5U8WlvDe6restjn",
        );
        let header = "{\n  \"alg\": \"HS384\",\n  \"type\": \"JWT\"\n}";
        let claims = "{\n  \"hello\": \"world\"\n}";

        let decoded = decode_jwt(inp, "password");
        assert_eq!(decoded.header, header);
        assert_eq!(decoded.claims, claims);
    }
}
