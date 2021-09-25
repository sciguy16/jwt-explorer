use base64::URL_SAFE_NO_PAD;
use crypto_hashes::sha2::{Sha256, Sha384, Sha512};
use hmac::{Hmac, Mac, NewMac};

pub fn calc_signature(
    payload: &str,
    secret: &str,
    hash_type: &str,
) -> Result<String, String> {
    match hash_type.to_lowercase().as_str() {
        "hs256" => {
            let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
                .map_err(|e| e.to_string())?;
            mac.update(payload.as_bytes());
            let result = mac.finalize();
            let signature_bytes = result.into_bytes();

            println!("bytes: {:?}", &signature_bytes);

            Ok(base64::encode_config(signature_bytes, URL_SAFE_NO_PAD))
        }
        "hs384" => {
            let mut mac = Hmac::<Sha384>::new_from_slice(secret.as_bytes())
                .map_err(|e| e.to_string())?;
            mac.update(payload.as_bytes());
            let result = mac.finalize();
            let signature_bytes = result.into_bytes();

            Ok(base64::encode_config(signature_bytes, URL_SAFE_NO_PAD))
        }
        "hs512" => {
            let mut mac = Hmac::<Sha512>::new_from_slice(secret.as_bytes())
                .map_err(|e| e.to_string())?;
            mac.update(payload.as_bytes());
            let result = mac.finalize();
            let signature_bytes = result.into_bytes();

            Ok(base64::encode_config(signature_bytes, URL_SAFE_NO_PAD))
        }
        _ => Err(format!("Unrecognised signature type: {}", hash_type)),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test::init;

    #[test]
    fn hs256() {
        init();

        let payload =
            "eyJhbGciOiJIUzI1NiIsInR5cGUiOiJKV1QifQ.eyJoZWxsbyI6IndvcmxkIn0";
        let secret = "password";

        let signature = calc_signature(payload, secret, "HS256").unwrap();

        assert_eq!(signature, "jW6hG22ajnhgpvKKvkWUVI8CYobL7DOdmp6KlGYAfZ8");
    }

    #[test]
    fn hs384() {
        init();

        let payload =
            "eyJhbGciOiJIUzM4NCIsInR5cGUiOiJKV1QifQ.eyJoZWxsbyI6IndvcmxkIn0";
        let secret = "password";

        let signature = calc_signature(payload, secret, "HS384").unwrap();

        assert_eq!(
            signature,
            "atUQ3QNbGaBYU27YAs-Bc9nmkGyUDqb8PM_Qg8THWWcaaIU9S5U8WlvDe6restjn"
        );
    }

    #[test]
    fn hs512() {
        init();

        let payload =
            "eyJhbGciOiJIUzUxMiIsInR5cGUiOiJKV1QifQ.eyJoZWxsbyI6IndvcmxkIn0";
        let secret = "password";

        let signature = calc_signature(payload, secret, "HS512").unwrap();

        assert_eq!(
            signature,
            concat!(
                "V4-Fm9ukreVKpfGf3Yxs9p-thbDvGWlRcPBXdE7qrEWu1CeP",
                "OFoXJZixJxmCDKGF_A8UgaObbw4biMgEeiEzZQ"
            )
        );
    }
}
