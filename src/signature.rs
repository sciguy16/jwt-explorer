use base64::URL_SAFE_NO_PAD;
use crypto_hashes::sha2::{Sha256, Sha384, Sha512};
use hmac::{Hmac, Mac, NewMac};
use rand_core::OsRng;
use std::fmt::{self, Display};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::JwtHeader;

#[derive(Copy, Clone, EnumIter, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub enum SignatureTypes {
    /// Detect from header
    Auto,
    /// No digital signature or MAC performed
    None,
    /// HMAC using SHA-256
    Hs256,
    /// HMAC using SHA-384
    Hs384,
    /// HMAC using SHA-512
    Hs512,
    /// RSASSA-PKCS1-v1_5 using SHA-256
    Rs256,
    /// RSASSA-PKCS1-v1_5 using SHA-384
    Rs384,
    /// RSASSA-PKCS1-v1_5 using SHA-512
    Rs512,
    /// ECDSA using P-256 and SHA-256
    Es256,
    /// ECDSA using P-384 and SHA-384
    Es384,
    /// ECDSA using P-521 and SHA-512
    Es512,
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    Ps256,
    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    Ps384,
    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    Ps512,
}

impl Default for SignatureTypes {
    fn default() -> Self {
        SignatureTypes::Auto
    }
}

impl Display for SignatureTypes {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(
            fmt,
            "{}",
            match self {
                SignatureTypes::Auto => "Auto".to_string(),
                s => format!("{:?}", s).to_uppercase(),
            }
        )
    }
}

impl SignatureTypes {
    pub fn from_header(header: &JwtHeader) -> Option<Self> {
        let header = header.alg.to_uppercase();
        let mut ret = SignatureTypes::Auto;
        for sig in SignatureTypes::iter() {
            if header == sig.to_string() {
                ret = sig;
                break;
            }
        }
        if ret == SignatureTypes::Auto {
            None
        } else {
            Some(ret)
        }
    }
}

#[derive(Clone, Debug)]
pub enum SigningKeyWrapper {
    Es256(p256::ecdsa::SigningKey),
}

#[derive(Clone, Debug)]
pub struct EncodedKey {
    pub key: SigningKeyWrapper,
    pub public: String,
    pub private: String,
}

pub fn calc_signature(
    payload: &str,
    secret: &str,
    key: Option<EncodedKey>,
    hash_type: SignatureTypes,
) -> Result<String, String> {
    use SignatureTypes::*;
    match hash_type {
        Hs256 => {
            // HMAC using SHA-256
            let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
                .map_err(|e| e.to_string())?;
            mac.update(payload.as_bytes());
            let result = mac.finalize();
            let signature_bytes = result.into_bytes();

            Ok(base64::encode_config(signature_bytes, URL_SAFE_NO_PAD))
        }
        Hs384 => {
            // HMAC using SHA-384
            let mut mac = Hmac::<Sha384>::new_from_slice(secret.as_bytes())
                .map_err(|e| e.to_string())?;
            mac.update(payload.as_bytes());
            let result = mac.finalize();
            let signature_bytes = result.into_bytes();

            Ok(base64::encode_config(signature_bytes, URL_SAFE_NO_PAD))
        }
        Hs512 => {
            // HMAC using SHA-512
            let mut mac = Hmac::<Sha512>::new_from_slice(secret.as_bytes())
                .map_err(|e| e.to_string())?;
            mac.update(payload.as_bytes());
            let result = mac.finalize();
            let signature_bytes = result.into_bytes();

            Ok(base64::encode_config(signature_bytes, URL_SAFE_NO_PAD))
        }
        Es256 => {
            // ECDSA using P-256 and SHA-256

            todo!()
        }
        None => Ok("".to_string()),
        _ => Err(format!("Unrecognised signature type: {}", hash_type)),
    }
}

pub fn gen_keys(alg: SignatureTypes) -> Option<EncodedKey> {
    use SignatureTypes::*;
    match alg {
        Es256 => {
            let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
            let encoded = EncodedKey {
                private: base64::encode(signing_key.to_bytes()),
                public: base64::encode(
                    signing_key.verifying_key().to_encoded_point(false),
                ),
                key: SigningKeyWrapper::Es256(signing_key),
            };

            Some(encoded)
        }
        _ => std::option::Option::None,
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

        let signature =
            calc_signature(payload, secret, None, SignatureTypes::Hs256)
                .unwrap();

        assert_eq!(signature, "jW6hG22ajnhgpvKKvkWUVI8CYobL7DOdmp6KlGYAfZ8");
    }

    #[test]
    fn hs384() {
        init();

        let payload =
            "eyJhbGciOiJIUzM4NCIsInR5cGUiOiJKV1QifQ.eyJoZWxsbyI6IndvcmxkIn0";
        let secret = "password";

        let signature =
            calc_signature(payload, secret, None, SignatureTypes::Hs384)
                .unwrap();

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

        let signature =
            calc_signature(payload, secret, None, SignatureTypes::Hs512)
                .unwrap();

        assert_eq!(
            signature,
            concat!(
                "V4-Fm9ukreVKpfGf3Yxs9p-thbDvGWlRcPBXdE7qrEWu1CeP",
                "OFoXJZixJxmCDKGF_A8UgaObbw4biMgEeiEzZQ"
            )
        );
    }

    #[test]
    fn gen_keys_es256() {
        init();

        let key = gen_keys(SignatureTypes::Es256).unwrap();

        println!("key: {:?}", key);

        // Probably can't test anything here apart from that the
        // function runs and returns a Some, since the keys will be
        // randomly generated each time
    }
}
