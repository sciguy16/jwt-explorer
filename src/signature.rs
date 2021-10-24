use anyhow::{anyhow, bail, Result};
use base64::URL_SAFE_NO_PAD;
use crypto_hashes::sha2::{Digest, Sha256, Sha384, Sha512};
use hmac::{Hmac, Mac, NewMac};
use openssl::bn::BigNum;
use openssl::ec::EcKey;
use openssl::ecdsa::EcdsaSig;
use std::fmt::{self, Display};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::JwtHeader;

#[derive(Copy, Clone, EnumIter, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub enum SignatureTypes {
    /// Detect from header
    Auto,
    /// Retain original signature
    Retain,
    /// No digital signature or MAC performed
    None,
    /// HMAC using SHA-256
    Hs256,
    /// HMAC using SHA-384
    Hs384,
    /// HMAC using SHA-512
    Hs512,
    /*/// RSASSA-PKCS1-v1_5 using SHA-256
    Rs256,
    /// RSASSA-PKCS1-v1_5 using SHA-384
    Rs384,
    /// RSASSA-PKCS1-v1_5 using SHA-512
    Rs512,*/
    /// ECDSA using P-256 and SHA-256
    Es256, /*
           /// ECDSA using P-384 and SHA-384
           Es384,
           /// ECDSA using P-521 and SHA-512
           Es512,
           /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
           Ps256,
           /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
           Ps384,
           /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
           Ps512,*/
}

pub enum SignatureClass {
    Other,
    Pubkey,
    Hmac,
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

    pub fn class(&self, jwt_header: &str) -> SignatureClass {
        use SignatureClass::*;
        use SignatureTypes::*;
        match self {
            None => Other,
            Hs256 | Hs384 | Hs512 => Hmac,
            Es256 => Pubkey,
            Auto | Retain => {
                if jwt_header.contains("HS") || jwt_header.contains("hs") {
                    return Hmac;
                }
                if jwt_header.contains("RS")
                    || jwt_header.contains("rs")
                    || jwt_header.contains("ES")
                    || jwt_header.contains("es")
                {
                    return Pubkey;
                }
                Other
            }
        }
    }
}

pub fn calc_signature(
    payload: &str,
    secret: &str,
    original_signature: &str,
    hash_type: SignatureTypes,
) -> Result<String> {
    use SignatureTypes::*;

    match hash_type {
        Retain => Ok(original_signature.to_string()),
        Hs256 => {
            // HMAC using SHA-256
            let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
                .map_err(|e| anyhow!("{}", e))?;
            mac.update(payload.as_bytes());
            let result = mac.finalize();
            let signature_bytes = result.into_bytes();

            Ok(base64::encode_config(signature_bytes, URL_SAFE_NO_PAD))
        }
        Hs384 => {
            // HMAC using SHA-384
            let mut mac = Hmac::<Sha384>::new_from_slice(secret.as_bytes())
                .map_err(|e| anyhow!("{}", e))?;
            mac.update(payload.as_bytes());
            let result = mac.finalize();
            let signature_bytes = result.into_bytes();

            Ok(base64::encode_config(signature_bytes, URL_SAFE_NO_PAD))
        }
        Hs512 => {
            // HMAC using SHA-512
            let mut mac = Hmac::<Sha512>::new_from_slice(secret.as_bytes())
                .map_err(|e| anyhow!("{}", e))?;
            mac.update(payload.as_bytes());
            let result = mac.finalize();
            let signature_bytes = result.into_bytes();

            Ok(base64::encode_config(signature_bytes, URL_SAFE_NO_PAD))
        }
        Es256 => {
            // ECDSA-256
            let mut hasher = Sha256::new();
            hasher.update(payload.as_bytes());
            let payload = hasher.finalize();
            debug!("SHA256: {:02x?}", payload);
            let secret_key = EcKey::private_key_from_pem(secret.as_bytes())?;
            let signature = EcdsaSig::sign(&payload, &secret_key)?;
            let mut signature_bytes = signature.r().to_vec();
            debug!("r len: {}", signature_bytes.len());
            signature_bytes.extend_from_slice(&signature.s().to_vec());
            debug!("total len: {}", signature_bytes.len());

            Ok(base64::encode_config(signature_bytes, URL_SAFE_NO_PAD))
        }
        None => Ok("".to_string()),
        _ => Err(anyhow!("Unrecognised signature type: {}", hash_type)),
    }
}

pub fn verify_signature(
    payload: &str,
    signature: &str,
    key: &str,
    hash_type: SignatureTypes,
) -> Result<bool> {
    use SignatureTypes::*;
    const BN_LEN: usize = 32;
    match hash_type {
        Es256 => {
            // ECDSA-256

            // Load the pubkey
            let pubkey = EcKey::public_key_from_pem(key.as_bytes())?;

            // Load the r and s components from the JWT signature
            let sig_bytes = base64::decode_config(signature, URL_SAFE_NO_PAD)?;
            if sig_bytes.len() != 2 * BN_LEN {
                bail!(
                    "signature of length {} is not {}",
                    sig_bytes.len(),
                    2 * BN_LEN
                );
            }
            let r = BigNum::from_slice(&sig_bytes[..BN_LEN])?;
            let s = BigNum::from_slice(&sig_bytes[BN_LEN..])?;
            let sig = EcdsaSig::from_private_components(r, s)?;

            // Hash the payload
            let mut hasher = Sha256::new();
            hasher.update(payload.as_bytes());
            let payload = hasher.finalize();
            debug!("SHA256: {:02x?}", payload);

            Ok(sig.verify(&payload, &pubkey)?)
        }
        None => Ok(true),
        _ => Err(anyhow!("Unrecognised signature type: {}", hash_type)),
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
            calc_signature(payload, secret, "", SignatureTypes::Hs256).unwrap();

        assert_eq!(signature, "jW6hG22ajnhgpvKKvkWUVI8CYobL7DOdmp6KlGYAfZ8");
    }

    #[test]
    fn hs384() {
        init();

        let payload =
            "eyJhbGciOiJIUzM4NCIsInR5cGUiOiJKV1QifQ.eyJoZWxsbyI6IndvcmxkIn0";
        let secret = "password";

        let signature =
            calc_signature(payload, secret, "", SignatureTypes::Hs384).unwrap();

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
            calc_signature(payload, secret, "", SignatureTypes::Hs512).unwrap();

        assert_eq!(
            signature,
            concat!(
                "V4-Fm9ukreVKpfGf3Yxs9p-thbDvGWlRcPBXdE7qrEWu1CeP",
                "OFoXJZixJxmCDKGF_A8UgaObbw4biMgEeiEzZQ"
            )
        );
    }

    /// To validate the signature calculation we have to do a proper
    /// verification, as part of the signature calculation involves
    /// a cryptographically-secure random value. This is because it
    /// would otherwise be possible to reconstruct the private key from
    /// multiple ECDSA signatures.
    ///
    /// Doing a string comparison against the provided value won't work
    #[test]
    fn es256() {
        init();

        let pubkey = r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----"#;
        let privkey = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
-----END PRIVATE KEY-----"#;

        let payload = concat!(
            "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.",
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYW",
            "RtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0"
        );

        let signature =
            calc_signature(payload, privkey, "", SignatureTypes::Es256)
                .unwrap();

        let valid = verify_signature(
            payload,
            &signature,
            pubkey,
            SignatureTypes::Es256,
        )
        .unwrap();
        assert!(valid);
    }
}
