use anyhow::{anyhow, bail, Result};
use base64::URL_SAFE_NO_PAD;
use crypto_hashes::sha2::{Digest, Sha256, Sha384, Sha512};
use hmac::{Hmac, Mac, NewMac};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::nid::Nid;
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
    Es256,
    /// ECDSA using P-384 and SHA-384
    Es384,
    /// ECDSA using P-521 and SHA-512
    Es512, /*
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
            Es256 | Es384 | Es512 => Pubkey,
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

    pub fn ec_group(&self) -> Option<EcGroup> {
        use SignatureTypes::*;
        let curve = match self {
            Es256 => Nid::SECP256K1,
            Es384 => Nid::SECP384R1,
            Es512 => Nid::SECP521R1,
            _ => return Option::None,
        };
        Some(EcGroup::from_curve_name(curve).unwrap())
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
            // ECDSA using P-256 and SHA-256
            //TODO factor out repeated code between Es* signatures
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
        Es384 => {
            // ECDSA using P-384 and SHA-384
            let mut hasher = Sha384::new();
            hasher.update(payload.as_bytes());
            let payload = hasher.finalize();
            debug!("SHA384: {:02x?}", payload);
            let secret_key = EcKey::private_key_from_pem(secret.as_bytes())?;
            let signature = EcdsaSig::sign(&payload, &secret_key)?;
            let mut signature_bytes = signature.r().to_vec();
            debug!("r len: {}", signature_bytes.len());
            signature_bytes.extend_from_slice(&signature.s().to_vec());
            debug!("total len: {}", signature_bytes.len());

            Ok(base64::encode_config(signature_bytes, URL_SAFE_NO_PAD))
        }
        Es512 => {
            // ECDSA using P-521 and SHA-512
            let mut hasher = Sha512::new();
            hasher.update(payload.as_bytes());
            let payload = hasher.finalize();
            debug!("SHA512: {:02x?}", payload);
            let secret_key = EcKey::private_key_from_pem(secret.as_bytes())?;
            let signature = EcdsaSig::sign(&payload, &secret_key)?;
            let mut signature_bytes = signature.r().to_vec();
            signature_bytes.pad_to(0, 66);
            debug!("r len: {}", signature_bytes.len());
            let mut s_padded = signature.s().to_vec();
            s_padded.pad_to(0, 66);
            signature_bytes.extend_from_slice(&s_padded);
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
    match hash_type {
        Hs256 | Hs384 | Hs512 => {
            let calculated = calc_signature(payload, key, "", hash_type)?;
            Ok(calculated == signature)
        }
        Es256 => {
            // ECDSA-256
            //TODO factor out repeated code

            const BN_LEN: usize = 32;

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
        Es384 => {
            // ECDSA-384

            const BN_LEN: usize = 48;

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
            let mut hasher = Sha384::new();
            hasher.update(payload.as_bytes());
            let payload = hasher.finalize();
            debug!("SHA384: {:02x?}", payload);

            Ok(sig.verify(&payload, &pubkey)?)
        }
        Es512 => {
            // ECDSA-512

            // Load the pubkey
            let pubkey = EcKey::public_key_from_pem(key.as_bytes())?;

            // Load the r and s components from the JWT signature
            debug!("signature:\n{}", signature);
            let sig_bytes = base64::decode_config(signature, URL_SAFE_NO_PAD)?;

            let halfway = (sig_bytes.len() as f32) / 2.0;
            let halfway = halfway.round() as usize;

            let (r, s) = sig_bytes.split_at(halfway);
            let r = BigNum::from_slice(r)?;
            let s = BigNum::from_slice(s)?;
            let sig = EcdsaSig::from_private_components(r, s)?;

            // Hash the payload
            let mut hasher = Sha512::new();
            hasher.update(payload.as_bytes());
            let payload = hasher.finalize();
            debug!("SHA512: {:02x?}", payload);

            Ok(sig.verify(&payload, &pubkey)?)
        }
        None => Ok(true),
        _ => bail!("Unrecognised signature type: {}", hash_type),
    }
}

#[derive(Debug)]
pub struct KeyPair {
    pub public: String,
    pub private: String,
}

pub fn generate_keypair(signature_type: SignatureTypes) -> Result<KeyPair> {
    use SignatureTypes::*;

    match signature_type {
        Es256 | Es384 | Es512 => {
            let group = signature_type
                .ec_group()
                .expect("Groups are all defined for relevant signatures");
            let kp = EcKey::generate(&group)?;
            Ok(KeyPair {
                public: String::from_utf8(kp.public_key_to_pem()?)?,
                private: String::from_utf8(kp.private_key_to_pem()?)?,
            })
        }
        _ => bail!(
            "Cannot create keypair for signature type `{}`",
            signature_type
        ),
    }
}

trait VecPadding<T: Copy> {
    fn pad_to(&mut self, value: T, len: usize);
}

impl<T> VecPadding<T> for Vec<T>
where
    T: Copy,
{
    fn pad_to(&mut self, value: T, len: usize) {
        while self.len() < len {
            self.insert(0, value);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test::init;

    #[test]
    fn generate_keys() {
        use SignatureTypes::*;
        init();

        for sig_type in &[Es256, Es384, Es512] {
            debug!("Signature type: {}", sig_type);
            let kp = generate_keypair(*sig_type).unwrap();
            debug!("Generated keypair:\n{:?}", kp);
            assert!(kp.public.contains("BEGIN PUBLIC KEY"));
            assert!(kp.private.contains("BEGIN EC PRIVATE KEY"));
        }
    }

    #[test]
    fn vec_padding() {
        init();

        let data = &[1u8, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut a_vec = Vec::new();
        a_vec.extend_from_slice(data);

        assert_eq!(data.len(), 9);

        a_vec.pad_to(0xff, 15);

        assert_eq!(a_vec.len(), 15);
        assert_eq!(a_vec[..6], [0xffu8, 0xff, 0xff, 0xff, 0xff, 0xff][..]);
        assert_eq!(a_vec[6..], data[..]);
    }

    #[test]
    fn hs256() {
        init();

        let payload =
            "eyJhbGciOiJIUzI1NiIsInR5cGUiOiJKV1QifQ.eyJoZWxsbyI6IndvcmxkIn0";
        let secret = "password";

        let signature =
            calc_signature(payload, secret, "", SignatureTypes::Hs256).unwrap();

        assert_eq!(signature, "jW6hG22ajnhgpvKKvkWUVI8CYobL7DOdmp6KlGYAfZ8");

        let valid = verify_signature(
            payload,
            &signature,
            secret,
            SignatureTypes::Hs256,
        )
        .unwrap();
        assert!(valid);
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

        let valid = verify_signature(
            payload,
            &signature,
            secret,
            SignatureTypes::Hs384,
        )
        .unwrap();
        assert!(valid);
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

        let valid = verify_signature(
            payload,
            &signature,
            secret,
            SignatureTypes::Hs512,
        )
        .unwrap();
        assert!(valid);
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

    #[test]
    fn es384() {
        init();

        let pubkey = r#"-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEC1uWSXj2czCDwMTLWV5BFmwxdM6PX9p+
Pk9Yf9rIf374m5XP1U8q79dBhLSIuaojsvOT39UUcPJROSD1FqYLued0rXiooIii
1D3jaW6pmGVJFhodzC31cy5sfOYotrzF
-----END PUBLIC KEY-----"#;
        let privkey = r#"-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCAHpFQ62QnGCEvYh/p
E9QmR1C9aLcDItRbslbmhen/h1tt8AyMhskeenT+rAyyPhGhZANiAAQLW5ZJePZz
MIPAxMtZXkEWbDF0zo9f2n4+T1h/2sh/fviblc/VTyrv10GEtIi5qiOy85Pf1RRw
8lE5IPUWpgu553SteKigiKLUPeNpbqmYZUkWGh3MLfVzLmx85ii2vMU=
-----END PRIVATE KEY-----"#;

        let payload = concat!(
            "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.",
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYW",
            "RtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0"
        );

        let signature =
            calc_signature(payload, privkey, "", SignatureTypes::Es384)
                .unwrap();

        let valid = verify_signature(
            payload,
            &signature,
            pubkey,
            SignatureTypes::Es384,
        )
        .unwrap();
        assert!(valid);
    }

    #[test]
    fn es512() {
        init();

        let pubkey = r#"-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBgc4HZz+/fBbC7lmEww0AO3NK9wVZ
PDZ0VEnsaUFLEYpTzb90nITtJUcPUbvOsdZIZ1Q8fnbquAYgxXL5UgHMoywAib47
6MkyyYgPk0BXZq3mq4zImTRNuaU9slj9TVJ3ScT3L1bXwVuPJDzpr5GOFpaj+WwM
Al8G7CqwoJOsW7Kddns=
-----END PUBLIC KEY-----"#;
        let privkey = r#"-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBiyAa7aRHFDCh2qga
9sTUGINE5jHAFnmM8xWeT/uni5I4tNqhV5Xx0pDrmCV9mbroFtfEa0XVfKuMAxxf
Z6LM/yKhgYkDgYYABAGBzgdnP798FsLuWYTDDQA7c0r3BVk8NnRUSexpQUsRilPN
v3SchO0lRw9Ru86x1khnVDx+duq4BiDFcvlSAcyjLACJvjvoyTLJiA+TQFdmrear
jMiZNE25pT2yWP1NUndJxPcvVtfBW48kPOmvkY4WlqP5bAwCXwbsKrCgk6xbsp12
ew==
-----END PRIVATE KEY-----"#;

        let payload = concat!(
            "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.",
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYW",
            "RtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0"
        );

        let signature =
            calc_signature(payload, privkey, "", SignatureTypes::Es512)
                .unwrap();

        let valid = verify_signature(
            payload,
            &signature,
            pubkey,
            SignatureTypes::Es512,
        )
        .unwrap();
        assert!(valid);
    }

    /// Run ES512 a bunch of times to make sure that the vec padding
    /// change has actually fixed the problem
    ///
    /// Run with cargo test -- --ignored
    #[test]
    #[ignore]
    fn repeat_es512() {
        init();
        const REPEAT_TIMES: usize = 1000;

        for _ in 0..REPEAT_TIMES {
            es512();
        }
    }
}
