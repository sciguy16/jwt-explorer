use crate::attack::Attack;
use crate::decoder::IatAndExp;
use crate::json_editor::{update_alg, update_time, TimeOffset};
use crate::log_err;
use crate::newtypes::*;
use crate::signature::{generate_keypair, SignatureClass, SignatureTypes};
use chrono::{DateTime, FixedOffset, NaiveDateTime, Utc};
use eframe::egui::{self, Color32, Label, RichText, TextEdit, TextStyle, Ui};
use std::time::Duration;
use strum::IntoEnumIterator;

pub fn secret(ui: &mut Ui, secret: &mut Secret) {
    ui.horizontal(|ui| {
        ui.label("Secret: ");
        ui.add(
            TextEdit::singleline(secret.as_mut()).font(TextStyle::Monospace),
        );
    });
}

#[derive(Debug, Default)]
pub(crate) struct KeyPairDisplayState {
    pubkey_focused: bool,
    privkey_focused: bool,
}

pub(crate) fn keypair(
    ui: &mut Ui,
    state: &mut KeyPairDisplayState,
    pubkey: &mut PubKey,
    privkey: &mut PrivKey,
) {
    ui.horizontal(|ui| {
        ui.label("Public: ");
        let inp = if !state.pubkey_focused {
            TextEdit::singleline(pubkey.as_mut())
        } else {
            TextEdit::multiline(pubkey.as_mut())
        };
        let inp_state = ui.add(inp);
        if inp_state.gained_focus() {
            state.pubkey_focused = true;
        }
        if inp_state.lost_focus() {
            state.pubkey_focused = false;
        }
    });
    ui.horizontal(|ui| {
        ui.label("Private: ");
        let inp = if !state.privkey_focused {
            TextEdit::singleline(privkey.as_mut())
        } else {
            TextEdit::multiline(privkey.as_mut())
        };
        let inp_state = ui.add(inp);
        if inp_state.gained_focus() {
            state.privkey_focused = true;
        }
        if inp_state.lost_focus() {
            state.privkey_focused = false;
        }
    });
}

pub fn attacks(
    ui: &mut Ui,
    attacks: &mut Vec<Attack>,
    jwt_header: &Header,
    jwt_claims: &Claims,
) {
    use crate::attack;
    ui.horizontal(|ui| {
        ui.label("Attacks: ");
        if ui.button("Alg:none").clicked() {
            debug!("Generating Alg:None attacks");
            let generated_attacks = attack::alg_none(jwt_claims);
            for attack in generated_attacks {
                attacks.push(attack);
            }
        }
        if ui.button("Null sig").clicked() {
            attacks.push(Attack {
                name: "Null signature".to_string(),
                token: attack::null_sig(jwt_header, jwt_claims),
            });
        }
    });
}

// Clippy doesn't like the &mut String, even though it's necessary for
// the egui TextEdit
#[allow(clippy::ptr_arg)]
pub fn iat_and_exp_time(
    ui: &mut Ui,
    jwt_claims: &mut Claims,
    iat: &mut String,
    iat_ok: &mut bool,
    exp: &mut String,
    exp_ok: &mut bool,
) {
    use TimeOffset::*;

    let jwt_claims = jwt_claims.as_mut();
    let mut recalculate_iat_and_exp = false;

    ui.add_space(10.0);
    {
        let field = "iat";
        // Issued-at time
        ui.horizontal(|ui| {
            ui.add(Label::new(
                RichText::new("iat:").text_style(TextStyle::Monospace),
            ));
            let response = ui.add({
                TextEdit::singleline(iat).text_color(if *iat_ok {
                    Color32::BLACK
                } else {
                    Color32::RED
                })
            });
            if response.changed() {
                *iat_ok = false;
                if let Ok(new_ts) = iat.parse::<DateTime<FixedOffset>>() {
                    if let Ok(new_ts) = new_ts.timestamp().try_into() {
                        log_err!(update_time(
                            jwt_claims,
                            field,
                            Absolute(new_ts),
                        ));
                        *iat_ok = true;
                    }
                }
            }
        });

        ui.horizontal(|ui| {
            // spacing so that buttons line up with text box
            ui.add(Label::new(
                RichText::new("    ").text_style(TextStyle::Monospace),
            ));

            if ui.button("-24h").clicked() {
                log_err!(update_time(
                    jwt_claims,
                    field,
                    Minus(Duration::from_secs(60 * 60 * 24)),
                ));
                recalculate_iat_and_exp = true;
            }
            if ui.button("+24h").clicked() {
                log_err!(update_time(
                    jwt_claims,
                    field,
                    Plus(Duration::from_secs(60 * 60 * 24)),
                ));
                recalculate_iat_and_exp = true;
            }
            if ui.button("+7d").clicked() {
                log_err!(update_time(
                    jwt_claims,
                    field,
                    Plus(Duration::from_secs(60 * 60 * 24 * 7)),
                ));
                recalculate_iat_and_exp = true;
            }
            if ui.button("+365d").clicked() {
                log_err!(update_time(
                    jwt_claims,
                    field,
                    Plus(Duration::from_secs(60 * 60 * 24 * 365)),
                ));
                recalculate_iat_and_exp = true;
            }
        });
    }

    ui.add_space(10.0);

    // Expiry time
    {
        let field = "exp";
        ui.horizontal(|ui| {
            ui.add(Label::new(
                RichText::new("exp:").text_style(TextStyle::Monospace),
            ));
            let response = ui.add({
                TextEdit::singleline(exp).text_color(if *exp_ok {
                    Color32::BLACK
                } else {
                    Color32::RED
                })
            });
            if response.changed() {
                *exp_ok = false;
                if let Ok(new_ts) = exp.parse::<DateTime<FixedOffset>>() {
                    if let Ok(new_ts) = new_ts.timestamp().try_into() {
                        log_err!(update_time(
                            jwt_claims,
                            field,
                            Absolute(new_ts),
                        ));
                        *exp_ok = true;
                    }
                }
            }
        });

        ui.horizontal(|ui| {
            ui.add(Label::new(
                RichText::new("    ").text_style(TextStyle::Monospace),
            ));

            if ui.button("-24h").clicked() {
                log_err!(update_time(
                    jwt_claims,
                    field,
                    Minus(Duration::from_secs(60 * 60 * 24)),
                ));
                recalculate_iat_and_exp = true;
            }
            if ui.button("+24h").clicked() {
                log_err!(update_time(
                    jwt_claims,
                    field,
                    Plus(Duration::from_secs(60 * 60 * 24)),
                ));
                recalculate_iat_and_exp = true;
            }
            if ui.button("+7d").clicked() {
                log_err!(update_time(
                    jwt_claims,
                    field,
                    Plus(Duration::from_secs(60 * 60 * 24 * 7)),
                ));
                recalculate_iat_and_exp = true;
            }
            if ui.button("+365d").clicked() {
                log_err!(update_time(
                    jwt_claims,
                    field,
                    Plus(Duration::from_secs(60 * 60 * 24 * 365)),
                ));
                recalculate_iat_and_exp = true;
            }
        });
    }

    if recalculate_iat_and_exp {
        if let Ok(times) = serde_json::from_str::<IatAndExp>(jwt_claims) {
            *iat = DateTime::<Utc>::from_utc(
                NaiveDateTime::from_timestamp(times.iat, 0),
                Utc,
            )
            .to_string();
            *exp = DateTime::<Utc>::from_utc(
                NaiveDateTime::from_timestamp(times.exp, 0),
                Utc,
            )
            .to_string();
            *iat_ok = true;
            *exp_ok = true;
        }
    }

    ui.add_space(10.0);
}

pub fn signature_type(
    ui: &mut Ui,
    signature_type: &mut SignatureTypes,
    jwt_header: &mut Header,
) {
    ui.horizontal(|ui| {
        ui.label("Signature type: ");
        egui::ComboBox::from_label("")
            .selected_text(format!("{}", signature_type))
            .show_ui(ui, |ui| {
                for sig in SignatureTypes::iter() {
                    ui.selectable_value(
                        signature_type,
                        sig,
                        format!("{}", sig),
                    );
                }
            });
        if ui.button("Update header").clicked() {
            log_err!(update_alg(jwt_header.as_mut(), *signature_type));
        }
    });
}

#[allow(clippy::too_many_arguments)]
pub fn encode_and_sign(
    ui: &mut Ui,
    jwt_header: &Header,
    jwt_claims: &Claims,
    original_signature: &str,
    secret: &Secret,
    public_key: &mut PubKey,
    private_key: &mut PrivKey,
    signature_type: SignatureTypes,
    attacks: &mut Vec<Attack>,
) {
    ui.horizontal(|ui| {
        if ui.button("Encode and sign").clicked() {
            debug!("Encode and sign JWT");
            match crate::encoder::encode_and_sign(
                jwt_header,
                jwt_claims,
                secret,
                private_key,
                original_signature,
                signature_type,
            ) {
                Ok(token) => {
                    debug!("Encode & sign successful");
                    attacks.push(Attack {
                        name: secret.to_string(),
                        token,
                    });
                }
                Err(e) => {
                    warn!("Error signing token: {}", e);
                }
            }
        }

        if let SignatureClass::Pubkey = signature_type.class(jwt_header) {
            // Only display keygen button if it's relevant
            if ui.button("Generate keypair").clicked() {
                match generate_keypair(signature_type) {
                    Ok(kp) => {
                        *private_key = kp.private;
                        *public_key = kp.public;
                        info!("Generated fresh keypair");
                    }
                    Err(e) => warn!("Error generating keypair: {}", e),
                }
            }
        }
    });
}
