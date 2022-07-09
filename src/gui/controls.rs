use crate::attack::Attack;
use crate::decoder::IatAndExp;
use crate::json_editor::{update_alg, update_time, TimeOffset};
use crate::newtypes::*;
use crate::signature::{generate_keypair, SignatureClass, SignatureTypes};
use crate::{log_err, AppState};
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

pub(crate) fn keypair(ui: &mut Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.label("Public: ");
        let inp = if !state.keypair_display_state.pubkey_focused {
            TextEdit::singleline(state.pubkey.as_mut())
        } else {
            TextEdit::multiline(state.pubkey.as_mut())
        };
        let inp_state = ui.add(inp);
        if inp_state.gained_focus() {
            state.keypair_display_state.pubkey_focused = true;
        }
        if inp_state.lost_focus() {
            state.keypair_display_state.pubkey_focused = false;
        }
    });
    ui.horizontal(|ui| {
        ui.label("Private: ");
        let inp = if !state.keypair_display_state.privkey_focused {
            TextEdit::singleline(state.privkey.as_mut())
        } else {
            TextEdit::multiline(state.privkey.as_mut())
        };
        let inp_state = ui.add(inp);
        if inp_state.gained_focus() {
            state.keypair_display_state.privkey_focused = true;
        }
        if inp_state.lost_focus() {
            state.keypair_display_state.privkey_focused = false;
        }
    });
}

pub(crate) fn attacks(ui: &mut Ui, state: &mut AppState) {
    use crate::attack;
    ui.horizontal(|ui| {
        ui.label("Attacks: ");
        if ui.button("Alg:none").clicked() {
            debug!("Generating Alg:None attacks");
            let generated_attacks = attack::alg_none(&state.jwt_claims);
            for attack in generated_attacks {
                state.attacks.push(attack);
            }
        }
        if ui.button("Null sig").clicked() {
            state.attacks.push(Attack {
                name: "Null signature".to_string(),
                token: attack::null_sig(&state.jwt_header, &state.jwt_claims),
            });
        }
    });
}

// Clippy doesn't like the &mut String, even though it's necessary for
// the egui TextEdit
#[allow(clippy::ptr_arg)]
pub(crate) fn iat_and_exp_time(ui: &mut Ui, state: &mut AppState) {
    use TimeOffset::*;

    let jwt_claims = state.jwt_claims.as_mut();
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
                TextEdit::singleline(&mut state.iat_string).text_color(
                    if state.iat_ok {
                        Color32::BLACK
                    } else {
                        Color32::RED
                    },
                )
            });
            if response.changed() {
                state.iat_ok = false;
                if let Ok(new_ts) =
                    state.iat_string.parse::<DateTime<FixedOffset>>()
                {
                    if let Ok(new_ts) = new_ts.timestamp().try_into() {
                        log_err!(update_time(
                            jwt_claims,
                            field,
                            Absolute(new_ts),
                        ));
                        state.iat_ok = true;
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
                TextEdit::singleline(&mut state.exp_string).text_color(
                    if state.exp_ok {
                        Color32::BLACK
                    } else {
                        Color32::RED
                    },
                )
            });
            if response.changed() {
                state.exp_ok = false;
                if let Ok(new_ts) =
                    state.exp_string.parse::<DateTime<FixedOffset>>()
                {
                    if let Ok(new_ts) = new_ts.timestamp().try_into() {
                        log_err!(update_time(
                            jwt_claims,
                            field,
                            Absolute(new_ts),
                        ));
                        state.exp_ok = true;
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
            state.iat_string = DateTime::<Utc>::from_utc(
                NaiveDateTime::from_timestamp(times.iat, 0),
                Utc,
            )
            .to_string();
            state.exp_string = DateTime::<Utc>::from_utc(
                NaiveDateTime::from_timestamp(times.exp, 0),
                Utc,
            )
            .to_string();
            state.iat_ok = true;
            state.exp_ok = true;
        }
    }

    ui.add_space(10.0);
}

pub(crate) fn signature_type(ui: &mut Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.label("Signature type: ");
        egui::ComboBox::from_label("")
            .selected_text(state.signature_type.to_string())
            .show_ui(ui, |ui| {
                for sig in SignatureTypes::iter() {
                    ui.selectable_value(
                        &mut state.signature_type,
                        sig,
                        sig.to_string(),
                    );
                }
            });
        if ui.button("Update header").clicked() {
            log_err!(update_alg(
                state.jwt_header.as_mut(),
                state.signature_type
            ));
        }
    });
}

pub(crate) fn encode_and_sign(ui: &mut Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        if ui.button("Encode and sign").clicked() {
            debug!("Encode and sign JWT");
            match crate::encoder::encode_and_sign(
                &state.jwt_header,
                &state.jwt_claims,
                &state.secret,
                &state.privkey,
                &state.original_signature,
                state.signature_type,
            ) {
                Ok(token) => {
                    debug!("Encode & sign successful");
                    state.attacks.push(Attack {
                        name: state.secret.to_string(),
                        token,
                    });
                }
                Err(e) => {
                    warn!("Error signing token: {}", e);
                }
            }
        }

        if let SignatureClass::Pubkey =
            state.signature_type.class(&state.jwt_header)
        {
            // Only display keygen button if it's relevant
            if ui.button("Generate keypair").clicked() {
                match generate_keypair(state.signature_type) {
                    Ok(kp) => {
                        state.privkey = kp.private;
                        state.pubkey = kp.public;
                        info!("Generated fresh keypair");
                    }
                    Err(e) => warn!("Error generating keypair: {}", e),
                }
            }
        }
    });
}
