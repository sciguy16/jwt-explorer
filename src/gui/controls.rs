use eframe::egui::{self, Label, TextEdit, TextStyle, Ui};
use std::time::Duration;
use strum::IntoEnumIterator;

use crate::attack::Attack;
use crate::json_editor::{update_alg, update_time, TimeOffset};
use crate::log_err;
use crate::newtypes::*;
use crate::signature::{generate_keypair, SignatureClass, SignatureTypes};

pub fn secret(ui: &mut Ui, secret: &mut String) {
    ui.horizontal(|ui| {
        ui.label("Secret: ");
        ui.add(TextEdit::singleline(secret).text_style(TextStyle::Monospace));
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
    pubkey: &mut String,
    privkey: &mut String,
) {
    ui.horizontal(|ui| {
        ui.label("Public: ");
        let inp = if !state.pubkey_focused {
            TextEdit::singleline(pubkey)
        } else {
            TextEdit::multiline(pubkey)
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
            TextEdit::singleline(privkey)
        } else {
            TextEdit::multiline(privkey)
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
    jwt_claims: &str,
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

pub fn iat_and_exp_time(ui: &mut Ui, jwt_claims: &mut String) {
    ui.horizontal(|ui| {
        use TimeOffset::*;
        let field = "iat";
        ui.add(Label::new("iat:").text_style(TextStyle::Monospace));
        if ui.button("-24h").clicked() {
            log_err!(update_time(
                jwt_claims,
                field,
                Minus(Duration::from_secs(60 * 60 * 24)),
            ));
        }
        if ui.button("+24h").clicked() {
            log_err!(update_time(
                jwt_claims,
                field,
                Plus(Duration::from_secs(60 * 60 * 24)),
            ));
        }
        if ui.button("+7d").clicked() {
            log_err!(update_time(
                jwt_claims,
                field,
                Plus(Duration::from_secs(60 * 60 * 24 * 7)),
            ));
        }
        if ui.button("+365d").clicked() {
            log_err!(update_time(
                jwt_claims,
                field,
                Plus(Duration::from_secs(60 * 60 * 24 * 365)),
            ));
        }
    });
    ui.horizontal(|ui| {
        use TimeOffset::*;
        let field = "exp";
        ui.add(Label::new("exp:").text_style(TextStyle::Monospace));
        if ui.button("-24h").clicked() {
            log_err!(update_time(
                jwt_claims,
                field,
                Minus(Duration::from_secs(60 * 60 * 24)),
            ));
        }
        if ui.button("+24h").clicked() {
            log_err!(update_time(
                jwt_claims,
                field,
                Plus(Duration::from_secs(60 * 60 * 24)),
            ));
        }
        if ui.button("+7d").clicked() {
            log_err!(update_time(
                jwt_claims,
                field,
                Plus(Duration::from_secs(60 * 60 * 24 * 7)),
            ));
        }
        if ui.button("+365d").clicked() {
            log_err!(update_time(
                jwt_claims,
                field,
                Plus(Duration::from_secs(60 * 60 * 24 * 365)),
            ));
        }
    });
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
    jwt_claims: &str,
    original_signature: &str,
    secret: &str,
    public_key: &mut String,
    private_key: &mut String,
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
