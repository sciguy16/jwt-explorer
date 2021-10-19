use eframe::egui::{self, Label, TextEdit, TextStyle, Ui};
use std::time::Duration;
use strum::IntoEnumIterator;

use crate::attack::Attack;
use crate::json_editor::{update_alg, update_time, TimeOffset};
use crate::log_err;
use crate::signature::SignatureTypes;

pub fn secret(ui: &mut Ui, secret: &mut String) {
    ui.horizontal(|ui| {
        ui.label("Secret: ");
        ui.add(TextEdit::singleline(secret).text_style(TextStyle::Monospace));
    });
}

pub fn attacks(ui: &mut Ui, attacks: &mut Vec<Attack>, jwt_claims: &str) {
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
    jwt_header: &mut String,
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
            log_err!(update_alg(jwt_header, *signature_type));
        }
    });
}

pub fn encode_and_sign(
    ui: &mut Ui,
    jwt_header: &str,
    jwt_claims: &str,
    secret: &str,
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
    });
}
