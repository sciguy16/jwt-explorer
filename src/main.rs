// On Windows platform, don't show a console when opening the app.
#![windows_subsystem = "windows"]

use eframe::{egui, epi};
use lazy_static::lazy_static;
use serde::Deserialize;
use simplelog::{
    ColorChoice, CombinedLogger, LevelFilter, TermLogger, TerminalMode,
    WriteLogger,
};
use std::fmt::{self, Write};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use strum::IntoEnumIterator;
#[macro_use]
extern crate log;

mod attack;
mod decoder;
mod encoder;
mod json_editor;
mod json_formatter;
mod signature;

use attack::Attack;
use json_editor::{update_time, TimeOffset};
use signature::SignatureTypes;

macro_rules! log_err {
    ($res:expr) => {
        if let Err(e) = $res {
            warn!("{}", e);
        }
    };
}

#[derive(Default)]
struct Log {
    inner: Arc<RwLock<Vec<String>>>,
}

impl Write for Log {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        LOG.inner.write().unwrap().push(s.to_string());
        Ok(())
    }
}

lazy_static! {
    static ref LOG: Log = Default::default();
}

#[derive(Deserialize)]
pub struct JwtHeader {
    alg: String,
    #[allow(dead_code)]
    typ: String,
}

#[derive(Clone, Default)]
struct AppState {
    jwt_input: String,
    jwt_header: String,
    jwt_claims: String,
    jwt_status: String,
    secret: String,
    signature_type: SignatureTypes,
    attacks: Vec<Attack>,
}

impl epi::App for AppState {
    fn name(&self) -> &str {
        "JWT Explorer"
    }

    fn update(&mut self, ctx: &egui::CtxRef, frame: &mut epi::Frame<'_>) {
        //let Self { name, age } = self;
        let Self {
            jwt_input,
            jwt_header,
            jwt_claims,
            jwt_status,
            secret,
            signature_type,
            attacks,
        } = self;

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("JWT Explorer");
            ui.label("Hint: pop the JWT into Hashcat to check for weak keys");
            ui.horizontal(|ui| {
                ui.label("JWT: ");
                ui.text_edit_singleline(jwt_input);
                if ui.button("Decode").clicked() {
                    info!("Decode clicked");
                    let decoded = decoder::decode_jwt(jwt_input, secret);
                    *jwt_header = decoded.header;
                    *jwt_claims = decoded.claims;
                    *jwt_status = decoded.status.join("\n");
                }
            });
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.text_edit_multiline(jwt_header);
                    ui.text_edit_multiline(jwt_claims);
                });
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label("Secret: ");
                        ui.text_edit_singleline(secret);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Attacks: ");
                        if ui.button("Alg:none").clicked() {
                            info!("Generating Alg:None attacks");
                            let generated_attacks =
                                attack::alg_none(jwt_claims);
                            for attack in generated_attacks {
                                attacks.push(attack);
                            }
                        }
                    });
                    ui.horizontal(|ui| {
                        use TimeOffset::*;
                        let field = "iat";
                        ui.label("iat:");
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
                        ui.label("exp:");
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
                    });
                    if ui.button("Encode and sign").clicked() {
                        info!("Encode and sign JWT");
                        match encoder::encode_and_sign(
                            jwt_header,
                            jwt_claims,
                            secret,
                            *signature_type,
                        ) {
                            Ok(token) => {
                                info!("Encode & sign successful");
                                attacks.push(Attack {
                                    name: secret.clone(),
                                    token,
                                });
                            }
                            Err(e) => {
                                warn!("Error signing token: {}", e);
                            }
                        }
                    }
                    ui.label("Log");
                    for item in LOG.inner.read().unwrap().iter() {
                        ui.label(item);
                    }
                });
            });

            ui.label("Generated attack payloads:");

            for atk in attacks {
                ui.horizontal(|ui| {
                    ui.label(format!("{}: ", atk.name));
                    ui.text_edit_singleline(&mut atk.token);
                    if ui.button("Copy").clicked() {
                        println!("Copy this text: {}", atk.token);
                    }
                });
            }
        });

        // Resize the native window to be just the size we need it to be:
        frame.set_window_size(ctx.used_size());
    }
}

pub fn main() {
    // env_logger::Builder::from_env(
    //    env_logger::Env::default().default_filter_or("info"),
    // )
    //.init();

    let _ = CombinedLogger::init(vec![TermLogger::new(
        LevelFilter::Info,
        Default::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )]);

    let options = eframe::NativeOptions::default();
    eframe::run_native(Box::new(AppState::default()), options);
}

#[cfg(test)]
mod test {
    use super::*;
    use simplelog::TestLogger;

    const JWT_HS384: &str = "\
        eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.\
        eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnR\
        ydWUsImlhdCI6MTUxNjIzOTAyMn0.IpWe_5UPstkFk6Wt8UNv2XillMQXRcVzr6i\
        WcRF-50VDwq40g0xzLaV-Zvj1yHx6\
        ";
    const JWT_HS384_DECODED: (&str, &str) = (
        r#"{
  "alg": "HS384",
  "typ": "JWT"
}"#,
        r#"{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true,
  "iat": 1516239022
}"#,
    );
    pub fn init() {
        let _ = TestLogger::init(LevelFilter::Debug, Default::default());
    }

    #[test]
    fn decode_jwt() {
        init();

        let jwt_input = JWT_HS384.to_string();
        let secret = "";
        let decoded = decoder::decode_jwt(&jwt_input, secret);
        assert_eq!(decoded.header, JWT_HS384_DECODED.0);
        assert_eq!(decoded.claims, JWT_HS384_DECODED.1);
    }
}
