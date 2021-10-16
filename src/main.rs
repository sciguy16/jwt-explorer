// On Windows platform, don't show a console when opening the app.
#![windows_subsystem = "windows"]

use copypasta::{ClipboardContext, ClipboardProvider};
use eframe::egui::{
    self, CtxRef, FontDefinitions, FontFamily, Label, Pos2, ScrollArea,
    TextEdit, TextStyle,
};
use eframe::epi::{self, Frame, Storage};
use lazy_static::lazy_static;
use serde::Deserialize;
use simplelog::{
    ColorChoice, CombinedLogger, LevelFilter, TermLogger, TerminalMode,
    WriteLogger,
};
use std::borrow::Cow;
use std::io::{self, Write};
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
use json_editor::{update_alg, update_time, TimeOffset};
use signature::SignatureTypes;

macro_rules! log_err {
    ($res:expr) => {
        if let Err(e) = $res {
            warn!("{}", e);
        }
    };
}

#[derive(Clone, Default)]
struct Log {
    buffer: Vec<u8>,
    inner: Arc<RwLock<Vec<String>>>,
}

impl Log {
    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }
}

impl Write for Log {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        for b in bytes {
            match b {
                b'\n' => self.flush()?,
                b => self.buffer.push(*b),
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buffer.is_empty() || self.buffer.ends_with(&[b'\n']) {
            let s =
                std::mem::replace(&mut self.buffer, Vec::with_capacity(200));
            let s = String::from_utf8_lossy(&s).to_string();
            self.inner.write().unwrap().push(s);
        }
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
    typ: Option<String>,
}

#[derive(Clone, Default)]
struct AppState {
    jwt_input: String,
    jwt_header: String,
    jwt_claims: String,
    secret: String,
    private_key: String,
    public_key: String,
    signature_type: SignatureTypes,
    attacks: Vec<Attack>,
    win_size: Pos2,
    clipboard: Clipboard,
}

#[derive(Clone, Default)]
struct Clipboard(Option<Arc<RwLock<ClipboardContext>>>);

impl Clipboard {
    #[inline]
    fn init(&mut self) {
        if self.0.is_none() {
            match ClipboardContext::new() {
                Ok(cc) => {
                    self.0 = Some(Arc::new(RwLock::new(cc)));
                }
                Err(e) => {
                    error!("Clipboard error: {}", e);
                }
            }
        }
    }

    pub fn put(&mut self, content: &str) {
        self.init();
        if let Some(cc) = &self.0 {
            if let Err(e) =
                cc.write().unwrap().set_contents(content.to_string())
            {
                error!("Clipboard error: {}", e);
            }
        }
    }
}

impl epi::App for AppState {
    fn name(&self) -> &str {
        "JWT Explorer"
    }

    fn setup(
        &mut self,
        ctx: &CtxRef,
        _frame: &mut Frame<'_>,
        _storage: Option<&dyn Storage>,
    ) {
        let mut fonts = FontDefinitions::default();

        fonts.font_data.insert(
            "Liberation Mono".to_string(),
            Cow::Borrowed(include_bytes!(concat!(
                "../fonts/liberation-mono/",
                "LiberationMono-Regular.ttf"
            ))),
        );
        fonts
            .fonts_for_family
            .get_mut(&FontFamily::Monospace)
            .unwrap()
            .insert(0, "Liberation Mono".to_string());

        fonts.font_data.insert(
            "Liberation Serif".to_string(),
            Cow::Borrowed(include_bytes!(concat!(
                "../fonts/liberation-serif/",
                "LiberationSerif-Regular.ttf"
            ))),
        );
        fonts
            .fonts_for_family
            .get_mut(&FontFamily::Proportional)
            .unwrap()
            .insert(0, "Liberation Serif".to_string());

        ctx.set_fonts(fonts);
    }

    fn update(&mut self, ctx: &egui::CtxRef, _frame: &mut epi::Frame<'_>) {
        let Self {
            jwt_input,
            jwt_header,
            jwt_claims,
            secret,
            private_key,
            public_key,
            signature_type,
            attacks,
            win_size,
            clipboard,
        } = self;

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("JWT Explorer");
            ui.label("Hint: pop the JWT into Hashcat to check for weak keys");
            ui.horizontal(|ui| {
                ui.label("JWT: ");
                ui.add(
                    TextEdit::singleline(jwt_input)
                        .text_style(TextStyle::Monospace),
                );
                if ui.button("Decode").clicked() {
                    let decoded = decoder::decode_jwt(jwt_input, secret);
                    *jwt_header = decoded.header;
                    *jwt_claims = decoded.claims;
                    if decoded.signature_valid {
                        info!("Valid signature!");
                    } else {
                        info!("Signature verification failed");
                    }
                    if secret.is_empty() {
                        attack::try_some_common_secrets(jwt_input, secret);
                    }
                }
                if ui.button("Demo").clicked() {
                    *jwt_input = concat!(
                        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
                        ".",
                        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6",
                        "IlN1cGVyIFNlY3VyZSBKV1QgQXV0aCIsImlh",
                        "dCI6MTUxNjIzOTAyMiwiZXhwIjoxNTE2MjM5",
                        "MDIyLCJpc19hZG1pbiI6ZmFsc2V9",
                        ".",
                        "4ZE1TbfJNpZluGDVH6CBtM9DXx6ZDmWwIk7bPxa2ZNY"
                    )
                    .to_string();
                }
            });

            let half_width = ui.available_width() / 2.0;
            let half_height = win_size.y / 2.5;

            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.group(|ui| {
                        ui.set_max_width(half_width);
                        ui.set_min_height(half_height);
                        ScrollArea::vertical().id_source("jwt_header").show(
                            ui,
                            |ui| {
                                ui.add(
                                    TextEdit::multiline(jwt_header)
                                        .code_editor(),
                                );
                                ui.add(
                                    TextEdit::multiline(jwt_claims)
                                        .code_editor(),
                                );
                            },
                        );
                    });
                });
                ui.vertical(|ui| {
                    ui.group(|ui| {
                        // Controls
                        ui.horizontal(|ui| {
                            ui.label("Secret: ");
                            ui.add(
                                TextEdit::singleline(secret)
                                    .text_style(TextStyle::Monospace),
                            );
                        });
                        ui.horizontal(|ui| {
                            ui.label("Public key: ");
                            ui.add(
                                TextEdit::singleline(public_key)
                                    .text_style(TextStyle::Monospace),
                            );
                        });
                        ui.horizontal(|ui| {
                            ui.label("Private key: ");
                            ui.add(
                                TextEdit::singleline(private_key)
                                    .text_style(TextStyle::Monospace),
                            );
                        });
                        ui.horizontal(|ui| {
                            ui.label("Attacks: ");
                            if ui.button("Alg:none").clicked() {
                                debug!("Generating Alg:None attacks");
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
                            ui.add(
                                Label::new("iat:")
                                    .text_style(TextStyle::Monospace),
                            );
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
                                    Plus(Duration::from_secs(
                                        60 * 60 * 24 * 365
                                    )),
                                ));
                            }
                        });
                        ui.horizontal(|ui| {
                            use TimeOffset::*;
                            let field = "exp";
                            ui.add(
                                Label::new("exp:")
                                    .text_style(TextStyle::Monospace),
                            );
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
                                    Plus(Duration::from_secs(
                                        60 * 60 * 24 * 365
                                    )),
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
                            if ui.button("Update header").clicked() {
                                log_err!(update_alg(
                                    jwt_header,
                                    *signature_type
                                ));
                            }
                        });
                        ui.horizontal(|ui| {
                            if ui.button("Encode and sign").clicked() {
                                debug!("Encode and sign JWT");
                                match encoder::encode_and_sign(
                                    jwt_header,
                                    jwt_claims,
                                    secret,
                                    *signature_type,
                                ) {
                                    Ok(token) => {
                                        debug!("Encode & sign successful");
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
                        });
                    });
                }); // controls
            });

            ui.horizontal(|ui| {
                ui.vertical(|ui| {ui.group(|ui|{
                        ui.set_max_width(half_width);
                        ui.set_min_height(half_height);
                    ui.label("Generated attack payloads:");

                    ui.add_space(4.0);

                    let row_height = ui.spacing().interact_size.y;
                    let num_rows = attacks.len();

                    ScrollArea::vertical().id_source("attacks").show_rows(
                        ui,
                        row_height,
                        num_rows,
                        |ui, row_range| {
                            for atk in
                                    attacks.get_mut(row_range)
                                    .unwrap_or_default()
                            {
                                ui.horizontal(|ui| {
                                    if ui.button("Copy").clicked() {
                                        clipboard.put(&atk.token);
                                    }
                                    ui.label(format!("{}: ", atk.name));
                                        ui.add_sized(
                                            ui.available_size(),
                                            egui::TextEdit::singleline(
                                                &mut atk.token)
                                                    .text_style(
                                                        TextStyle::Monospace)
                                            );

                                });
                            }
                        },
                    );
                });
                });
                ui.vertical(|ui| {
                    ui.group(|ui|{
                        ui.set_min_height(half_height);
                    ui.label("Log");
                    ui.add_space(4.0);

                    let text_style = TextStyle::Body;
                    let row_height = ui.fonts()[text_style].row_height();
                    let num_rows = LOG.len();

                    ScrollArea::vertical().id_source("logs").show_rows(
                        ui,
                        row_height,
                        num_rows,
                        |ui, row_range| {
                            for row in LOG
                                .inner
                                .read()
                                .unwrap()
                                .get(row_range)
                                .unwrap_or_default()
                            {
                                ui.label(row);
                            }
                        },
                    );
                });});
            })/*the bottom horizontal()*/;
        });

        *win_size = ctx.available_rect().max;
    }
}

pub fn main() {
    use simplelog::ConfigBuilder;

    let write_logger_config = ConfigBuilder::new().build();

    let _ = CombinedLogger::init(vec![
        TermLogger::new(
            LevelFilter::Info,
            Default::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        ),
        WriteLogger::new(LevelFilter::Info, write_logger_config, LOG.clone()),
    ]);

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
