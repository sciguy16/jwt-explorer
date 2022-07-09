// On Windows platform, don't show a console when opening the app.
#![windows_subsystem = "windows"]
#![forbid(unsafe_code)]

use copypasta::{ClipboardContext, ClipboardProvider};
use eframe::egui::{self, FontData, FontDefinitions, FontFamily, Pos2};
use lazy_static::lazy_static;
use serde::Deserialize;
use simplelog::{
    ColorChoice, CombinedLogger, LevelFilter, TermLogger, TerminalMode,
    WriteLogger,
};

use std::io::{self, Write};
use std::sync::{Arc, RwLock};

#[macro_use]
extern crate log;

mod attack;
mod decoder;
mod encoder;
mod gui;
mod json_editor;
mod json_formatter;
mod newtypes;
mod signature;
mod update_checker;

use attack::Attack;
use newtypes::*;
use signature::{SignatureClass, SignatureTypes};
use update_checker::UpdateStatus;

const VERSION: &str = env!("CARGO_PKG_VERSION");
lazy_static! {
    static ref BUILD_DATE: &'static str =
        option_env!("DATE").unwrap_or_default();
    static ref WINDOW_TITLE: String =
        format!("JWT Explorer - {}, built on {}", VERSION, *BUILD_DATE);
    static ref BUILD_HEADER: String = format!("v{} ({})", VERSION, *BUILD_DATE);
}

#[macro_export]
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

    pub fn clear(&self) {
        self.inner.write().unwrap().clear();
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

#[derive(Default)]
struct AppState {
    jwt_input: String,
    jwt_header: Header,
    jwt_claims: Claims,
    original_signature: String,
    secret: Secret,
    pubkey: PubKey,
    privkey: PrivKey,
    keypair_display_state: gui::controls::KeyPairDisplayState,
    signature_type: SignatureTypes,
    attacks: Vec<Attack>,
    win_size: Pos2,
    clipboard: Clipboard,
    iat_string: String,
    iat_ok: bool,
    exp_string: String,
    exp_ok: bool,
    update_status: Option<UpdateStatus>,
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

impl AppState {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut fonts = FontDefinitions::default();

        fonts.font_data.insert(
            "Liberation Mono".to_string(),
            FontData::from_static(include_bytes!(concat!(
                "../fonts/liberation-mono/",
                "LiberationMono-Regular.ttf"
            ))),
        );
        fonts
            .families
            .get_mut(&FontFamily::Monospace)
            .unwrap()
            .insert(0, "Liberation Mono".to_string());

        fonts.font_data.insert(
            "Liberation Serif".to_string(),
            FontData::from_static(include_bytes!(concat!(
                "../fonts/liberation-serif/",
                "LiberationSerif-Regular.ttf"
            ))),
        );
        fonts
            .families
            .get_mut(&FontFamily::Proportional)
            .unwrap()
            .insert(0, "Liberation Serif".to_string());

        cc.egui_ctx.set_fonts(fonts);
        cc.egui_ctx.set_visuals(egui::Visuals::dark());

        Self::default()
    }
}

impl eframe::App for AppState {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            gui::header(ui, self);
            gui::jwt_entry(ui, self);

            let half_width = ui.available_width() / 2.0;
            let half_height = self.win_size.y / 2.5;

            // Upper/middle section of window with details and controls
            ui.horizontal(|ui| {
                gui::header_and_claims(ui, half_width, half_height, self);
                ui.vertical(|ui| {
                    ui.group(|ui| {
                        ui.set_min_height(half_height);
                        ui.set_width(ui.available_width());
                        // Controls
                        match self.signature_type.class(&self.jwt_header) {
                            SignatureClass::Hmac => {
                                gui::controls::secret(ui, self)
                            }
                            SignatureClass::Pubkey => {
                                gui::controls::keypair(ui, self)
                            }
                            _ => (),
                        }

                        gui::controls::attacks(ui, self);
                        gui::controls::iat_and_exp_time(ui, self);
                        gui::controls::signature_type(ui, self);
                        gui::controls::encode_and_sign(ui, self);
                    });
                });
            });

            // Lower half of window with attack and log lists
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.group(|ui| {
                        ui.set_width(half_width);
                        ui.set_min_height(half_height);
                        gui::attack_list(
                            ui,
                            &mut self.attacks,
                            &mut self.clipboard,
                        );
                    });
                });
                ui.vertical(|ui| {
                    ui.group(|ui| {
                        ui.set_min_height(half_height);
                        ui.set_width(ui.available_width());
                        gui::log_list(ui, self);
                    });
                });
            });
        });

        self.win_size = ctx.available_rect().max;
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

    let native_options = eframe::NativeOptions {
        initial_window_size: Some((1280.0, 1024.0).into()),
        ..Default::default()
    };
    eframe::run_native(
        &WINDOW_TITLE,
        native_options,
        Box::new(|cc| Box::new(AppState::new(cc))),
    );
    // let options = eframe::NativeOptions::default();
    // eframe::run_native(Box::new(AppState::default()), options);
}

#[cfg(test)]
mod test {
    use super::*;
    use simplelog::TestLogger;

    const JWT_HS384: &str = concat!(
        "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9",
        ".",
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG",
        "9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0",
        ".",
        "IpWe_5UPstkFk6Wt8UNv2XillMQXRcVzr6iWcRF-50VDwq40g0xzLaV-Zvj1yHx6"
    );
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
        let secret = Default::default();
        let decoded =
            decoder::decode_jwt(&jwt_input, &secret, &Default::default());
        assert_eq!(decoded.header.as_str(), JWT_HS384_DECODED.0);
        assert_eq!(decoded.claims.as_str(), JWT_HS384_DECODED.1);
    }
}
