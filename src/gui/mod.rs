use crate::newtypes::*;
use crate::update_checker::{check_up_to_date, UpdateStatus};
use crate::{Attack, Clipboard, LOG};
use chrono::{DateTime, NaiveDateTime, Utc};
use eframe::egui::{
    self, Button, Color32, RichText, ScrollArea, TextEdit, TextStyle, Ui,
};

pub mod controls;

// Button::new(RichText::new("Copy all").color(Color32::WHITE))
// .fill(Color32::from_rgb(0, 0, 0xc0));

pub fn header(ui: &mut Ui, update_status: &mut Option<UpdateStatus>) {
    ui.horizontal(|ui| {
        ui.heading("JWT Explorer ");
        ui.label(&*crate::BUILD_HEADER);
        ui.hyperlink("https://github.com/sciguy16/jwt-explorer");
        egui::widgets::global_dark_light_mode_buttons(ui);

        let update_button = match update_status {
            None => Button::new("Check for updates"),
            Some(UpdateStatus::Ok) => {
                Button::new(RichText::new("Up to date!").color(Color32::BLACK))
                    .fill(Color32::GREEN)
            }
            Some(UpdateStatus::NeedsUpdate(latest)) => Button::new(
                RichText::new(&format!(
                    "Update available ({})",
                    latest.tag_name
                ))
                .color(Color32::BLACK),
            )
            .fill(Color32::RED),
        };
        if ui.add(update_button).clicked() {
            match check_up_to_date() {
                Ok(us) => {
                    match &us {
                        UpdateStatus::Ok => {
                            info!("Up to date!");
                        }
                        UpdateStatus::NeedsUpdate(latest) => {
                            info!(
                                "Update available to version {}",
                                latest.tag_name
                            );
                        }
                    }
                    *update_status = Some(us);
                }
                Err(e) => {
                    error!("Failed to fetch latest release information: {e}");
                }
            }
        }
    });
    ui.label("Hint: pop the JWT into Hashcat to check for weak keys");
}

#[allow(clippy::too_many_arguments)]
pub fn jwt_entry(
    ui: &mut Ui,
    jwt_input: &mut String,
    secret: &mut Secret, // needs &mut for secret guessing attack
    public_key: &PubKey,
    jwt_header: &mut Header,
    jwt_claims: &mut Claims,
    original_signature: &mut String,
    iat: &mut String,
    iat_ok: &mut bool,
    exp: &mut String,
    exp_ok: &mut bool,
) {
    ui.horizontal(|ui| {
        ui.label("JWT: ");
        ui.add(TextEdit::singleline(jwt_input).font(TextStyle::Monospace));
        if ui.button("Decode").clicked() {
            if secret.is_empty() {
                crate::attack::try_some_common_secrets(jwt_input, secret);
            }
            let decoded =
                crate::decoder::decode_jwt(jwt_input, secret, public_key);
            *jwt_header = decoded.header;
            *jwt_claims = decoded.claims;
            *original_signature = decoded.signature;
            if decoded.signature_valid {
                info!("Valid signature!");
            } else {
                info!("Signature verification failed");
            }

            // set iat and exp strings
            if let Some(times) = decoded.times {
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
}

pub fn header_and_claims(
    ui: &mut Ui,
    half_width: f32,
    half_height: f32,
    jwt_header: &mut Header,
    jwt_claims: &mut Claims,
) {
    ui.vertical(|ui| {
        ui.group(|ui| {
            ui.set_max_width(half_width);
            ui.set_min_height(half_height);
            ScrollArea::vertical()
                .id_source("jwt_header")
                .show(ui, |ui| {
                    ui.add(
                        TextEdit::multiline(jwt_header.as_mut()).code_editor(),
                    );
                    ui.add(
                        TextEdit::multiline(jwt_claims.as_mut()).code_editor(),
                    );
                });
        });
    });
}

pub(crate) fn attack_list(
    ui: &mut Ui,
    attacks: &mut Vec<Attack>,
    clipboard: &mut Clipboard,
) {
    ui.horizontal(|ui| {
        ui.label("Generated attack payloads:");
        let copy_button =
            Button::new(RichText::new("Copy all").color(Color32::WHITE))
                .fill(Color32::from_rgb(0, 0, 0xc0));
        if ui.add(copy_button).clicked() {
            let cap: usize = attacks.iter().map(|a| a.token.len()).sum();
            let mut tokenlist = String::with_capacity(cap + attacks.len());
            for atk in attacks.iter() {
                tokenlist.push_str(&atk.token);
                tokenlist.push('\n');
            }

            clipboard.put(&tokenlist);
        }
        let clear_button =
            Button::new(RichText::new("Clear").color(Color32::WHITE))
                .fill(Color32::from_rgb(0xa0, 0, 0));
        if ui.add(clear_button).clicked() {
            info!("Deleted {} attacks", attacks.len());
            attacks.clear();
        }
    });

    ui.add_space(4.0);

    let row_height = ui.spacing().interact_size.y;
    let num_rows = attacks.len();

    ScrollArea::vertical().id_source("attacks").show_rows(
        ui,
        row_height,
        num_rows,
        |ui, row_range| {
            const DELETE_TOKEN_MAGIC_VALUE: &str = "MARKED_FOR_DELETION";
            for atk in attacks.get_mut(row_range).unwrap_or_default() {
                ui.horizontal(|ui| {
                    let copy_button = Button::new(
                        RichText::new("Copy").color(Color32::WHITE),
                    )
                    .fill(Color32::from_rgb(0, 0, 0xc0));
                    if ui.add(copy_button).clicked() {
                        clipboard.put(&atk.token);
                    }
                    let delete_button = Button::new(
                        RichText::new("Delete").color(Color32::WHITE),
                    )
                    .fill(Color32::from_rgb(0xa0, 0, 0));
                    if ui.add(delete_button).clicked() {
                        atk.token = DELETE_TOKEN_MAGIC_VALUE.to_string();
                    }
                    ui.label(format!("{}: ", atk.name));
                    ui.add_sized(
                        ui.available_size(),
                        egui::TextEdit::singleline(&mut atk.token)
                            .font(TextStyle::Monospace),
                    );
                });
            }
            attacks.retain(|atk| atk.token != DELETE_TOKEN_MAGIC_VALUE);
        },
    );
}

pub fn log_list(ui: &mut Ui) {
    ui.horizontal(|ui| {
        ui.label("Log");
        let clear_button =
            Button::new(RichText::new("Clear").color(Color32::WHITE))
                .fill(Color32::from_rgb(0xa0, 0, 0));
        if ui.add(clear_button).clicked() {
            LOG.clear();
        }
    });
    ui.add_space(4.0);

    let row_height = 10.0;
    let num_rows = LOG.len();

    ScrollArea::vertical().id_source("logs").show_rows(
        ui,
        row_height,
        num_rows,
        |ui, row_range| {
            let log = LOG.inner.read().unwrap();
            let rows = log.get(row_range).unwrap_or_default();
            for row in rows {
                ui.label(row);
            }
        },
    );
}
