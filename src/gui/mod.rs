use crate::update_checker::{check_up_to_date, UpdateStatus};
use crate::{AppState, Attack, Clipboard, LOG};
use chrono::{DateTime, NaiveDateTime, Utc};
use eframe::egui::{
    self, Button, Color32, RichText, ScrollArea, TextEdit, TextStyle, Ui,
};

pub mod controls;

fn copy_button(ui: &mut Ui, clipboard: &mut Clipboard, content: &str) {
    if ui.button("Copy").clicked() {
        clipboard.put(content);
    }
}

pub(crate) fn header(ui: &mut Ui, state: &mut AppState, ctx: &egui::Context) {
    ui.horizontal(|ui| {
        ui.heading("JWT Explorer ");
        ui.label(&*crate::BUILD_HEADER);
        ui.hyperlink("https://github.com/sciguy16/jwt-explorer");
        egui::widgets::global_dark_light_mode_buttons(ui);

        let update_button = match &state.update_status {
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
                    state.update_status = Some(us);
                }
                Err(e) => {
                    error!("Failed to fetch latest release information: {e}");
                }
            }
        }

        ui.label("Scale:");
        egui::ComboBox::from_label("")
            .selected_text(
                state
                    .display_scales
                    .get(state.display_scale_selected_idx)
                    .map(|s| s.to_string())
                    .unwrap_or_else(String::new),
            )
            .show_ui(ui, |ui| {
                for (idx, scale) in state.display_scales.iter().enumerate() {
                    ui.selectable_value(
                        &mut state.display_scale_selected_idx,
                        idx,
                        &scale.to_string(),
                    );
                }
            });
        if let Some(px_per_pt) =
            state.display_scales.get(state.display_scale_selected_idx)
        {
            ctx.set_pixels_per_point(*px_per_pt);
            ctx.request_repaint();
        }
    });

    ui.label("Hint: pop the JWT into Hashcat to check for weak keys");
}

pub(crate) fn jwt_entry(ui: &mut Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.label("JWT: ");
        ui.add(
            TextEdit::singleline(&mut state.jwt_input)
                .font(TextStyle::Monospace),
        );

        if ui.button("Decode").clicked() {
            if state.secret.is_empty() {
                crate::attack::try_some_common_secrets(
                    &state.jwt_input,
                    &mut state.secret,
                );
            }
            let decoded = crate::decoder::decode_jwt(
                &state.jwt_input,
                &state.secret,
                &state.pubkey,
            );
            state.jwt_header = decoded.header;
            state.jwt_claims = decoded.claims;
            state.original_signature = decoded.signature;
            if decoded.signature_valid {
                info!("Valid signature!");
            } else {
                info!("Signature verification failed");
            }

            // set iat and exp strings
            if let Some(times) = decoded.times {
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

        copy_button(ui, &mut state.clipboard, &state.jwt_input);

        if ui.button("Demo").clicked() {
            state.jwt_input = concat!(
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

pub(crate) fn header_and_claims(
    ui: &mut Ui,
    half_width: f32,
    half_height: f32,
    state: &mut AppState,
) {
    ui.vertical(|ui| {
        ui.group(|ui| {
            ui.set_width(half_width);
            ui.set_min_height(half_height);
            ScrollArea::vertical()
                .id_source("jwt_header")
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        copy_button(
                            ui,
                            &mut state.clipboard,
                            state.jwt_header.as_ref(),
                        );
                        ui.add(
                            TextEdit::multiline(state.jwt_header.as_mut())
                                .code_editor()
                                .desired_width(ui.available_width()),
                        );
                    });
                    ui.horizontal(|ui| {
                        copy_button(
                            ui,
                            &mut state.clipboard,
                            state.jwt_claims.as_ref(),
                        );
                        ui.add(
                            TextEdit::multiline(state.jwt_claims.as_mut())
                                .code_editor()
                                .desired_width(ui.available_width()),
                        );
                    });
                });
        });
    });
}

pub(crate) fn attack_list(
    ui: &mut Ui,
    attacks: &mut Vec<Attack>,
    clipboard: &mut Clipboard,
) {
    use csv::Writer;
    use serde::Serialize;

    #[derive(Serialize)]
    struct AttackCsv<'a> {
        attack: &'a str,
        payload: &'a str,
    }

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
        let csv_copy_button =
            Button::new(RichText::new("Copy as CSV").color(Color32::WHITE))
                .fill(Color32::from_rgb(0, 0, 0xc0));
        if ui.add(csv_copy_button).clicked() {
            let cap: usize = attacks.iter().map(|a| a.token.len()).sum();
            let mut tokenlist = String::with_capacity(cap + attacks.len());
            for atk in attacks.iter() {
                tokenlist.push_str(&atk.token);
                tokenlist.push('\n');
            }

            let mut csv_output = Writer::from_writer(Vec::new());
            for atk in attacks.iter().map(|atk| AttackCsv {
                attack: &atk.name,
                payload: &atk.token,
            }) {
                csv_output
                    .serialize(atk)
                    .expect("Failed to serialise token");
            }

            clipboard.put(&String::from_utf8_lossy(
                &csv_output.into_inner().expect("Failed to write CSV data"),
            ));
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

pub(crate) fn log_list(ui: &mut Ui, state: &mut AppState) {
    ui.horizontal(|ui| {
        ui.label("Log");

        if ui.button("Copy").clicked() {
            let logs = LOG.inner.read().unwrap().join("\n");
            state.clipboard.put(&logs);
        }

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
