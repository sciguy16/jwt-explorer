use crate::{Attack, Clipboard, LOG};
use eframe::egui::{
    self, Button, Color32, ScrollArea, TextEdit, TextStyle, Ui,
};

pub mod controls;

pub fn header(ui: &mut Ui) {
    ui.horizontal(|ui| {
        ui.heading("JWT Explorer ");
        ui.label(&*crate::BUILD_HEADER);
        ui.hyperlink("https://github.com/sciguy16/jwt-explorer");
    });
    ui.label("Hint: pop the JWT into Hashcat to check for weak keys");
}

#[allow(clippy::too_many_arguments)]
pub fn jwt_entry(
    ui: &mut Ui,
    jwt_input: &mut String,
    secret: &mut String, // needs &mut for secret guessing attack
    public_key: &str,
    jwt_header: &mut String,
    jwt_claims: &mut String,
    original_signature: &mut String,
) {
    ui.horizontal(|ui| {
        ui.label("JWT: ");
        ui.add(
            TextEdit::singleline(jwt_input).text_style(TextStyle::Monospace),
        );
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
    jwt_header: &mut String,
    jwt_claims: &mut String,
) {
    ui.vertical(|ui| {
        ui.group(|ui| {
            ui.set_max_width(half_width);
            ui.set_min_height(half_height);
            ScrollArea::vertical()
                .id_source("jwt_header")
                .show(ui, |ui| {
                    ui.add(TextEdit::multiline(jwt_header).code_editor());
                    ui.add(TextEdit::multiline(jwt_claims).code_editor());
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
        let copy_button = Button::new("Copy all")
            .fill(Color32::from_rgb(0, 0, 0xc0))
            .text_color(Color32::WHITE);
        if ui.add(copy_button).clicked() {
            let cap: usize = attacks.iter().map(|a| a.token.len()).sum();
            let mut tokenlist = String::with_capacity(cap + attacks.len());
            for atk in attacks.iter() {
                tokenlist.push_str(&atk.token);
                tokenlist.push('\n');
            }

            clipboard.put(&tokenlist);
        }
        let clear_button = Button::new("Clear")
            .fill(Color32::from_rgb(0xa0, 0, 0))
            .text_color(Color32::WHITE);
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
                    let copy_button = Button::new("Copy")
                        .fill(Color32::from_rgb(0, 0, 0xc0))
                        .text_color(Color32::WHITE);
                    if ui.add(copy_button).clicked() {
                        clipboard.put(&atk.token);
                    }
                    let delete_button = Button::new("Delete")
                        .fill(Color32::from_rgb(0xa0, 0, 0))
                        .text_color(Color32::WHITE);
                    if ui.add(delete_button).clicked() {
                        atk.token = DELETE_TOKEN_MAGIC_VALUE.to_string();
                    }
                    ui.label(format!("{}: ", atk.name));
                    ui.add_sized(
                        ui.available_size(),
                        egui::TextEdit::singleline(&mut atk.token)
                            .text_style(TextStyle::Monospace),
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
        let clear_button = Button::new("Clear")
            .fill(Color32::from_rgb(0xa0, 0, 0))
            .text_color(Color32::WHITE);
        if ui.add(clear_button).clicked() {
            LOG.clear();
        }
    });
    ui.add_space(4.0);

    let text_style = TextStyle::Body;
    let row_height = ui.fonts()[text_style].row_height();
    let num_rows = LOG.len();

    ScrollArea::vertical().id_source("logs").show_rows(
        ui,
        row_height,
        num_rows,
        |ui, row_range| {
            for row in
                LOG.inner.read().unwrap().get(row_range).unwrap_or_default()
            {
                ui.label(row);
            }
        },
    );
}
