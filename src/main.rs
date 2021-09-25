// On Windows platform, don't show a console when opening the app.
#![windows_subsystem = "windows"]

use druid::im::Vector;
use druid::widget::{Button, Flex, Label, List, Scroll, TextBox};
use druid::{
    AppLauncher, Color, Data, Env, Lens, LocalizedString, Menu, UnitPoint,
    Widget, WidgetExt, WindowDesc, WindowId,
};
use serde::Deserialize;
#[macro_use]
extern crate log;

mod attack;
mod decoder;
mod encoder;
mod json_formatter;
mod signature;

use attack::Attack;

const WINDOW_TITLE: LocalizedString<AppState> =
    LocalizedString::new("JWT Explorer");

const EXPLAINER: &str = "Paste a JWT in the box below and click DECODE";

#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
    #[allow(dead_code)]
    typ: String,
}

#[derive(Clone, Data, Default, Lens)]
struct AppState {
    jwt_input: String,
    jwt_header: String,
    jwt_claims: String,
    jwt_status: String,
    secret: String,
    attacks: Vector<Attack>,
}

impl AppState {
    fn decode_jwt(&mut self) {
        let decoded = decoder::decode_jwt(&self.jwt_input, &self.secret);
        self.jwt_header = decoded.header;
        self.jwt_claims = decoded.claims;
        self.jwt_status = decoded.status.join("\n");
    }

    fn generate_alg_none_attacks(&mut self) {
        info!("Generating Alg:None attacks");
        let attacks = attack::alg_none(&self.jwt_claims);
        for attack in attacks {
            self.attacks.push_back(attack);
        }
    }

    fn encode_and_sign(&mut self) {
        info!("Encode and sign JWT");
        match encoder::encode_and_sign(
            &self.jwt_header,
            &self.jwt_claims,
            &self.secret,
        ) {
            Ok(token) => {
                info!("Encode & sign successful");
                self.attacks.push_back(Attack {
                    name: self.secret.clone(),
                    token,
                });
            }
            Err(e) => {
                warn!("Error signing token: {}", e);
            }
        }
    }
}

pub fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();
    // describe the main window
    let main_window = WindowDesc::new(build_root_widget())
        .title(WINDOW_TITLE)
        .menu(make_menu)
        .window_size((400.0, 600.0));

    // create the initial app state
    let initial_state = AppState::default();

    // start the application
    AppLauncher::with_window(main_window)
        .log_to_console()
        .launch(initial_state)
        .expect("Failed to launch application");
}

fn build_root_widget() -> impl Widget<AppState> {
    let blurb = Label::new(EXPLAINER)
        .with_line_break_mode(druid::widget::LineBreaking::WordWrap)
        .padding(8.0)
        .border(Color::grey(0.6), 2.0)
        .rounded(5.0);

    Flex::column()
        .cross_axis_alignment(druid::widget::CrossAxisAlignment::Start)
        .with_child(blurb)
        .with_spacer(24.0)
        .with_flex_child(
            Flex::row()
                .with_flex_child(
                    TextBox::new()
                        .with_placeholder("Paste JWT here")
                        .expand_width()
                        .lens(AppState::jwt_input),
                    1.0,
                )
                .with_child(Button::new("Decode").on_click(
                    |_, state: &mut AppState, _: &_| state.decode_jwt(),
                ))
                //.with_spacer(20.0)
                .padding(20.0),
            1.0,
        )
        .with_default_spacer()
        .with_flex_child(
            Flex::row()
                .with_flex_child(
                    Flex::column()
                        .with_flex_child(
                            TextBox::multiline()
                                .with_placeholder("Status")
                                .disabled_if(|_, _| true)
                                .lens(AppState::jwt_status)
                                .expand_width()
                                .expand_height(),
                            1.0,
                        )
                        .with_flex_child(
                            TextBox::multiline()
                                .with_placeholder("Header")
                                .lens(AppState::jwt_header)
                                .expand_width()
                                .expand_height(),
                            1.0,
                        )
                        .with_flex_child(
                            TextBox::multiline()
                                .with_placeholder("Claims")
                                .lens(AppState::jwt_claims)
                                .expand_width()
                                .expand_height(),
                            1.0,
                        ),
                    1.0,
                )
                .with_default_spacer()
                .with_flex_child(
                    Flex::column()
                        .with_flex_child(
                            TextBox::new()
                                .with_placeholder("secret")
                                .expand_width()
                                .lens(AppState::secret),
                            1.0,
                        )
                        .with_child(
                            Flex::row()
                                .with_child(Label::new("Attack: "))
                                .with_child(Button::new("Alg: None").on_click(
                                    |_, state: &mut AppState, _: &_| {
                                        state.generate_alg_none_attacks()
                                    },
                                )),
                        )
                        .with_child(Button::new("Encode and sign").on_click(
                            |_, state: &mut AppState, _: &_| {
                                state.encode_and_sign()
                            },
                        ))
                        .fix_width(150.0),
                    1.0,
                )
                .expand_width(),
            1.0,
        )
        .with_flex_child(
            Scroll::new(List::new(|| {
                Flex::row()
                    .with_flex_child(
                        Label::new(|item: &Attack, _env: &_| {
                            item.name.to_string()
                        }),
                        1.0,
                    )
                    .with_flex_child(
                        TextBox::new().expand_width().lens(Attack::token),
                        1.0,
                    )
                    .with_flex_child(Button::new("Copy"), 1.0)
                    .align_vertical(UnitPoint::LEFT)
                    .padding(10.0)
                    .expand()
                    .height(50.0)
                    .background(Color::rgb(1.0, 0.5, 0.5))
            }))
            .expand()
            .lens(AppState::attacks),
            1.0,
        )
        .expand()
        .padding(8.0)
}

#[allow(unused_assignments, unused_mut)]
fn make_menu<T: Data>(
    _window: Option<WindowId>,
    _data: &AppState,
    _env: &Env,
) -> Menu<T> {
    let mut base = Menu::empty();
    #[cfg(target_os = "macos")]
    {
        base = base.entry(druid::platform_menus::mac::application::default())
    }
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    {
        base = base.entry(druid::platform_menus::win::file::default());
    }
    base.entry(
        Menu::new(LocalizedString::new("common-menu-edit-menu"))
            .entry(druid::platform_menus::common::undo())
            .entry(druid::platform_menus::common::redo())
            .separator()
            .entry(druid::platform_menus::common::cut())
            .entry(druid::platform_menus::common::copy())
            .entry(druid::platform_menus::common::paste()),
    )
}

#[cfg(test)]
mod test {
    use super::*;

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
        let _ = env_logger::builder()
            .is_test(true)
            .filter(None, log::LevelFilter::Debug)
            .try_init();
    }

    #[test]
    fn decode_jwt() {
        init();
        let mut state = AppState {
            jwt_input: JWT_HS384.to_string(),
            ..Default::default()
        };
        state.decode_jwt();
        assert_eq!(state.jwt_header, JWT_HS384_DECODED.0);
        assert_eq!(state.jwt_claims, JWT_HS384_DECODED.1);
    }
}
