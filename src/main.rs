use iced::{
    button, executor, scrollable, text_input, Align, Application, Button,
    Checkbox, Clipboard, Column, Command, Container, Element, Font,
    HorizontalAlignment, Length, Row, Scrollable, Settings, Text, TextInput,
};
use serde::{Deserialize, Serialize};

mod decoder;

pub fn main() -> iced::Result {
    JwtExplorer::run(Settings::default())
}

struct JwtExplorer {
    scroll: scrollable::State,
    error: Option<String>,
    input_text_state: text_input::State,
    input_text: String,
    decode_button_state: button::State,
    jwt_text: String,
}

#[derive(Clone, Debug)]
enum Message {
    InputTextChanged(String),
    DecodeButton,
}

impl Application for JwtExplorer {
    type Executor = executor::Default;
    type Message = Message;
    type Flags = ();
    fn new(_flags: ()) -> (JwtExplorer, Command<Message>) {
        (
            JwtExplorer {
                scroll: scrollable::State::new(),
                error: None,
                input_text_state: text_input::State::new(),
                input_text: String::new(),
                decode_button_state: button::State::new(),
                jwt_text: String::new(),
            },
            Command::none(),
        )
    }

    fn title(&self) -> String {
        String::from("JWT Explorer")
    }

    fn update(
        &mut self,
        message: Message,
        _clipboard: &mut Clipboard,
    ) -> Command<Message> {
        match message {
            Message::InputTextChanged(jwt) => {
                self.input_text = jwt;
            }
            Message::DecodeButton => {
                println!("Decode button pressed");
                let decoded = decoder::decode_jwt(&self.input_text);
                println!("Decoded: {:?}", decoded);
                match decoded {
                    Ok(_) => {
                        self.error = None;
                    }
                    Err(msg) => self.error = Some(msg),
                }
            } /*
              Message::Toggle => match self.state {
                  State::Idle => {
                      self.state = State::Ticking {
                          last_tick: Instant::now(),
                      };
                  }
                  State::Ticking { .. } => {
                      self.state = State::Idle;
                  }
              },
              Message::Tick(now) => match &mut self.state {
                  State::Ticking { last_tick } => {
                      self.duration += now - *last_tick;
                      *last_tick = now;
                  }
                  _ => {}
              },
              Message::Reset => {
                  self.duration = Duration::default();
              }*/
        }

        Command::none()
    }

    /*fn subscription(&self) -> Subscription<Message> {
        match self.state {
            State::Idle => Subscription::none(),
            State::Ticking { .. } => {
                time::every(Duration::from_millis(10)).map(Message::Tick)
            }
        }
    }*/

    fn view(&mut self) -> Element<Message> {
        let header = Text::new("JWT Explorer")
            .horizontal_alignment(HorizontalAlignment::Center);
        let jwt_input = TextInput::new(
            &mut self.input_text_state,
            "Paste a JWT here",
            &self.input_text,
            Message::InputTextChanged,
        )
        .padding(15)
        .size(30)
        .on_submit(Message::DecodeButton);

        let button = |state, label, style| {
            Button::new(
                state,
                Text::new(label)
                    .horizontal_alignment(HorizontalAlignment::Center),
            )
            .min_width(80)
            .padding(10)
            .style(style)
        };

        let decode_button = button(
            &mut self.decode_button_state,
            "Decode",
            style::Button::Primary,
        )
        .on_press(Message::DecodeButton);

        /*let toggle_button = {
            let (label, color) = match self.state {
                State::Idle => ("Start", style::Button::Primary),
                State::Ticking { .. } => ("Stop", style::Button::Destructive),
            };

            button(&mut self.toggle, label, color).on_press(Message::Toggle)
        };

        let reset_button =
            button(&mut self.reset, "Reset", style::Button::Secondary)
                .on_press(Message::Reset);*/

        let decode_row =
            Row::new().spacing(20).push(jwt_input).push(decode_button);

            let big_edit_box = Text::new("hi");

            let attack_mode_buttons_column = Column::new().spacing(20);

        let big_edit_box_row = Row::new().spacing(20).push(big_edit_box).push(attack_mode_buttons_column);

        let mut content = Column::new()
            .align_items(Align::Center)
            .spacing(20)
            .push(header).push(decode_row);

        if let Some(err) = &self.error {
            let error_msg = Text::new(err);
            content = content.push(error_msg);
        }
        content = content.push(big_edit_box_row);

        Scrollable::new(&mut self.scroll)
            .padding(40)
            .push(Container::new(content).width(Length::Fill).center_x())
            .into()
    }
}

mod style {
    use iced::{button, Background, Color, Vector};

    pub enum Button {
        Primary,
        Secondary,
        Destructive,
    }

    impl button::StyleSheet for Button {
        fn active(&self) -> button::Style {
            button::Style {
                background: Some(Background::Color(match self {
                    Button::Primary => Color::from_rgb(0.11, 0.42, 0.87),
                    Button::Secondary => Color::from_rgb(0.5, 0.5, 0.5),
                    Button::Destructive => Color::from_rgb(0.8, 0.2, 0.2),
                })),
                border_radius: 12.0,
                shadow_offset: Vector::new(1.0, 1.0),
                text_color: Color::WHITE,
                ..button::Style::default()
            }
        }
    }
}
