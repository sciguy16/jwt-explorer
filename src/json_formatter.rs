/// Implementation from https://github.com/bbarnickel/json-prettifier
pub struct Prettifier {
    indent: usize,
    indent_string: &'static str,
    within_literal: bool,
}

impl Prettifier {
    pub fn new() -> Self {
        Prettifier {
            indent: 0,
            indent_string: "  ",
            within_literal: false,
        }
    }

    fn push_newline_and_delim(&self, string: &mut String) {
        string.push('\n');
        for _ in 0..self.indent {
            string.push_str(self.indent_string);
        }
    }

    pub fn process(&mut self, line: &str) -> String {
        let mut result = String::with_capacity(line.len());

        for c in line.chars() {
            if c == '"' {
                self.within_literal = !self.within_literal;
            }

            if self.within_literal {
                result.push(c);
                continue;
            }

            if c == '}' || c == ']' {
                self.indent -= 1;
                self.push_newline_and_delim(&mut result);
            }

            result.push(c);

            if c == '{' || c == '[' {
                self.indent += 1;
                self.push_newline_and_delim(&mut result);
            }

            if c == ':' {
                result.push(' ');
            }

            if c == ',' {
                self.push_newline_and_delim(&mut result);
            }
        }

        result
    }
}
