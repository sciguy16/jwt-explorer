use std::fmt::{self, Display};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header(String);

impl From<String> for Header {
    fn from(s: String) -> Self {
        Header(s)
    }
}

impl From<&str> for Header {
    fn from(s: &str) -> Self {
        Header(s.to_string())
    }
}

impl Display for Header {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.0, fmt)
    }
}

impl AsMut<String> for Header {
    fn as_mut(&mut self) -> &mut String {
        &mut self.0
    }
}

impl AsRef<str> for Header {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl AsRef<[u8]> for Header {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}
