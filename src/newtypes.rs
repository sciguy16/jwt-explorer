use std::fmt::{self, Display};

macro_rules! newtype_impls {
    ($ty:ident) => {
        #[derive(Clone, Debug, Default, PartialEq, Eq)]
        pub struct $ty(String);

        impl From<String> for $ty {
            fn from(s: String) -> Self {
                $ty(s)
            }
        }

        impl From<&str> for $ty {
            fn from(s: &str) -> Self {
                $ty(s.to_string())
            }
        }

        impl Display for $ty {
            fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
                Display::fmt(&self.0, fmt)
            }
        }

        impl AsMut<String> for $ty {
            fn as_mut(&mut self) -> &mut String {
                &mut self.0
            }
        }

        impl AsRef<str> for $ty {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<[u8]> for $ty {
            fn as_ref(&self) -> &[u8] {
                self.0.as_bytes()
            }
        }

        impl $ty {
            #[allow(dead_code)]
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }

            #[allow(dead_code)]
            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }
        }
    };
}

newtype_impls!(Header);
newtype_impls!(Claims);
newtype_impls!(Secret);
newtype_impls!(PubKey);
newtype_impls!(PrivKey);
