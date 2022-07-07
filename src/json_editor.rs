use std::fmt::{self, Display};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::signature::SignatureTypes;

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum TimeOffset {
    Plus(Duration),
    Minus(Duration),
}

#[derive(Clone, Copy)]
pub enum FieldType<'a> {
    Number(u64),
    String(&'a str),
}

impl<'a> From<&'a str> for FieldType<'a> {
    fn from(inp: &'a str) -> Self {
        Self::String(inp)
    }
}

impl<'a> From<u64> for FieldType<'a> {
    fn from(inp: u64) -> Self {
        Self::Number(inp)
    }
}

impl Display for FieldType<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FieldType::Number(n) => write!(fmt, "{}", n),
            FieldType::String(s) => write!(fmt, "\"{}\"", s),
        }
    }
}

/// Replace the first instance of a field with the given value
pub fn replace_field<'a, T>(
    thing: &mut String,
    field: &str,
    value: T,
) -> Result<(), &'static str>
where
    T: Into<FieldType<'a>> + std::fmt::Display,
{
    let value: FieldType = value.into();
    debug!("JSON replace {} with {} in {}", field, value, thing);

    // Find where the field is
    let field_idx = thing
        .find(&format!("\"{}\"", field))
        .ok_or("Unable to find field")?;

    // idx is the start of the field name - add the length of the field
    // name and enclosing quotation marks to get the index of the end of
    // it, close to where the value should start
    let field_idx = field_idx + field.len() + 2; // advance past field name

    let (first, second) = thing.split_at_mut(field_idx);
    debug!("Pattern: {}, first: {}, second: {}", field, first, second);

    // second looks like this:
    // : "value", "other_fields": {} }
    // * Advance to the first non-whitespace character past the colon
    //   - If " then do some super-advanced string handling
    //   - If [0-9] then eat everything up to the next , or }

    enum State {
        Start,
        Colon,
        StringValue,
        StringEscape,
        NumericValue,
    }
    let mut state = State::Start;
    let mut start_of_value = Option::<usize>::None;
    let mut end_of_value = Option::<usize>::None;
    for (idx, chr) in second.chars().enumerate() {
        use State::*;
        match state {
            Start => {
                if chr == ':' {
                    state = Colon;
                }
            }
            Colon => {
                match chr {
                    '"' => {
                        // Start of a string
                        start_of_value = Some(idx + field_idx);
                        state = StringValue;
                    }
                    c if c.is_numeric() || c == '-' => {
                        // Start of a number
                        start_of_value = Some(idx + field_idx);
                        state = NumericValue;
                    }
                    _ => {}
                }
            }
            StringValue => {
                match chr {
                    '"' => {
                        // end of string
                        // +1 to advance past the closing quotation mark
                        end_of_value = Some(idx + field_idx + 1);
                        break;
                    }
                    '\\' => {
                        // escape next char
                        state = StringEscape;
                    }
                    _ => {}
                }
            }
            StringEscape => {
                // Only valid characters to escape are \"n
                // Maybe hex codes could be useful, but I don't see any
                // good reason to support them here
                match chr {
                    '\\' | '"' | 'n' => {
                        state = StringValue;
                    }
                    _ => return Err("Invalid escape sequence"),
                }
            }
            NumericValue => {
                // Wait until a character that is not:
                // * numeric
                // * 'e' for exponent
                // * '-' for negative exponent
                if !(chr.is_numeric() || chr == 'e' || chr == '-') {
                    end_of_value = Some(idx + field_idx);
                    break;
                }
            }
        }
    }

    if let (Some(a), Some(b)) = (start_of_value, end_of_value) {
        debug!("Start and end of value are at offset ({}, {})", a, b);
        thing.replace_range(a..b, &value.to_string());
        debug!("After: {}", thing);
        Ok(())
    } else {
        Err("JSON fragment matching the field does not appear to be valid")
    }
}

pub fn update_time(
    json: &mut String,
    field: &str,
    offset: TimeOffset,
) -> Result<(), &'static str> {
    use TimeOffset::*;

    let now_plus_24h = SystemTime::now();
    let now_plus_24h = match offset {
        Plus(offset) => now_plus_24h.checked_add(offset),
        Minus(offset) => now_plus_24h.checked_sub(offset),
    };
    let now_plus_24h = now_plus_24h
        .expect("Time calculation error")
        .duration_since(UNIX_EPOCH)
        .expect("Negative time somehow")
        .as_secs();

    // Try to replace the given field with the calculated value
    replace_field(json, field, now_plus_24h)
}

pub fn update_alg(
    json: &mut String,
    replacement: SignatureTypes,
) -> Result<(), &'static str> {
    if replacement != SignatureTypes::Auto {
        replace_field(json, "alg", replacement.to_string().as_str())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test::init;

    #[test]
    fn format_value() {
        init();

        assert_eq!(format!("{}", FieldType::String("hello")), r#""hello""#);
        assert_eq!(format!("{}", FieldType::Number(12345)), r#"12345"#);
    }

    #[test]
    fn replace_valid_json() {
        init();

        let mut json = r#"
    		{
    			"hello": "world",
    			"goodbye": 5
    		}
    	"#
        .to_string();
        let expected = r#"
    		{
    			"hello": "potato",
    			"goodbye": 324
    		}
    	"#;

        replace_field(&mut json, "goodbye", 324).unwrap();
        replace_field(&mut json, "hello", "potato").unwrap();
        assert_eq!(json, expected);
    }

    #[test]
    fn replace_invalid_json() {
        init();

        let mut json = r#"
    		{{
    			"this: {1234[]}===========
    			"hello": "world",
    			12345_____------
    	"#
        .to_string();

        let expected = r#"
    		{{
    			"this: {1234[]}===========
    			"hello": "potato",
    			12345_____------
    	"#;

        replace_field(&mut json, "hello", "potato").unwrap();
        assert_eq!(json, expected);
    }

    #[test]
    fn replace_missing_field() {
        init();

        let mut json = r#"
    		{
    			"hello": "world",
    			"goodbye": 324
    		}
    	"#
        .to_string();

        let expected = json.clone();

        let res = replace_field(&mut json, "potato", "potato");
        assert_eq!(json, expected);
        assert!(res.is_err());
    }

    #[test]
    fn replace_duplicate_field() {
        init();

        // when duplicate values are present only the first will be
        // replaced
        let mut json = r#"
    		{
    			"hello": "world",
    			"hello": "world",
    			"hello": "world",
    			"goodbye": 5,
    			"hello": "world",
    			"goodbye": 5
    		}
    	"#
        .to_string();
        let expected = r#"
    		{
    			"hello": "potato",
    			"hello": "world",
    			"hello": "world",
    			"goodbye": 324,
    			"hello": "world",
    			"goodbye": 5
    		}
    	"#;

        replace_field(&mut json, "goodbye", 324).unwrap();
        replace_field(&mut json, "hello", "potato").unwrap();
        assert_eq!(json, expected);
    }

    #[test]
    fn replace_string_with_escape_sequence() {
        init();

        let mut json = r#"
    		{
    			"hello": "w\"or\\ld",
    			"goodbye": 5
    		}
    	"#
        .to_string();
        let expected = r#"
    		{
    			"hello": "potato",
    			"goodbye": 5
    		}
    	"#;

        replace_field(&mut json, "hello", "potato").unwrap();
        assert_eq!(json, expected);
    }

    #[test]
    fn replace_string_with_invalid_escape_sequence() {
        init();

        let mut json = r#"
    		{
    			"hello": "w\orld",
    			"goodbye": 5
    		}
    	"#
        .to_string();
        let expected = json.clone();

        let res = replace_field(&mut json, "hello", "potato");
        assert_eq!(json, expected);
        assert!(res.is_err());
    }

    #[test]
    fn test_update_alg() {
        init();

        let mut json = r#"
            {
                "alg": "HS384",
                "typ": "JWT"
            }
        "#
        .to_string();
        let expected = r#"
            {
                "alg": "HS256",
                "typ": "JWT"
            }
        "#;

        update_alg(&mut json, SignatureTypes::Hs256).unwrap();
        assert_eq!(json, expected);
    }

    #[test]
    fn test_update_alg_auto() {
        init();

        let mut json = r#"
            {
                "alg": "HS384",
                "typ": "JWT"
            }
        "#
        .to_string();
        let expected = r#"
            {
                "alg": "HS384",
                "typ": "JWT"
            }
        "#;

        update_alg(&mut json, SignatureTypes::Auto).unwrap();
        assert_eq!(json, expected);
    }
}
