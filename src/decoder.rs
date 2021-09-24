pub fn decode_jwt(inp: &str) -> Result<String, String> {
    if inp.is_empty() {
        return Err("Empty input".to_string());
    }
    Ok(inp.to_owned())
}
