use chrono::{DateTime, SecondsFormat, Utc};

fn main() {
    let now: DateTime<Utc> = Utc::now();

    println!(
        "cargo:rustc-env=DATE={}",
        now.to_rfc3339_opts(SecondsFormat::Secs, true)
    );
}
