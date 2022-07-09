use chrono::{DateTime, Utc};
use serde::Deserialize;

const API_URL: &str =
    r"https://api.github.com/repos/sciguy16/jwt-explorer/releases?per_page=1";
/// Github API requires a user-agent
const USER_AGENT: &str =
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.0.3705)";

#[derive(Debug, Deserialize)]
pub struct Release {
    pub url: String,
    pub tag_name: String,
    pub name: String,
    pub published_at: DateTime<Utc>,
}

pub enum UpdateStatus {
    Ok,
    NeedsUpdate(Release),
}

fn fetch_latest_release() -> anyhow::Result<Release> {
    let client = reqwest::blocking::ClientBuilder::new()
        .user_agent(USER_AGENT)
        .build()?;
    let mut resp: Vec<Release> = client.get(API_URL).send()?.json()?;
    let release = resp
        .pop()
        .ok_or_else(|| anyhow::anyhow!("No releases found"))?;
    Ok(release)
}

fn version_up_to_date(current: &str, latest: &str) -> anyhow::Result<bool> {
    use semver::Version;
    dbg!(&current);
    dbg!(&latest);

    let latest = latest.strip_prefix('v').unwrap_or(latest);

    let latest = Version::parse(latest)?;
    let current = Version::parse(current)?;

    Ok(current >= latest)
}

pub fn check_up_to_date() -> anyhow::Result<UpdateStatus> {
    let latest = fetch_latest_release()?;

    Ok(if version_up_to_date(crate::VERSION, &latest.tag_name)? {
        UpdateStatus::Ok
    } else {
        UpdateStatus::NeedsUpdate(latest)
    })
}

#[cfg(test)]
mod test {
    use super::*;

    /// only the fields we care about for brevity
    const API_RESP: &str = r###"
[
  {
    "url": "https://api.github.com/repos/sciguy16/jwt-explorer/releases/71516242",
    "assets_url": "https://api.github.com/repos/sciguy16/jwt-explorer/releases/71516242/assets",
    "html_url": "https://github.com/sciguy16/jwt-explorer/releases/tag/v0.4.1",
    "id": 71516242,
    "node_id": "RE_kwDOGG7cPs4EQ0BS",
    "tag_name": "v0.4.1",
    "target_commitish": "06503ba6f1035402c78cef06ff2ba1e809501987",
    "name": "v0.4.1",
    "draft": false,
    "prerelease": false,
    "created_at": "2022-07-07T20:51:36Z",
    "published_at": "2022-07-07T21:01:54Z",
    "body": "## [v0.4.1] - 2022-07-07\n### Added\n* Added null signature attack\n\n### Security\n* Updated dependencies, removing security bugs in openssl, xcb, and nix"
  }
]
"###;

    #[test]
    fn deserialise_gh_response() {
        let mut parsed: Vec<Release> = serde_json::from_str(API_RESP).unwrap();
        assert_eq!(parsed.len(), 1);
        let rel = parsed.pop().unwrap();
        assert_eq!(rel.tag_name, "v0.4.1");
    }

    #[test]
    fn semver_comparisons() {
        // cargo version does not have leading 'v', but github version does

        // current is latest
        let current = "0.4.1";
        let latest = "v0.4.1";
        assert!(version_up_to_date(current, latest).unwrap());

        // update available
        let current = "0.4.1";
        let latest = "v0.4.2";
        assert!(!version_up_to_date(current, latest).unwrap());

        // newer than latest -> OK
        let current = "0.5.1";
        let latest = "v0.4.1";
        assert!(version_up_to_date(current, latest).unwrap());
    }
}
