//! Locate and read the Apple Remote Desktop preferences: the encrypted
//! `accessCredentials` blob and the plaintext `ComputerDatabase` list.

use std::path::{Path, PathBuf};

pub struct Computer {
    pub name: String,
    pub uuid: Option<String>,
    pub address: Option<String>,
}

pub struct Prefs {
    pub access_credentials: Vec<u8>,
    pub computers: Vec<Computer>,
}

/// The sandboxed (App Store) location used by ARD 3.x.
pub fn default_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(
        "Library/Containers/com.apple.RemoteDesktop/Data/Library/Preferences/com.apple.RemoteDesktop.plist",
    )
}

/// The older, non-sandboxed location (pre-App-Store installs).
pub fn legacy_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join("Library/Preferences/com.apple.RemoteDesktop.plist")
}

pub fn load(path: &Path) -> Result<Prefs, String> {
    let value = plist::Value::from_file(path)
        .map_err(|e| format!("could not read plist {}: {e}", path.display()))?;
    let dict = value
        .as_dictionary()
        .ok_or("preferences plist is not a dictionary")?;

    let access_credentials = dict
        .get("accessCredentials")
        .and_then(|v| v.as_data())
        .ok_or("no `accessCredentials` in preferences (nothing saved yet?)")?
        .to_vec();

    let mut computers = Vec::new();
    if let Some(arr) = dict.get("ComputerDatabase").and_then(|v| v.as_array()) {
        for entry in arr {
            let Some(cd) = entry.as_dictionary() else {
                continue;
            };
            let name = cd
                .get("name")
                .and_then(|v| v.as_string())
                .unwrap_or("")
                .to_string();
            let uuid = cd
                .get("uuid")
                .and_then(|v| v.as_string())
                .map(str::to_string);
            let address = cd
                .get("lastContactedAddress")
                .and_then(|v| v.as_dictionary())
                .and_then(|d| d.get("address"))
                .and_then(|v| v.as_string())
                .map(str::to_string);
            computers.push(Computer {
                name,
                uuid,
                address,
            });
        }
    }

    Ok(Prefs {
        access_credentials,
        computers,
    })
}
