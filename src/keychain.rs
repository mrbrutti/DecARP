//! Retrieve the Apple Remote Desktop "Master Password" from the login keychain.
//!
//! ARD stores it as a generic-password item (service and account both fixed).
//! We shell out to `/usr/bin/security`, the supported macOS way to read it; the
//! keychain may prompt the user to allow access the first time. The stored data
//! carries a trailing NUL, so `security -w` prints it as hex.

use std::process::Command;

const SERVICE: &str = "Apple Remote Desktop";
const ACCOUNT: &str = "Master Password";

/// Get the master password, honoring the `DECARP_MASTER_PASSWORD` override.
pub fn master_password() -> Result<String, String> {
    if let Ok(p) = std::env::var("DECARP_MASTER_PASSWORD") {
        if !p.is_empty() {
            return Ok(p);
        }
    }

    let out = Command::new("/usr/bin/security")
        .args(["find-generic-password", "-s", SERVICE, "-a", ACCOUNT, "-w"])
        .output()
        .map_err(|e| format!("could not run /usr/bin/security: {e}"))?;

    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let err = err.trim();
        return Err(format!(
            "keychain lookup failed for \"{SERVICE}\" / \"{ACCOUNT}\": {}",
            if err.is_empty() {
                "item not found"
            } else {
                err
            }
        ));
    }

    let raw = String::from_utf8_lossy(&out.stdout);
    let raw = raw.trim();

    // `-w` emits hex when the data isn't printable UTF-8. ARD's value has a
    // trailing NUL, so it is hex; decode, strip NULs, then interpret as UTF-8.
    let bytes = if let Some(decoded) = try_hex(raw) {
        decoded
    } else {
        raw.as_bytes().to_vec()
    };
    let bytes: Vec<u8> = bytes.into_iter().take_while(|&b| b != 0).collect();

    String::from_utf8(bytes).map_err(|_| "master password is not valid UTF-8".to_string())
}

fn try_hex(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    // Only accept the hex interpretation if it yields valid UTF-8 (after NUL
    // stripping); otherwise the literal string was itself the password.
    let trimmed: Vec<u8> = bytes.iter().copied().take_while(|&b| b != 0).collect();
    if std::str::from_utf8(&trimmed).is_ok() {
        Some(bytes)
    } else {
        None
    }
}
