//! DecARP — decrypt and display saved Apple Remote Desktop credentials.

mod crypto;
mod keychain;
mod prefs;
mod typedstream;

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use comfy_table::{presets::UTF8_FULL, Cell, ContentArrangement, Table};
use typedstream::Value;

/// Decrypt and display the per-computer admin credentials that Apple Remote
/// Desktop stores on this Mac.
#[derive(Parser)]
#[command(name = "decarp", version, about, long_about = None)]
struct Cli {
    /// Path to com.apple.RemoteDesktop.plist (defaults to the sandboxed
    /// location, then the legacy one).
    #[arg(long, value_name = "PATH")]
    plist: Option<PathBuf>,

    /// Master password to use instead of reading it from the login keychain.
    /// (Also read from DECARP_MASTER_PASSWORD.)
    #[arg(long, value_name = "PASSWORD")]
    master_password: Option<String>,

    /// Output as JSON instead of a table.
    #[arg(long)]
    json: bool,

    /// Include the 16-byte ARD shared secret (hex) for each computer.
    #[arg(long)]
    show_secret: bool,
}

struct Cred {
    login: String,
    password: String,
    shared_secret: Option<Vec<u8>>,
}

fn run(cli: Cli) -> Result<(), String> {
    // 1. Locate and load the preferences.
    let path = match &cli.plist {
        Some(p) => p.clone(),
        None => {
            let d = prefs::default_path();
            if d.exists() {
                d
            } else {
                prefs::legacy_path()
            }
        }
    };
    let prefs = prefs::load(&path)?;

    // 2. Master password -> AES key.
    let master = match cli.master_password {
        Some(p) => p,
        None => keychain::master_password()?,
    };
    let key = crypto::derive_key(&master);

    // 3. Decrypt and unarchive.
    if prefs.access_credentials.len() % 16 != 0 {
        return Err(format!(
            "accessCredentials length ({}) is not a multiple of the AES block size",
            prefs.access_credentials.len()
        ));
    }
    let plaintext = crypto::decrypt_ecb(&prefs.access_credentials, &key);
    let root = typedstream::unarchive(&plaintext)
        .map_err(|e| format!("failed to decode credentials (wrong master password?): {e}"))?;

    // 4. Build uuid -> credential map.
    let creds = extract_creds(&root);

    // 5. Join with the computer list and render.
    let mut rows: Vec<(prefs::Computer, Option<&Cred>)> = Vec::new();
    for c in prefs.computers {
        let cred = c.uuid.as_ref().and_then(|u| creds.get(u));
        rows.push((c, cred));
    }

    if cli.json {
        print_json(&rows, cli.show_secret);
    } else {
        print_table(&rows, cli.show_secret);
    }
    Ok(())
}

fn extract_creds(root: &Value) -> HashMap<String, Cred> {
    let mut map = HashMap::new();
    if let Value::Dict(pairs) = root {
        for (k, v) in pairs {
            let Some(uuid) = k.as_str() else { continue };
            if let Value::Dict(inner) = v {
                let mut login = String::new();
                let mut password = String::new();
                let mut shared_secret = None;
                for (ik, iv) in inner {
                    match ik.as_str() {
                        Some("login") => login = iv.as_str().unwrap_or("").to_string(),
                        Some("password") => password = iv.as_str().unwrap_or("").to_string(),
                        Some("sharedSecret") => {
                            shared_secret = iv.as_data().map(|d| d.to_vec());
                        }
                        _ => {}
                    }
                }
                map.insert(
                    uuid.to_string(),
                    Cred {
                        login,
                        password,
                        shared_secret,
                    },
                );
            }
        }
    }
    map
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn print_table(rows: &[(prefs::Computer, Option<&Cred>)], show_secret: bool) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic);

    let mut header = vec!["Computer", "Address", "Login", "Password"];
    if show_secret {
        header.push("Shared Secret");
    }
    table.set_header(header.into_iter().map(Cell::new));

    for (c, cred) in rows {
        let (login, password, secret) = match cred {
            Some(cr) => (
                cr.login.clone(),
                cr.password.clone(),
                cr.shared_secret.as_deref().map(hex).unwrap_or_default(),
            ),
            None => ("—".into(), "(no saved credential)".into(), String::new()),
        };
        let mut cells = vec![
            Cell::new(&c.name),
            Cell::new(c.address.as_deref().unwrap_or("—")),
            Cell::new(login),
            Cell::new(password),
        ];
        if show_secret {
            cells.push(Cell::new(secret));
        }
        table.add_row(cells);
    }

    println!("{table}");
}

fn print_json(rows: &[(prefs::Computer, Option<&Cred>)], show_secret: bool) {
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|(c, cred)| {
            let mut obj = serde_json::Map::new();
            obj.insert("name".into(), c.name.clone().into());
            obj.insert(
                "address".into(),
                c.address
                    .clone()
                    .map(Into::into)
                    .unwrap_or(serde_json::Value::Null),
            );
            obj.insert(
                "uuid".into(),
                c.uuid
                    .clone()
                    .map(Into::into)
                    .unwrap_or(serde_json::Value::Null),
            );
            match cred {
                Some(cr) => {
                    obj.insert("login".into(), cr.login.clone().into());
                    obj.insert("password".into(), cr.password.clone().into());
                    if show_secret {
                        obj.insert(
                            "sharedSecret".into(),
                            cr.shared_secret
                                .as_deref()
                                .map(|d| serde_json::Value::from(hex(d)))
                                .unwrap_or(serde_json::Value::Null),
                        );
                    }
                }
                None => {
                    obj.insert("login".into(), serde_json::Value::Null);
                    obj.insert("password".into(), serde_json::Value::Null);
                }
            }
            serde_json::Value::Object(obj)
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&items).unwrap());
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("decarp: {e}");
            ExitCode::FAILURE
        }
    }
}
