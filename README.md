# DecARP

**Dec**rypt **A**pple **R**emote **D**esktop — a small macOS CLI that recovers the
per-computer admin credentials Apple Remote Desktop (ARD) has saved on your Mac,
and prints them as a table (or JSON).

ARD keeps the passwords for every computer in your list, but never shows them
back to you. They live encrypted in ARD's preferences, keyed by a "master
password" stored in your login keychain. DecARP reads both, decrypts the blob,
and joins it with your computer list.

```
┌──────────────────────┬─────────────┬──────────┬──────────────────────────┐
│ Computer             ┆ Address     ┆ Login    ┆ Password                 │
╞══════════════════════╪═════════════╪══════════╪══════════════════════════╡
│ Front Desk iMac      ┆ 10.0.1.20   ┆ admin    ┆ examplePassw0rd!         │
├╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌┼╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤
│ Lab Mac mini 3       ┆ 10.0.1.53   ┆ labuser  ┆ hunter2-not-real         │
└──────────────────────┴─────────────┴──────────┴──────────────────────────┘
```

*(Example output. The data above is fictional.)*

## Why this exists

This is a recovery tool for **your own** machines. If you administer a fleet
with ARD and lose track of the credentials it is happily using every day, they
are technically already on your disk — just not visible. DecARP surfaces them
without a third-party app or a trip to the keychain GUI, and its JSON mode lets
you pipe them into whatever you need next.

It only works with data you can already decrypt: it needs read access to your
own login keychain (macOS will prompt you to allow it) and your own ARD
preferences. It grants no access you did not already have.

## How ARD stores credentials (the format)

Recovered from `MasterPassword.m` in Apple Remote Desktop and consistent with
[`ygini/ARD-Inspector`](https://github.com/ygini/ARD-Inspector):

1. **Master password** — a generic-password keychain item, service and account
   both `Apple Remote Desktop` / `Master Password`. On modern installs its value
   is your macOS login password.
2. **Key derivation** — encode that password as **UTF-16LE**, zero-pad the byte
   buffer up to the next multiple of 16, then **MD5** it. The 16-byte digest is
   the AES key.
3. **Cipher** — **AES-128 in ECB mode** decrypts the `accessCredentials` blob
   found in ARD's preferences plist.
4. **Plaintext** — an old `NSArchiver` `streamtyped` archive: a dictionary of
   computer-UUID → `{ login, password, sharedSecret }`.
5. **Join** — each entry in the plist's `ComputerDatabase` carries a `uuid` that
   points at its credential record.

DecARP implements all of this natively in Rust, including a from-scratch reader
for the `streamtyped` archive format, so there is no dependency on Python,
Objective-C, or `openssl` at runtime.

### Where the data lives

| What | Path |
| --- | --- |
| Encrypted blob + computer list | `~/Library/Containers/com.apple.RemoteDesktop/Data/Library/Preferences/com.apple.RemoteDesktop.plist` |
| Legacy (pre-sandbox) location | `~/Library/Preferences/com.apple.RemoteDesktop.plist` |
| AES-key source | login keychain item `Apple Remote Desktop` / `Master Password` |

## Install

Requires a Rust toolchain (`rustup`/`cargo`) and macOS.

```bash
git clone https://github.com/mrbrutti/DecARP.git
cd DecARP
cargo build --release
# binary at target/release/decarp
```

Optionally copy it onto your `PATH`:

```bash
cp target/release/decarp /usr/local/bin/
```

## Usage

```bash
# Print the table, reading the master password from your login keychain
decarp

# JSON output (for scripting)
decarp --json

# Include the 16-byte ARD shared secret (hex) per computer
decarp --show-secret

# Point at a specific plist (e.g. a backup)
decarp --plist /path/to/com.apple.RemoteDesktop.plist

# Supply the master password yourself instead of touching the keychain
decarp --master-password '••••••••'
# or
DECARP_MASTER_PASSWORD='••••••••' decarp
```

The first keychain read pops a standard macOS dialog asking you to allow access
to the `Apple Remote Desktop` item. Click **Allow** (or **Always Allow**).

### Options

| Flag | Description |
| --- | --- |
| `--plist <PATH>` | Preferences plist to read (defaults to the sandboxed then legacy location). |
| `--master-password <PASSWORD>` | Use this instead of reading the keychain. |
| `--json` | Emit JSON instead of a table. |
| `--show-secret` | Add the ARD shared secret (hex) column/field. |
| `-h`, `--version` | Help and version. |

`DECARP_MASTER_PASSWORD` is honored as an alternative to `--master-password`.

## Security notes

- DecARP prints plaintext passwords to your terminal. Be mindful of scrollback,
  screen sharing, and shell history when using `--master-password`.
- It performs **no** network access and writes nothing to disk.
- Nothing here bypasses macOS security: reading the master password still
  requires unlocking your login keychain and approving access.

## How it was reverse-engineered

The decryption scheme was confirmed three ways: the exported symbols and error
strings in the ARD binary (`MasterPassword.m`, "creating AES 128 key"), the
open-source [`ygini/ARD-Inspector`](https://github.com/ygini/ARD-Inspector),
and the `streamtyped` format documented by
[`dgelessus/python-typedstream`](https://github.com/dgelessus/python-typedstream).

## Credits

- [ygini/ARD-Inspector](https://github.com/ygini/ARD-Inspector) — the original
  proof that the blob is UTF-16 MD5 → AES-128-ECB.
- [dgelessus/python-typedstream](https://github.com/dgelessus/python-typedstream)
  — reference for the `streamtyped` archive format.

## License

MIT © MrBrutti. See [LICENSE](LICENSE).

This project is provided for legitimate administration and recovery of systems
you own or are authorized to manage.
