//! Key derivation and decryption for the ARD `accessCredentials` blob.
//!
//! The scheme (recovered from `MasterPassword.m` in Apple Remote Desktop and
//! matching ygini/ARD-Inspector):
//!
//! 1. Encode the master password as UTF-16LE, then zero-pad the byte buffer up
//!    to the next multiple of 16.
//! 2. `MD5` that buffer. The 16-byte digest is the AES-128 key.
//! 3. AES-128 in ECB mode decrypts the blob. The plaintext is an `NSArchiver`
//!    `streamtyped` archive.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes128;
use md5::{Digest, Md5};

/// Derive the AES-128 key from the master password.
pub fn derive_key(master: &str) -> [u8; 16] {
    let mut raw: Vec<u8> = master
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let target = (raw.len() + 0xf) & !0xf;
    raw.resize(target, 0);

    let digest = Md5::digest(&raw);
    let mut key = [0u8; 16];
    key.copy_from_slice(&digest);
    key
}

/// AES-128-ECB decrypt. Length must be a multiple of 16; trailing bytes beyond
/// the archive are harmless (the parser stops at the archive's logical end).
#[allow(clippy::chunks_exact_to_as_chunks)]
pub fn decrypt_ecb(ciphertext: &[u8], key: &[u8; 16]) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut out = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.chunks_exact(16) {
        let mut block = *GenericArray::from_slice(chunk);
        cipher.decrypt_block(&mut block);
        out.extend_from_slice(&block);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_utf16_padded_md5() {
        // Neutral vectors (MD5 of the password as UTF-16LE, zero-padded to 16).
        assert_eq!(
            hex_of(&derive_key("test")),
            "4b7629f5d628f7000769c80a3cd1b8ca"
        );
        assert_eq!(
            hex_of(&derive_key("Passw0rd!")),
            "70b086db1dd3a07acf242e09c0c94f2f"
        );
    }

    fn hex_of(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
