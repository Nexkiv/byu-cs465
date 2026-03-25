use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::{KeyInit, aead::Aead};
use base16ct::lower::{decode, encode};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::io::{BufWriter, Write};

const DIRECTORY: &str = "breach";

fn decrypt_vault(line: String, writer: &mut BufWriter<File>) {
    // 1. Parse fields
    let parts: Vec<&str> = line.split(':').collect();
    let (username, hex_salt, hex_hash, hex_nonce, hex_vault) =
        (parts[0], parts[1], parts[2], parts[3], parts[4]);

    // 2. Decode hex to bytes
    let mut salt = [0u8; 12];
    decode(hex_salt, &mut salt).unwrap();
    let mut nonce = [0u8; 12];
    decode(hex_nonce, &mut nonce).unwrap();
    let mut vault = vec![0u8; hex_vault.len() / 2];
    decode(hex_vault, &mut vault).unwrap();

    // 3. Get password file contents
    let path = format!("{}/passwords", DIRECTORY);
    let file = File::open(path).unwrap(); // Replace with your filename
    let reader = BufReader::new(file);

    for password_result in reader.lines() {
        let password = password_result.unwrap(); // Each line as a String
        // writeln!(writer, "{}", password).unwrap();

        // 4. Derive key & hash
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 100_100, &mut key);
        let mut hash = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 100_101, &mut hash);

        // 5. Compare hashes
        let mut hash_hex = [0u8; 64];
        encode(&hash, &mut hash_hex).unwrap();
        let hash_hex_str = std::str::from_utf8(&hash_hex).unwrap();
        if hex_hash != hash_hex_str {
            // writeln!(writer, "Hash mismatch!").unwrap();
            continue;
        } else {
            // 6. Decrypt vault
            let key = Key::<Aes256Gcm>::from_slice(&key);
            let cipher = Aes256Gcm::new(key);
            let nonce = Nonce::from_slice(&nonce); // 96-bits; 12-bytes
            let plaintext = cipher
                .decrypt(nonce, vault.as_ref())
                .expect("decryption failed");

            writeln!(writer, "Username: {}", username).unwrap();
            writeln!(writer, "Password: {}\n", password).unwrap();

            writeln!(
                writer,
                "Vault contents: {}",
                String::from_utf8_lossy(&plaintext)
            )
            .unwrap();
            break;
        }
    }
}

fn main() {
    // Creates output file
    let path = format!("{}/{}_solutions.txt", DIRECTORY, DIRECTORY);
    let file = File::create(path).unwrap(); // Overwrites or creates file
    let mut writer = BufWriter::new(file);

    // Get vault file contents
    let path = format!("{}/vaults", DIRECTORY);
    let file = File::open(path).unwrap(); // Replace with your filename
    let reader = BufReader::new(file);
    let mut vault_num = 1;

    for line_result in reader.lines() {
        let line = line_result.unwrap(); // Each line as a String
        writeln!(
            writer,
            "Vault {}:\n-------------------------------------------------------\n",
            vault_num
        )
        .unwrap();
        decrypt_vault(line, &mut writer);
        writeln!(
            writer,
            "-------------------------------------------------------\n\n"
        )
        .unwrap();
        vault_num += 1;
    }
}
