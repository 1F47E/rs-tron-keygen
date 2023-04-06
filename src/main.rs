///
/// Here are the steps to decode a public key to a Tron address:
///
/// 1. Take the public key that you want to decode. It should be in hexadecimal format.
///
/// 2. Decode the public key from hexadecimal to binary.
///
/// 3. Take the Keccak-256 hash of the binary public key. Keccak-256 is a hashing algorithm used by Tron to derive addresses.
///
/// 4. Take the first byte of the Keccak-256 hash, which should be 41 in hexadecimal.
///
/// 5. Append the remaining 20 bytes of the Keccak-256 hash to the first byte 41.
///
/// 6. Convert the resulting 21-byte binary string to a Base58Check encoded string. Base58Check is a variation of Base58 encoding that adds a checksum to ensure that the address is valid.
///
/// 7. The resulting Base58Check encoded string is the Tron address corresponding to the public key.
///
/// The Tron address is now ready!
///
///
use rand::Rng;
use ripemd::Digest;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

fn main() {
    let key = generate_key();
    println!("Private key: {}", hex::encode(key));
    let public_key = public_key_from_private_key(&key);
    println!("Public key: {}", hex::encode(public_key));
    let address_hex = address_hex_from_public_key(&public_key);
    println!("Address hex: {}", address_hex);
    let address_b58 = address_b58_from_address_hex(&address_hex);
    println!("Address base58: {}", address_b58);
}

/// Generate a random private key and return it as a 32 byte array
fn generate_key() -> [u8; 32] {
    let mut rng = rand::thread_rng();
    let private_key = loop {
        let bytes: [u8; 32] = rng.gen();
        if let Ok(key) = SecretKey::from_slice(&bytes) {
            break key;
        }
    };
    private_key.secret_bytes()
}

/// Get the public key from a private key
fn public_key_from_private_key(private_key: &[u8]) -> [u8; 65] {
    let secp = Secp256k1::new();
    let private_key = SecretKey::from_slice(private_key).unwrap();
    let public_key = PublicKey::from_secret_key(&secp, &private_key);
    public_key.serialize_uncompressed()
}

/// Get the address from a public key in hex format
fn address_hex_from_public_key(public_key: &[u8]) -> String {
    // Hash bytes using SHA3-256 algorithm
    let mut hasher = sha3::Keccak256::new();
    // remove the first byte
    let public_key_bytes = &public_key[1..];
    hasher.update(public_key_bytes);
    let public_key_hashed = hasher.finalize().to_vec();

    // get last 20 bytes from hash
    let start = public_key_hashed.len() - 20;
    let hashed_last_20 = public_key_hashed[start..].to_vec();

    // Prepend 0x41 to hashed bytes
    let mut prepended = vec![0x41];
    prepended.extend(hashed_last_20.iter());
    hex::encode(&prepended)
}

/// Get the address in base58 format from the address in hex format
/// encoding is base58 with checksum
fn address_b58_from_address_hex(address_hex: &str) -> String {
    let address_bytes = hex::decode(address_hex).unwrap();
    // get checksum
    let double_hash = sha2::Sha256::digest(sha2::Sha256::digest(&address_bytes));
    let checksum = double_hash[0..4].to_vec();
    // apend checksum to hex address
    let prepended_with_checksum = [&address_bytes[..], &checksum[..]].concat();
    bs58::encode(&prepended_with_checksum).into_string()
}
