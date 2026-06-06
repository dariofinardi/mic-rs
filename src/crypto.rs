use aes::Aes256;
use cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use hkdf::Hkdf;
use p256::{ecdh::EphemeralSecret, PublicKey};
use rand_core::OsRng;
use sha2::Sha256;

use crate::error::SoundcoreError;
use crate::protocol::{BLOCKS_PER_PACKET, FILE_KEY_MAGIC, HKDF_INFO, HKDF_SALT};

type Aes256Ctr = Ctr128BE<Aes256>;

// ---------- ECDH key exchange ----------

pub struct EcdhKeypair {
    secret: Option<EphemeralSecret>,
    pub public_key_bytes: Vec<u8>,
}

impl EcdhKeypair {
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random(&mut OsRng);
        let public = PublicKey::from(&secret);
        let public_bytes = public.to_sec1_bytes().to_vec();
        Self {
            secret: Some(secret),
            public_key_bytes: public_bytes,
        }
    }

    pub fn derive_shared_secret(
        mut self,
        device_public_bytes: &[u8],
    ) -> Result<[u8; 32], SoundcoreError> {
        let dev_public = PublicKey::from_sec1_bytes(device_public_bytes).map_err(|e| {
            SoundcoreError::CryptoError(format!("invalid device public key: {e}"))
        })?;
        let secret = self
            .secret
            .take()
            .ok_or_else(|| SoundcoreError::CryptoError("keypair already consumed".into()))?;
        let shared = secret.diffie_hellman(&dev_public);
        let raw = shared.raw_secret_bytes();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(raw.as_slice());
        Ok(bytes)
    }
}

// ---------- HKDF session key derivation ----------

pub fn derive_session_key(shared_secret: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(&HKDF_SALT), shared_secret);
    let mut key = [0u8; 32];
    hk.expand(&HKDF_INFO, &mut key).expect("HKDF expand failed");
    key
}

// ---------- File key decryption ----------
// Decrypts the 46-byte encrypted_key from the 1A07 header using AES-256-CTR.
// Plaintext = "soundcored3200" (14 bytes) + file_key (32 bytes).

pub fn decrypt_file_key(
    session_key: &[u8; 32],
    encrypted_key: &[u8; 46],
    session_nonce: &[u8; 16],
) -> Result<[u8; 32], SoundcoreError> {
    let mut decrypted = [0u8; 46];
    decrypted.copy_from_slice(encrypted_key);

    let key = cipher::generic_array::GenericArray::from_slice(session_key);
    let iv = cipher::generic_array::GenericArray::from_slice(session_nonce);
    let mut cipher = Aes256Ctr::new(key, iv);
    cipher.apply_keystream(&mut decrypted);

    if &decrypted[..14] != FILE_KEY_MAGIC {
        return Err(SoundcoreError::CryptoError(
            "invalid file key: missing 'soundcored3200' magic header".into(),
        ));
    }

    let mut file_key = [0u8; 32];
    file_key.copy_from_slice(&decrypted[14..46]);
    Ok(file_key)
}

// ---------- Chunk decryption (AES-256-CTR, big-endian counter) ----------
// IV layout: nonce[0..12] || (sequence_number * BLOCKS_PER_PACKET) as BE u32
// Each 160-byte chunk = 10 AES blocks. SpongyCastle SICBlockCipher increments
// the counter internally per block, so packet N starts at counter N*10.

pub fn decrypt_chunk(
    file_key: &[u8; 32],
    nonce_base: &[u8; 16],
    sequence_number: u32,
    encrypted: &[u8],
) -> Vec<u8> {
    let mut iv = [0u8; 16];
    iv[..12].copy_from_slice(&nonce_base[..12]);
    let counter = sequence_number * BLOCKS_PER_PACKET;
    iv[12..16].copy_from_slice(&counter.to_be_bytes());

    let key = cipher::generic_array::GenericArray::from_slice(file_key);
    let iv_ga = cipher::generic_array::GenericArray::from_slice(&iv);
    let mut cipher = Aes256Ctr::new(key, iv_ga);
    let mut output = encrypted.to_vec();
    cipher.apply_keystream(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- ECDH ----------

    #[test]
    fn ecdh_keypair_generates() {
        let kp = EcdhKeypair::generate();
        assert_eq!(kp.public_key_bytes[0], 0x04); // uncompressed SEC1
        assert_eq!(kp.public_key_bytes.len(), 65);
    }

    #[test]
    fn ecdh_keypairs_are_unique() {
        let kp1 = EcdhKeypair::generate();
        let kp2 = EcdhKeypair::generate();
        assert_ne!(kp1.public_key_bytes, kp2.public_key_bytes);
    }

    #[test]
    fn ecdh_shared_secret_between_two_pairs() {
        let kp_a = EcdhKeypair::generate();
        let kp_b = EcdhKeypair::generate();
        let pub_a = kp_a.public_key_bytes.clone();
        let pub_b = kp_b.public_key_bytes.clone();

        let secret_a = kp_a.derive_shared_secret(&pub_b).unwrap();
        let secret_b = kp_b.derive_shared_secret(&pub_a).unwrap();
        assert_eq!(secret_a, secret_b);
    }

    #[test]
    fn ecdh_invalid_public_key() {
        let kp = EcdhKeypair::generate();
        let bad_key = vec![0xFF; 65];
        assert!(kp.derive_shared_secret(&bad_key).is_err());
    }

    #[test]
    fn ecdh_empty_public_key() {
        let kp = EcdhKeypair::generate();
        assert!(kp.derive_shared_secret(&[]).is_err());
    }

    #[test]
    fn ecdh_derive_consumes_keypair() {
        let kp = EcdhKeypair::generate();
        let other = EcdhKeypair::generate();
        let pub_other = other.public_key_bytes.clone();
        let shared = kp.derive_shared_secret(&pub_other).unwrap();
        assert_ne!(shared, [0u8; 32]);
    }

    // ---------- HKDF ----------

    #[test]
    fn hkdf_deterministic() {
        let fake_secret = [0xABu8; 32];
        let key1 = derive_session_key(&fake_secret);
        let key2 = derive_session_key(&fake_secret);
        assert_eq!(key1, key2);
        assert_ne!(key1, [0u8; 32]);
    }

    #[test]
    fn hkdf_different_inputs_different_keys() {
        let key_a = derive_session_key(&[0x01; 32]);
        let key_b = derive_session_key(&[0x02; 32]);
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn hkdf_short_input_works() {
        let key = derive_session_key(&[0x42]);
        assert_ne!(key, [0u8; 32]);
    }

    #[test]
    fn hkdf_full_ecdh_roundtrip() {
        let kp_a = EcdhKeypair::generate();
        let kp_b = EcdhKeypair::generate();
        let pub_a = kp_a.public_key_bytes.clone();
        let pub_b = kp_b.public_key_bytes.clone();

        let shared_a = kp_a.derive_shared_secret(&pub_b).unwrap();
        let shared_b = kp_b.derive_shared_secret(&pub_a).unwrap();

        let session_a = derive_session_key(&shared_a);
        let session_b = derive_session_key(&shared_b);
        assert_eq!(session_a, session_b);
        assert_ne!(session_a, [0u8; 32]);
    }

    // ---------- decrypt_file_key ----------

    #[test]
    fn decrypt_file_key_with_valid_magic() {
        // Construct a plaintext that starts with the magic header
        let mut plaintext = [0u8; 46];
        plaintext[..14].copy_from_slice(FILE_KEY_MAGIC);
        plaintext[14..46].copy_from_slice(&[0x42; 32]); // file key

        // Encrypt it to get our "encrypted_key"
        let session_key = [0x99u8; 32];
        let session_nonce = [0xBB; 16];
        let mut encrypted = plaintext;
        let key = cipher::generic_array::GenericArray::from_slice(&session_key);
        let iv = cipher::generic_array::GenericArray::from_slice(&session_nonce);
        let mut cipher = Aes256Ctr::new(key, iv);
        cipher.apply_keystream(&mut encrypted);

        let file_key = decrypt_file_key(&session_key, &encrypted, &session_nonce).unwrap();
        assert_eq!(file_key, [0x42; 32]);
    }

    #[test]
    fn decrypt_file_key_bad_magic_fails() {
        // Random data won't have the magic header after decryption
        let session = [0x42u8; 32];
        let enc = [0xAA; 46];
        let nonce = [0xBB; 16];
        let result = decrypt_file_key(&session, &enc, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_file_key_deterministic() {
        let session = [0x42u8; 32];
        let enc = [0xCC; 46];
        let nonce = [0x00; 16];
        let r1 = decrypt_file_key(&session, &enc, &nonce);
        let r2 = decrypt_file_key(&session, &enc, &nonce);
        assert_eq!(r1.is_err(), r2.is_err());
    }

    // ---------- decrypt_chunk ----------

    #[test]
    fn decrypt_chunk_deterministic() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 16];
        let data = [0xFFu8; 160];
        let d1 = decrypt_chunk(&key, &nonce, 0, &data);
        let d2 = decrypt_chunk(&key, &nonce, 0, &data);
        assert_eq!(d1, d2);
        assert_ne!(d1, data.to_vec());
    }

    #[test]
    fn decrypt_chunk_different_seq_different_output() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 16];
        let data = [0xAA; 160];
        let d0 = decrypt_chunk(&key, &nonce, 0, &data);
        let d1 = decrypt_chunk(&key, &nonce, 1, &data);
        let d2 = decrypt_chunk(&key, &nonce, 2, &data);
        assert_ne!(d0, d1);
        assert_ne!(d1, d2);
        assert_ne!(d0, d2);
    }

    #[test]
    fn decrypt_chunk_ctr_is_self_inverse() {
        let key = [0x99u8; 32];
        let nonce = [0x55u8; 16];
        let plaintext = (0..160u8).collect::<Vec<_>>();
        let ciphertext = decrypt_chunk(&key, &nonce, 7, &plaintext);
        let recovered = decrypt_chunk(&key, &nonce, 7, &ciphertext);
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn decrypt_chunk_different_keys_different_output() {
        let nonce = [0x00; 16];
        let data = [0x42; 160];
        let d1 = decrypt_chunk(&[0x01; 32], &nonce, 0, &data);
        let d2 = decrypt_chunk(&[0x02; 32], &nonce, 0, &data);
        assert_ne!(d1, d2);
    }

    #[test]
    fn decrypt_chunk_preserves_length() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 16];
        for len in [0, 1, 16, 100, 160, 256] {
            let data = vec![0xAA; len];
            let out = decrypt_chunk(&key, &nonce, 0, &data);
            assert_eq!(out.len(), len);
        }
    }

    #[test]
    fn decrypt_chunk_iv_uses_first_12_nonce_bytes() {
        let key = [0x42u8; 32];
        let data = [0xAA; 160];
        // Two nonces identical in first 12 bytes, different in last 4
        let mut nonce_a = [0x01u8; 16];
        let mut nonce_b = [0x01u8; 16];
        nonce_a[12..16].copy_from_slice(&[0xFF; 4]);
        nonce_b[12..16].copy_from_slice(&[0x00; 4]);
        // With seq=0, counter=0, so iv[12..16] = 0x00000000 for both
        // The last 4 bytes of the nonce are overwritten by the counter
        let d_a = decrypt_chunk(&key, &nonce_a, 0, &data);
        let d_b = decrypt_chunk(&key, &nonce_b, 0, &data);
        assert_eq!(d_a, d_b);
    }

    #[test]
    fn decrypt_chunk_counter_is_seq_times_blocks() {
        let key = [0x42u8; 32];
        let nonce = [0x00u8; 16];
        let data = [0xAA; 160];

        // seq=0 → counter=0, iv = [0;16]
        // seq=1 → counter=10, iv[12..16] = [0,0,0,10]
        let d0 = decrypt_chunk(&key, &nonce, 0, &data);
        let d1 = decrypt_chunk(&key, &nonce, 1, &data);
        assert_ne!(d0, d1);

        // Verify the IV construction explicitly
        let mut expected_iv = [0u8; 16];
        expected_iv[12..16].copy_from_slice(&(1u32 * BLOCKS_PER_PACKET).to_be_bytes());
        let k = cipher::generic_array::GenericArray::from_slice(&key);
        let iv = cipher::generic_array::GenericArray::from_slice(&expected_iv);
        let mut cipher = Aes256Ctr::new(k, iv);
        let mut manual = data.to_vec();
        cipher.apply_keystream(&mut manual);
        assert_eq!(d1, manual);
    }
}
