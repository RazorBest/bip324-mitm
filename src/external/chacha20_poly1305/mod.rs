use chacha20_poly1305::{Key, Nonce, chacha20::ChaCha20, poly1305::Poly1305};

/// Zero array for padding slices.
const ZEROES: [u8; 16] = [0u8; 16];

/// Encrypt and decrypt content along with an authentication tag.
pub struct ChaCha20Poly1305Stream {
    chacha: ChaCha20,
    encrypted: Vec<u8>,
}

// Copied from https://github.com/rust-bitcoin/rust-bitcoin/blob/c93d17ab2becc683e090486b9dbe5b02ce46f82e/chacha20_poly1305/src/lib.rs
// And modified to support proper stream encryption
impl ChaCha20Poly1305Stream {
    /// Make a new instance of a `ChaCha20Poly1305` AEAD.
    pub const fn new(key: Key, nonce: Nonce) -> Self {
        let chacha = ChaCha20::new_from_block(key, nonce, 1);
        Self {
            chacha,
            encrypted: vec![],
        }
    }

    /// Encrypt content chunk using the underlying stream cipher, and store the result internally.
    ///
    /// # Parameters
    ///
    /// - `content` - the plaintext chunk to be encrypted.
    pub fn encrypt_and_store_chunk(&mut self, content: &mut [u8]) {
        self.chacha.apply_keystream(content);
        self.encrypted.extend_from_slice(content);
    }

    /// Decrypt the ciphertext chunk in place using the underlying stream cipher.
    /// Also store the ciphertext internally for when computign the authentication tag.
    ///
    /// # Parameters
    ///
    /// - `content` - the ciphertext chunk to be decrypted.
    pub fn decrypt_and_store_chunk(&mut self, content: &mut [u8]) {
        self.encrypted.extend_from_slice(content);
        self.chacha.apply_keystream(content);
    }

    pub fn get_tag(self, aad: Option<&[u8]>) -> [u8; 16] {
        let keystream = self.chacha.get_keystream(0);
        let mut poly_key = [0u8; 32];
        poly_key.copy_from_slice(&keystream[..32]);
        let mut poly = Poly1305::new(poly_key);
        let aad = aad.unwrap_or(&[]);
        // AAD and ciphertext are padded if not 16-byte aligned.
        poly.input(aad);
        let aad_overflow = aad.len() % 16;
        if aad_overflow > 0 {
            poly.input(&ZEROES[0..(16 - aad_overflow)]);
        }

        poly.input(&self.encrypted);
        let text_overflow = self.encrypted.len() % 16;
        if text_overflow > 0 {
            poly.input(&ZEROES[0..(16 - text_overflow)]);
        }

        let len_buffer = encode_lengths(aad.len() as u64, self.encrypted.len() as u64);
        poly.input(&len_buffer);
        poly.tag()
    }

    /// Returns true if the tag is valid.
    pub fn check_tag(self, tag: [u8; 16], aad: Option<&[u8]>) -> bool {
        self.get_tag(aad) == tag
    }
}

/// AAD and content lengths are each encoded in 8-bytes.
fn encode_lengths(aad_len: u64, content_len: u64) -> [u8; 16] {
    let aad_len_bytes = aad_len.to_le_bytes();
    let content_len_bytes = content_len.to_le_bytes();
    let mut len_buffer = [0u8; 16];
    let (aad_len_buffer, content_len_buffer) = len_buffer.split_at_mut(8);
    aad_len_buffer.copy_from_slice(&aad_len_bytes[..]);
    content_len_buffer.copy_from_slice(&content_len_bytes[..]);

    len_buffer
}
