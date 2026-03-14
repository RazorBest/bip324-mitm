// SPDX-License-Identifier: CC0-1.0

//! Wrap ciphers with automatic re-keying in order to provide [forward secrecy](https://eprint.iacr.org/2001/035.pdf) within a session.
//! Logic is covered by the BIP-324 test vectors.
//!
//! ## Performance Considerations
//!
//! This module uses small stack-allocated arrays (12-byte nonces, 32-byte keys) for temporary
//! cryptographic operations. These allocations are intentionally kept as local variables rather
//! than pre-allocated struct fields for optimal performance.
//!
//! Tests comparing the current implementation against a version with
//! pre-allocated buffers to reduce stack allocations showed decreased performance.
//!
//! (OUTDATED) * **FSChaCha20 operations** +3.7% overhead with pre-allocated buffers.
//! * **FSChaCha20Poly1305 operations** +1.0% overhead with pre-allocated buffers.  

use chacha20_poly1305::{ChaCha20Poly1305, Key, Nonce, chacha20::ChaCha20};
use core::fmt;

use crate::external::chacha20_poly1305::ChaCha20Poly1305Stream;

/// Message lengths are encoded in three bytes.
const LENGTH_BYTES: u32 = 3;
/// Ciphers are re-keyed after 224 messages (or chunks).
const REKEY_INTERVAL: u64 = 224;
/// Static four byte prefix used on every re-key.
const REKEY_INITIAL_NONCE: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];

/// Errors encrypting and decrypting with [`FSChaCha20Poly1305`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Decryption(chacha20_poly1305::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Decryption(e) => write!(f, "Unable to dycrypt: {e}."),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Decryption(e) => Some(e),
        }
    }
}

/// A wrapper over ChaCha20Poly1305 AEAD stream cipher which handles automatically changing
/// nonces and re-keying, providing forward secrecy within the session.
///
/// FSChaCha20Poly1305 is used for message packets in BIP-324.
#[derive(Clone)]
pub struct FSChaCha20Poly1305 {
    key: Key,
    message_counter: u64,
    stream_mode: bool,

    #[cfg(test)]
    pub key_bytes: [u8; 32],
}

impl FSChaCha20Poly1305 {
    pub fn new(key: [u8; 32]) -> Self {
        FSChaCha20Poly1305 {
            key: Key::new(key),
            message_counter: 0,
            stream_mode: false,

            #[cfg(test)]
            key_bytes: key,
        }
    }

    /// Derive current nonce.
    fn nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        // The 32-bit little-endian encoding of the number of messages with the current key.
        let counter_mod = ((self.message_counter % REKEY_INTERVAL) as u32).to_le_bytes();
        nonce[0..4].copy_from_slice(&counter_mod);
        // The 64-bit little-endian encoding of the number of rekeyings performed.
        let counter_div = (self.message_counter / REKEY_INTERVAL).to_le_bytes();
        nonce[4..12].copy_from_slice(&counter_div);

        nonce
    }

    /// Increment the message counter and rekey if necessary.
    fn rekey(&mut self, aad: &[u8]) {
        if self.stream_mode {
            panic!("Can't rekey while in stream mode");
        }
        if (self.message_counter + 1).is_multiple_of(REKEY_INTERVAL) {
            let mut rekey_nonce = [0u8; 12];
            rekey_nonce[0..4].copy_from_slice(&REKEY_INITIAL_NONCE);
            rekey_nonce[4..].copy_from_slice(&self.nonce()[4..]);

            let mut plaintext = [0u8; 32];
            let cipher = ChaCha20Poly1305::new(self.key, Nonce::new(rekey_nonce));
            cipher.encrypt(&mut plaintext, Some(aad));
            self.key = Key::new(plaintext);
        }

        self.message_counter += 1;
    }

    /// Encrypt the contents in place and return the 16-byte authentication tag.
    ///
    /// # Arguments
    ///
    /// * `content` - Plaintext to be encrypted in place.
    /// * `aad`     - Optional associated authenticated data covered by the authentication tag.
    ///
    /// # Returns
    ///
    /// The 16-byte authentication tag.
    pub fn encrypt(&mut self, aad: &[u8], content: &mut [u8]) -> [u8; 16] {
        if self.stream_mode {
            panic!("Can't encrypt block while in stream mode");
        }
        let cipher = ChaCha20Poly1305::new(self.key, Nonce::new(self.nonce()));

        let tag = cipher.encrypt(content, Some(aad));

        self.rekey(aad);

        tag
    }

    pub fn start_one_payload_stream_encryption(&mut self) -> ChaCha20Poly1305Stream {
        if self.stream_mode {
            panic!(
                "Can't start a new stream. Another stream has already started without ending the previous one"
            );
        }
        let stream_cipher = ChaCha20Poly1305Stream::new(self.key, Nonce::new(self.nonce()));
        self.stream_mode = true;

        stream_cipher
    }

    pub fn end_current_stream(&mut self, aad: &[u8]) {
        self.stream_mode = false;
        self.rekey(aad);
    }

    /// Decrypt the contents in place.
    ///
    /// # Arguments
    ///
    /// * `content` - Ciphertext to be decrypted in place.
    /// * `tag`     - 16-byte authentication tag.
    /// * `aad`     - Optional associated authenticated data covered by the authentication tag.
    pub fn decrypt(&mut self, aad: &[u8], content: &mut [u8], tag: [u8; 16]) -> Result<(), Error> {
        if self.stream_mode {
            panic!("Can't decrypt block while in stream mode");
        }
        let cipher = ChaCha20Poly1305::new(self.key, Nonce::new(self.nonce()));

        cipher
            .decrypt(content, tag, Some(aad))
            .map_err(Error::Decryption)?;

        self.rekey(aad);

        Ok(())
    }
}

#[derive(Clone)]
pub struct FSChaCha20Stream {
    key: Key,
    byte_counter: u32,
    total_byte_counter: u32,

    #[cfg(test)]
    pub key_bytes: [u8; 32],
}

impl FSChaCha20Stream {
    pub fn new(key: [u8; 32]) -> Self {
        FSChaCha20Stream {
            key: Key::new(key),
            byte_counter: 0,
            total_byte_counter: 0,

            #[cfg(test)]
            key_bytes: key,
        }
    }

    fn rekey(&mut self) {
        const STREAM_SIZE: u32 = REKEY_INTERVAL as u32 * LENGTH_BYTES;
        if self.byte_counter < STREAM_SIZE {
            return;
        }

        let counter_mod = (self.total_byte_counter / STREAM_SIZE - 1).to_le_bytes();
        let mut nonce = [0u8; 12];
        nonce[4..8].copy_from_slice(&counter_mod);

        let mut cipher = ChaCha20::new(self.key, Nonce::new(nonce), 0);
        cipher.seek(self.byte_counter);

        let mut key_buffer = [0u8; 32];
        cipher.apply_keystream(&mut key_buffer);
        self.key = Key::new(key_buffer);
        self.byte_counter = 0;
    }

    fn initialize_cipher_at_position(&self, position: u32) -> ChaCha20 {
        const STREAM_SIZE: u32 = REKEY_INTERVAL as u32 * LENGTH_BYTES;
        let counter_mod = (self.total_byte_counter / STREAM_SIZE).to_le_bytes();
        let mut nonce = [0u8; 12];
        nonce[4..8].copy_from_slice(&counter_mod);

        let mut cipher = ChaCha20::new(self.key, Nonce::new(nonce), 0);
        cipher.seek(position);

        cipher
    }

    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        const STREAM_SIZE: u32 = REKEY_INTERVAL as u32 * LENGTH_BYTES;
        let remaining_data = if self.byte_counter + data.len() as u32 >= STREAM_SIZE {
            let bytes_until_next_chunk = (STREAM_SIZE - self.byte_counter) as usize;
            let (first_chunk, rest) = data.split_at_mut(bytes_until_next_chunk);

            // Encrypt a partial first chunk such that self.bytes_counter can become 0
            {
                let mut cipher = self.initialize_cipher_at_position(self.byte_counter);
                cipher.apply_keystream(first_chunk);
                self.byte_counter += first_chunk.len() as u32;
                self.total_byte_counter += first_chunk.len() as u32;
            }

            self.rekey();

            // Encrypt chunks of fixed size, and rekey after each chunk
            let mut chunks = rest.chunks_exact_mut(STREAM_SIZE as usize);
            for chunk in &mut chunks {
                debug_assert_eq!(self.byte_counter, 0);
                let mut cipher = self.initialize_cipher_at_position(0);
                cipher.apply_keystream(chunk);
                self.byte_counter += chunk.len() as u32;
                self.total_byte_counter += chunk.len() as u32;
                self.rekey();
            }

            chunks.into_remainder()
        } else {
            data
        };

        debug_assert!(self.byte_counter + (remaining_data.len() as u32) < STREAM_SIZE);

        let mut test_buf = [0u8; 3];
        let mut cipher = self.initialize_cipher_at_position(self.byte_counter);
        cipher.apply_keystream(&mut test_buf);

        let mut cipher = self.initialize_cipher_at_position(self.byte_counter);
        cipher.apply_keystream(remaining_data);
        self.byte_counter += remaining_data.len() as u32;
        self.total_byte_counter += remaining_data.len() as u32;
    }
}
