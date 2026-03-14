use bip324::Role;
use secp256k1::{SecretKey, ellswift::ElligatorSwift};

use crate::external::bip324::fschacha20poly1305::{FSChaCha20Poly1305, FSChaCha20Stream};
use crate::external::bip324::{InboundCipher, OutboundCipher, SessionKeyMaterial};

/// A point on the curve used to complete the handshake.
#[derive(Clone)]
pub struct EcdhPoint {
    pub(crate) secret_key: SecretKey,
    pub(crate) elligator_swift: ElligatorSwift,
}

/// Manages cipher state for a BIP-324 encrypted connection.
#[derive(Debug, Clone)]
pub struct CipherSession {
    /// A unique identifier for the communication session.
    id: [u8; 32],
    /// Decrypts inbound packets.
    pub(crate) inbound: InboundCipher,
    /// Encrypts outbound packets.
    pub(crate) outbound: OutboundCipher,
}

impl CipherSession {
    pub(crate) fn new(mut materials: SessionKeyMaterial, role: Role) -> Self {
        if role == Role::Responder {
            std::mem::swap(
                &mut materials.initiator_length_key,
                &mut materials.responder_length_key,
            );
            std::mem::swap(
                &mut materials.initiator_packet_key,
                &mut materials.responder_packet_key,
            );
        }

        let outbound_length_cipher = FSChaCha20Stream::new(materials.initiator_length_key);
        let inbound_length_cipher = FSChaCha20Stream::new(materials.responder_length_key);
        let outbound_packet_cipher = FSChaCha20Poly1305::new(materials.initiator_packet_key);
        let inbound_packet_cipher = FSChaCha20Poly1305::new(materials.responder_packet_key);

        CipherSession {
            id: materials.session_id,
            inbound: InboundCipher {
                length_cipher: inbound_length_cipher,
                packet_cipher: inbound_packet_cipher,
            },
            outbound: OutboundCipher {
                length_cipher: outbound_length_cipher,
                packet_cipher: outbound_packet_cipher,
            },
        }
    }

    /// Unique session ID.
    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    /// Get a mutable reference to the inbound cipher for decryption operations.
    pub fn inbound(&mut self) -> &mut InboundCipher {
        &mut self.inbound
    }

    /// Get a mutable reference to the outbound cipher for encryption operations.
    pub fn outbound(&mut self) -> &mut OutboundCipher {
        &mut self.outbound
    }

    /// Split the session into separate inbound and outbound ciphers.
    pub fn into_split(self) -> (InboundCipher, OutboundCipher) {
        (self.inbound, self.outbound)
    }
}
