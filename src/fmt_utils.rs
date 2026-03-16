use crate::external::chacha20_poly1305::ChaCha20Poly1305Stream;
use crate::protocol::EcdhPoint;
use std::fmt;

impl fmt::Debug for ChaCha20Poly1305Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<ChaCha20Poly1305Stream>")
    }
}

impl fmt::Debug for EcdhPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<EcdhPoint>")
    }
}
