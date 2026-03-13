use crate::external::bip324::{InboundCipher, OutboundCipher};
use crate::external::chacha20_poly1305::ChaCha20Poly1305Stream;
use std::fmt;

impl fmt::Debug for InboundCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<InboundCipher>")
    }
}

impl fmt::Debug for OutboundCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<OutboundCipher>")
    }
}

impl fmt::Debug for ChaCha20Poly1305Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<ChaCha20Poly1305Stream>")
    }
}
