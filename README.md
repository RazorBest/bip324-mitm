# BIP324 MitM

Rust crate implementing the MitM adaptation of the BIP-324 encrypted protocol. Used for MitM proxies and network analysis tools.

This MitM layer is async-compatible and has byte-level granularity:
- async-compatible: the read/write functions are non-blocking
- byte-level granularity: for each byte sent by the sending peer, the mitm bridge can send one byte to the receiving peer

## Getting started

The library exposes the `MitmBIP324` struct, which can be placed between the client and the server, and has 4 main methods:
- `client_write`: receives the bytes from the client
- `client_read`: sends bytes to the client
- `server_write`: receives bytes from the server
- `server_read`: sends bytes to the server

![Top level diagram of the MitmBIP324 struct](/doc/images/bip324mitm_api.png)

**Example:**:
```rust
use std::error::Error;

use bip324_mitm::{MitmBIP324, UserKeyInfo};
use hex_literal::hex;

const BUFSIZE: usize = 2048;

fn main() -> Result<(), Box<dyn Error>> {
    let fake_client_key = UserKeyInfo::new(
        /* secret */ hex!("61062ea5071d800bbfd59e2e8b53d47d194b095ae5a4df04936b49772ef0d4d7"),
        /* pubkey_ellswift */ Some(hex!("ec0adff257bbfe500c188c80b4fdd640f6b45a482bbc15fc7cef5931deff0aa186f6eb9bba7b85dc4dcc28b28722de1e3d9108b985e2967045668f66098e475b")),
    );
    let fake_server_key = UserKeyInfo::new(
        /* secret */ hex!("6f312890ec83bbb26798abaadd574684a53e74ccef7953b790fcc29409080246"),
        /* pubkey_ellswift */ Some(hex!("a8785af31c029efc82fa9fc677d7118031358d7c6a25b5779a9b900e5ccd94aac97eb36a3c5dbcdb2ca5843cc4c2fe0aaa46d10eb3d233a81c3dde476da00eef")),
    );

    let mut mitm = MitmBIP324::new_from_key_info(fake_client_key, fake_server_key)?;

    let data_from_client = hex!("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f0000000000000000000000000000000000000000000000000000000000000000ca29b3a35237f8212bd13ed187a1da2e");
    let data_from_server = hex!("a4a94dfce69b4a2a0a099313d10f9f7e7d649d60501c9e1d274c300e0d89aafaffffffffffffffffffffffffffffffffffffffffffffffffffffffff8faf88d52222222222222202cb8ff24307a6e27de3b4e7ea3fa65b");

    mitm.client_write(&data_from_client)?;
    mitm.server_write(&data_from_server)?;

    let mut data_to_client = [0u8; BUFSIZE];
    let mut data_to_server = [0u8; BUFSIZE];
    let size1 = mitm.server_read(&mut data_to_server)?;
    let size2 = mitm.client_read(&mut data_to_client)?;

    // Expect ec0adff257bbfe500c188c80b4fdd640f6b45a482bbc15fc7cef5931deff0aa186f6eb9bba7b85dc4dcc28b28722de1e3d9108b985e2967045668f66098e475bfaef555dfcdb936425d84aba524758f3
    println!("data_to_server: {:?}", &data_to_server[..size1]);
    // Expect a8785af31c029efc82fa9fc677d7118031358d7c6a25b5779a9b900e5ccd94aac97eb36a3c5dbcdb2ca5843cc4c2fe0aaa46d10eb3d233a81c3dde476da00eef2222222222222244737108aec5f8b6c1c277b31bbce9c1
    println!("data_to_client: {:?}", &data_to_client[..size2]);

    Ok(())
}
```
