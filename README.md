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

## BIP-324

[BIP-324](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki) is a Bitcoin Improvment Proposal released in 2019.
It features opportunistic encryption over Bitcoin's P2P transport protocol.
It is indistiguishable from [obfs4](https://gitlab.com/yawning/obfs4).
However, it doesn't provide authentication, and in fact the key exchange is vulnerable against Man-in-the-Middle attacks.
This is by design.
If you want to understand more about why BIP-324 doesn't offer authentication, check the proposal.
But the short answer is: it's impossible in Bitcoin's decentralized system.

Nodes known to implement BIP-324:
- Bitcoin Core and Knots
- Bitcoin Knots
- btcd
- Nodes based on the rust-bitcoin crate


## Motivation

Bitcoin's P2P layer stays at the foundation of Bitcoin, below the consensus rules. Everything you know about blockchains wouldn't be possible without having multiple nodes around the world that keep a copy of the blockchain and propagate the new transactions.

Despite its importance, the P2P layer is very little documented. Some characteristic of the network are not even part of the protocol, but they emerge from the system.
For example, one of this characteristics is the block propagation time. Generally, it takes less than a minute for a block to propagate to almost all the peers.
Without a small enough propagation time, Bitcoin would not be practical.

But you might ask yourself: how do you know that the block propagation time is small? Is there a way to prove it, given the P2P protocol specification?
The answer is: not really, because we don't have a good enough theoretical model of the internet.
At the end of the day, we will still need to do live measurements in different points of the network in order to draw conclusions that are closer to the truth.
That's why one key part of networking is monitoring.

This project aims to contribute to [Bitcoin's toolchain for network monitoring](https://bnoc.xyz/).
This is especially useful for monitoring tools that need to know what kind of messages are passedthe  on the P2P network, between the nodes, since BIP324 makes that task harder.

The difference between this library and other monitoring libraries is that this is agnostic of the node's implementation, as long as the node correctly implements the BIP.
