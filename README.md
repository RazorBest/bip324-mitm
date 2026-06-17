# BIP324 MitM

Rust crate implementing the MitM adaptation of the BIP-324 encrypted protocol. Used for MitM proxies and network analysis tools.

This MitM layer is async-compatible and has byte-level granularity:
- async-compatible: the read/write functions are non-blocking
- byte-level granularity: for each byte sent by the sending peer, the mitm bridge can send one byte to the receiving peer

## Getting started

The library exposes the `MitmBIP324` struct, which can be placed between the client and the server, and has 6 main methods:
- `client_write`: receives the bytes from the client
- `client_read`: sends bytes to the client
- `server_write`: receives bytes from the server
- `server_read`: sends bytes to the server
- `next_client_protocol_packet`: returns a decrypted packet from the client
- `next_server_protocol_packet`: returns a decrypted packet from the server

![Top level diagram of the MitmBIP324 struct](/doc/images/bip324mitm_api.png)

**Examples**:

Check the examples directory

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
