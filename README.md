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
