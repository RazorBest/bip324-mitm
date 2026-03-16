# BIP324 MitM

Rust crate implementing the MitM adaptation of the BIP-324 encrypted protocol. Used for MitM proxies and network analysis tools.

This MitM layer is async-compatible and has byte-level granularity:
- async-compatible: the read/write functions are non-blocking
- byte-level granularity: for each byte sent by the sending peer, the mitm bridge can send one byte to the receiving peer

## Getting started

![Top level diagram of the MitmBIP324 struct](/doc/images/bip324mitm_api.png)
