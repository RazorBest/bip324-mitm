# Examples

## intercept
This example uses the `nfq-rs` crate to access the nerfilter_nfqueue API. In order to receive the packets, you need to tell the kernel to store those packets in a queue with a given id. Then the user process will attach to the queue and consume it.
netfilter_queue lets you accept, drop and modify packets. The way you redirect packets to nfqueue is through iptables.

Here is an example of how to set the iptables rules, to catch all the packets on port 8333:
```
iptables -A INPUT -t mangle -p tcp --dport 8333 -j NFQUEUE --queue-num 0 --queue-bypass
iptables -A INPUT -t mangle -p tcp --sport 8333 -j NFQUEUE --queue-num 0 --queue-bypass
iptables -A OUTPUT -t mangle -p tcp --dport 8333 -j NFQUEUE --queue-num 0 --queue-bypass
iptables -A OUTPUT -t mangle -p tcp --sport 8333 -j NFQUEUE --queue-num 0 --queue-bypass
```

If one of the rules matches, it pushes the packet on the queue with id 0, and waits for a verdict. If `--queue-bypass` is set, then the packet is pushed only if a process is attached to the queue. Otherwise, the packet will flow as if no rule was present.

One issue with these rules is that they are bound by the port. However, Bitcoin peers can also listen to other ports. A better way to do this is to catch all the tcp packets from a specific user. Then, run the bitcoin node under that user.

> [!CAUTION]
> The following rules could get you locked out of your ssh session, or cut you off from the internet, especially if you remove `--queue-bypass`. Make sure you don't use them on your main user.

Second, more robust example:
```
# Allow the RPC communication (otherwise, you can't use bitcoin-cli). These rules must be placed before the NFQUEUE rules.
iptables -t mangle -A INPUT -p tcp -s 127.0.0.1 -d 127.0.0.1 --dport 8332 -j ACCEPT
iptables -t mangle -A INPUT -p tcp -s 127.0.0.1 -d 127.0.0.1 --sport 8332 -j ACCEPT
iptables -t mangle -A OUTPUT -p tcp -m owner --uid-owner btc_user -m tcp --sport 8332 -j ACCEPT
iptables -t mangle -A OUTPUT -p tcp -m owner --uid-owner btc_user -m tcp --dport 8332 -j ACCEPT

# Outbound packets are marked and then stored in NFQUEUE
iptables -t mangle -A OUTPUT -p tcp -m owner --uid-owner btc_user -j CONNMARK --set-xmark 0x1/0xffffffff
iptables -t mangle -A OUTPUT -p tcp -m owner --uid-owner btc_user -j NFQUEUE --queue-num 0 --queue-bypass

# Since we can't match inbound packets to users, we match on the mark that was set before.
iptables -t mangle -A INPUT -p tcp -m connmark --mark 0x1 -j NFQUEUE --queue-num 0 --queue-bypass
```

One drawback with these rules is that they don't catch the first SYN packet of an inbound connection.

Running it:
```
cargo build --release --example intercept
./target/release/examples/intercept # sudo is needed
```

## test_bip324

```
cargo run --example test_bip324
```

This one showcases the `bip324` module, without the mitm.

