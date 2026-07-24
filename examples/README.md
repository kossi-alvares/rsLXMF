# Networked LXMF examples in Rust

These binaries are real-network counterparts to
`LXMF/docs/example_sender.py` and `LXMF/docs/example_receiver.py`. They start
rsReticulum, use the canonical `lxmf.delivery` destination, exchange announces,
and transfer signed LXMF messages over a Reticulum Link.

Start the receiver:

```text
cargo run -p lxmf-examples --bin example_receiver
```

It registers a `LinkManager`, announces its destination and prints the
destination hash. Keep it running.

In another terminal, pass that hash to the sender:

```text
cargo run -p lxmf-examples --bin example_sender -- <recipient_hash>
```

If the hash is omitted, the sender prompts for it like the Python example. The
sender announces its own delivery identity, requests a path when necessary,
recalls the recipient identity, establishes and identifies a Direct Link, then
waits for the packet or Resource delivery proof before exiting.

An optional Reticulum config directory can be supplied after the recipient to
the sender, or as the first argument to the receiver:

```text
cargo run -p lxmf-examples --bin example_receiver -- /path/to/rns-config
cargo run -p lxmf-examples --bin example_sender -- <hash> /path/to/rns-config
```

The receiver accepts both single Link packets and larger Resource transfers.
For each message it decodes the LXMF envelope, recalls the announced source
identity when available, validates the Ed25519 signature, and prints the same
core fields as the Python callback.

The Rust sender is intentionally one-shot instead of the Python script's
infinite “press Enter to send another random message” loop. This keeps it
useful in scripts while preserving the actual announce, discovery, Link and
delivery semantics.

The examples crate includes a loopback integration test that runs a shared
Reticulum instance plus separate sender and receiver clients, transfers an
oversized signed message as a Resource, waits for its proof and validates the
received signature:

```text
cargo test -p lxmf-examples
```
