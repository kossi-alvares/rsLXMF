# LXMF examples in Rust

These binaries correspond to `LXMF/docs/example_sender.py` and
`LXMF/docs/example_receiver.py`:

```text
cargo run -p lxmf-examples --bin example_sender -- <recipient_hash>
cargo run -p lxmf-examples --bin example_receiver -- <packed_lxmf_hex>
```

Arguments are optional so both programs also run as deterministic API probes.
The sender creates and signs a Direct message, queues it in `LxmRouter`, and
prints its wire representation. The receiver creates an `lxmf.delivery`
identity and announce, and can decode a packed message.

`DeliveryIdentity` in `lxmf-core::application` fills the application API gap
found by the port: it binds an RNS Identity to the canonical delivery
Destination, announce metadata, announce construction and signed message
creation.

End-to-end interface/link driving remains the responsibility of a runtime
adapter. The complete adapter currently lives in `lxmd-rs`; the core router
deliberately has no hidden network task.
