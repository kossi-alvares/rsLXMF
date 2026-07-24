# Public API compatibility

This document compares the public rsLXMF surface with the local Python LXMF
reference checkout at commit `795fdaa` (LXMF 1.1.0). rsLXMF remains version
1.0.1 and targets wire and behaviour compatibility; it is not intended to be a
name-for-name Rust translation of Python classes.

## Supported equivalents

| Python LXMF surface | rsLXMF surface | Status |
| --- | --- | --- |
| `LXMessage` packing, signing, validation and callbacks | `LxMessage`, `MessagePayload`, `MessageCallbacks` | Implemented |
| Opportunistic, Direct, Propagated and Paper methods | `DeliveryMethod`, `LxmRouter`, `LinkDeliveryManager` | Implemented |
| `LXMRouter.register_delivery_identity()` | `DeliveryIdentity` plus router delivery registration | Implemented with Rust ownership |
| `LXMRouter.register_delivery_callback()` | `LxmRouter::register_delivery_callback()` | Implemented |
| `LXMRouter.handle_outbound()` | `LxmRouter::try_send()` and outbound actor processing | Implemented |
| Propagation-node enablement, storage and peer sync | `PropagationNode`, `PropagationClient`, `PropagationSyncTask` | Implemented |
| Propagation control (`status`, `peers`, `sync`, `break`) | `lxmd-rs` control commands | Implemented |
| Delivery/propagation announces | `DeliveryIdentity` and rsReticulum announce builders | Implemented |
| Stamps, tickets and persistent router state | `stamper`, `ticket`, `persist` | Implemented |

Constants, MessagePack layouts, destination/hash widths, request paths and
delivery state values are covered by compatibility tests against the Python
wire shapes.

## Known differences

- The APIs follow Rust ownership, typed errors and Tokio task conventions.
  Python methods that mutate dynamic objects do not have identical signatures.
- rsLXMF is version 1.0.1 while the checked reference tree is LXMF 1.1.0.
  New 1.1-only API additions are not claimed unless explicitly tested.
- `lxmd-rs` deliberately uses a distinct executable name. Python's `--service`,
  `--verbose` and `--quiet` command-line switches are not exposed; Rust logging
  is configured through its daemon configuration/environment.
- `lxmd-rs` adds `--send`, `--send-file`, `--send-method`,
  `--send-timeout-secs` and `--send-fields-json`.
- Paper-message URI generation and ingest are available in the library, but
  the CLI does not render or scan QR images.
- Propagation and control Link managers currently require an extractable
  software signing key. Hardware-backed identities can sign messages through
  the external signer API, but cannot yet run those two daemon endpoints.
- Stamp generation has a bounded iteration cap to prevent hostile costs from
  occupying a worker indefinitely. Python LXMF does not impose this bound.
- MessagePack extension values in custom fields are rejected; supported field
  values use the typed LXMF field representation.

When compatibility and Rust ergonomics conflict, wire interoperability and
observable network behaviour take precedence over matching Python call
signatures.
