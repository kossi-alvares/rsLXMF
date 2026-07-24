//! Shared implementation for the LXMF sender and receiver examples.

use std::error::Error;

use lxmf_core::application::DeliveryIdentity;
use lxmf_core::constants::{DeliveryMethod, UnverifiedReason};
use lxmf_core::message::LxMessage;
use lxmf_core::router::{LxmRouter, RouterConfig};
use rns_identity::identity::Identity;

pub type ExampleResult = Result<(), Box<dyn Error>>;

pub fn parse_destination_hash(value: &str) -> ExampleResultHash {
    let bytes = hex::decode(value)?;
    if bytes.len() != 16 {
        return Err("destination hash must be exactly 32 hexadecimal characters".into());
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

pub type ExampleResultHash = Result<[u8; 16], Box<dyn Error>>;

/// Sender counterpart. With no hash argument a deterministic demonstration
/// recipient is used, making the example suitable for CI.
pub fn sender(recipient: Option<&str>) -> ExampleResult {
    let recipient = recipient
        .map(parse_destination_hash)
        .transpose()?
        .unwrap_or([0x22; 16]);
    let source = DeliveryIdentity::new(Identity::new(), Some("Rust Sender".into()), Some(8))?;
    let message = source.message(
        recipient,
        "Hi there",
        "This is an LXMF message from the Rust sender example.",
        DeliveryMethod::Direct,
    )?;
    let packed = message.pack()?;

    let mut router = LxmRouter::new(RouterConfig::default());
    router.send(message);
    println!("Source: <{}>", hex::encode(source.destination_hash()));
    println!("Recipient: <{}>", hex::encode(recipient));
    println!("Queued messages: {}", router.stats().pending_outbound);
    println!("Packed LXMF: {}", hex::encode(packed));
    Ok(())
}

/// Receiver counterpart. When passed a packed message it decodes and delivers
/// it through the same router callback used by network adapters.
pub fn receiver(packed_hex: Option<&str>) -> ExampleResult {
    let mut local = DeliveryIdentity::new(Identity::new(), Some("Anonymous Peer".into()), Some(8))?;
    println!(
        "Ready to receive on: <{}>",
        hex::encode(local.destination_hash())
    );
    println!(
        "Delivery announce packet: {} bytes",
        local.announce_packet(now())?.len()
    );

    let Some(packed_hex) = packed_hex else {
        return Ok(());
    };
    let message = LxMessage::unpack(&hex::decode(packed_hex)?)?;
    let mut router = LxmRouter::new(RouterConfig::default());
    router.register_delivery_callback(print_message);
    if !router.deliver_inbound(&message) {
        return Err("delivery callback was not invoked".into());
    }
    Ok(())
}

pub fn print_message(message: &LxMessage) {
    let signature = if message.signature_validated {
        "Validated"
    } else {
        match message.unverified_reason {
            Some(UnverifiedReason::SignatureInvalid) => "Invalid signature",
            Some(UnverifiedReason::SourceUnknown) => "Cannot verify, source is unknown",
            _ => "Not validated",
        }
    };
    println!("+--- LXMF Delivery ---------------------------------------------");
    println!(
        "| Source hash          : <{}>",
        hex::encode(message.source_hash)
    );
    println!(
        "| Destination hash     : <{}>",
        hex::encode(message.destination_hash)
    );
    println!("| Timestamp            : {:.3}", message.timestamp);
    println!("| Title                : {}", message.title);
    println!("| Content              : {}", message.content);
    println!("| Fields               : {:?}", message.fields);
    println!("| Message signature    : {signature}");
    println!("+---------------------------------------------------------------");
}

fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_receiver_wire_round_trip() {
        let source =
            DeliveryIdentity::new(Identity::new(), Some("Sender".into()), Some(8)).unwrap();
        let message = source
            .message([0x44; 16], "Test", "Round trip", DeliveryMethod::Direct)
            .unwrap();
        let packed = message.pack().unwrap();
        let received = LxMessage::unpack(&packed).unwrap();
        assert_eq!(received.title, "Test");
        assert_eq!(received.content, "Round trip");
        assert_eq!(received.source_hash, source.destination_hash());
    }
}
