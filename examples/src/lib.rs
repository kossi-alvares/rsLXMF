//! Networked counterparts to LXMF's Python sender and receiver examples.

use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use bytes::Bytes;
use lxmf_core::application::{DELIVERY_APP_NAME, DeliveryIdentity};
use lxmf_core::constants::{DeliveryMethod, UnverifiedReason};
use lxmf_core::message::LxMessage;
use rns_crypto::ed25519::Ed25519PublicKey;
use rns_identity::identity::Identity;
use rns_runtime::lifecycle::ShutdownSignal;
use rns_runtime::link_client::{LinkPayloadSendReceipt, LinkSession};
use rns_runtime::link_manager::LinkManager;
use rns_runtime::reticulum::{ReticulumHandle, init};
use rns_transport::messages::{
    OutboundRequest, TransportMessage, TransportQuery, TransportQueryResponse,
};
use tokio::sync::mpsc;

pub type ExampleResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

pub fn parse_destination_hash(value: &str) -> ExampleResult<[u8; 16]> {
    let bytes = hex::decode(value.trim())?;
    if bytes.len() != 16 {
        return Err("destination hash must be exactly 32 hexadecimal characters".into());
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&bytes);
    Ok(hash)
}

pub async fn start_reticulum(
    config_dir: Option<&str>,
) -> ExampleResult<(ReticulumHandle, ShutdownSignal)> {
    let shutdown = ShutdownSignal::new();
    let runtime = init(
        config_dir,
        None,
        shutdown.clone(),
        Arc::new(AtomicBool::new(true)),
    )
    .await?;
    Ok((runtime, shutdown))
}

pub async fn announce(runtime: &ReticulumHandle, identity: &mut DeliveryIdentity) -> ExampleResult {
    let destination_hash = identity.destination_hash();
    let raw = identity.announce_packet(now())?;
    runtime
        .transport_tx
        .send(TransportMessage::Outbound(OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash,
        }))
        .await?;
    Ok(())
}

pub async fn wait_for_destination(
    runtime: &ReticulumHandle,
    destination_hash: [u8; 16],
    timeout: Duration,
) -> ExampleResult<[u8; 64]> {
    if let Some(public_key) = recall_public_key(runtime, destination_hash).await {
        return Ok(public_key);
    }

    println!("Destination is not yet known. Requesting path and waiting for announce...");
    runtime
        .transport_tx
        .send(TransportMessage::RequestPath { destination_hash })
        .await?;
    let (reply, response) = tokio::sync::oneshot::channel();
    runtime
        .transport_tx
        .send(TransportMessage::AwaitPath {
            dest: destination_hash,
            reply,
        })
        .await?;
    if !tokio::time::timeout(timeout, response).await?? {
        return Err("destination path was not discovered before timeout".into());
    }
    recall_public_key(runtime, destination_hash)
        .await
        .ok_or_else(|| "destination announce did not contain a public key".into())
}

async fn recall_public_key(
    runtime: &ReticulumHandle,
    destination_hash: [u8; 16],
) -> Option<[u8; 64]> {
    match runtime
        .query_control(TransportQuery::Recall { destination_hash })
        .await
    {
        Some(TransportQueryResponse::Announce(Some(entry))) => entry.public_key,
        _ => None,
    }
}

pub async fn send_direct(
    runtime: &ReticulumHandle,
    source: &DeliveryIdentity,
    recipient: [u8; 16],
    recipient_public_key: [u8; 64],
    title: &str,
    content: &str,
) -> ExampleResult<LinkPayloadSendReceipt> {
    let message = source.message(recipient, title, content, DeliveryMethod::Direct)?;
    let payload = message.pack()?;
    let private_key = source
        .identity()
        .get_private_key()
        .ok_or("source identity has no private key")?;
    let link_identity = Identity::from_private_key(private_key.as_ref())?;
    let mut link = LinkSession::open_with_public_key(
        runtime,
        link_identity,
        recipient,
        recipient_public_key,
        1,
        Duration::from_secs(30),
    )
    .await?;
    link.identify().await?;
    let receipt = link
        .send_payload(payload, true, Duration::from_secs(120))
        .await?;
    link.close().await?;
    Ok(receipt)
}

pub async fn run_receiver(runtime: ReticulumHandle, mut local: DeliveryIdentity) -> ExampleResult {
    let destination_hash = local.destination_hash();
    let (delivery_tx, delivery_rx) = mpsc::channel(256);
    let (packet_tx, mut packet_rx) = mpsc::channel(256);
    let (resource_tx, mut resource_rx) = mpsc::channel(64);
    runtime
        .transport_tx
        .send(TransportMessage::RegisterDestination {
            hash: destination_hash,
            app_name: DELIVERY_APP_NAME.to_string(),
            delivery_tx: Some(delivery_tx),
        })
        .await?;

    let mut manager = LinkManager::with_destination(
        runtime.transport_tx.clone(),
        delivery_rx,
        local.identity(),
        DELIVERY_APP_NAME,
        local.identity().get_signing_key(),
    );
    manager.set_link_packet_channel(packet_tx);
    manager.set_resource_completed_channel(resource_tx);
    let manager_task = tokio::spawn(manager.run());

    announce(&runtime, &mut local).await?;
    println!("Ready to receive on: <{}>", hex::encode(destination_hash));
    println!("Announced lxmf.delivery destination");

    loop {
        let payload = tokio::select! {
            packet = packet_rx.recv() => packet.map(|(payload, _)| payload),
            resource = resource_rx.recv() => resource.map(|(payload, _)| payload),
            _ = runtime.shutdown.wait() => break,
        };
        let Some(payload) = payload else {
            break;
        };
        match decode_network_message(&runtime, &payload).await {
            Ok(message) => print_message(&message),
            Err(error) => eprintln!("Could not decode inbound LXMF message: {error}"),
        }
    }

    manager_task.abort();
    Ok(())
}

pub async fn decode_network_message(
    runtime: &ReticulumHandle,
    payload: &[u8],
) -> ExampleResult<LxMessage> {
    let mut message = LxMessage::unpack(payload)?;
    if let Some(public_key) = recall_public_key(runtime, message.source_hash).await {
        verify_message(&mut message, &public_key)?;
    } else {
        message.unverified_reason = Some(UnverifiedReason::SourceUnknown);
    }
    Ok(message)
}

pub fn verify_message(message: &mut LxMessage, public_key: &[u8; 64]) -> ExampleResult {
    let verify_key = Ed25519PublicKey::from_bytes(
        public_key[32..]
            .try_into()
            .map_err(|_| "invalid recalled signing key")?,
    )?;
    if !message.verify(&verify_key) {
        message.unverified_reason = Some(UnverifiedReason::SignatureInvalid);
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
    use rns_runtime::reticulum::InstanceMode;

    #[test]
    fn destination_hash_parser_matches_python_input_shape() {
        assert_eq!(
            parse_destination_hash("11111111111111111111111111111111").unwrap(),
            [0x11; 16]
        );
        assert!(parse_destination_hash("11").is_err());
    }

    async fn free_tcp_port_pair() -> (u16, u16) {
        let first = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        (
            first.local_addr().unwrap().port(),
            second.local_addr().unwrap().port(),
        )
    }

    #[tokio::test]
    async fn sender_and_receiver_exchange_signed_resource_over_shared_instance() {
        let (port, control_port) = free_tcp_port_pair().await;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("lxmf_examples_network_{nonce}"));
        let shared_dir = base.join("shared");
        let sender_dir = base.join("sender");
        let receiver_dir = base.join("receiver");
        for dir in [&shared_dir, &sender_dir, &receiver_dir] {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(
                dir.join("config"),
                format!(
                    "[reticulum]\nshare_instance = Yes\nshared_instance_type = tcp\n\
                     shared_instance_port = {port}\ninstance_control_port = {control_port}\n\
                     rpc_key = 4242424242424242424242424242424242424242424242424242424242424242\n\
                     enable_transport = No\n\n[interfaces]\n"
                ),
            )
            .unwrap();
        }

        let (shared, shared_shutdown) = start_reticulum(Some(shared_dir.to_str().unwrap()))
            .await
            .unwrap();
        let (sender_runtime, sender_shutdown) = start_reticulum(Some(sender_dir.to_str().unwrap()))
            .await
            .unwrap();
        let (receiver_runtime, receiver_shutdown) =
            start_reticulum(Some(receiver_dir.to_str().unwrap()))
                .await
                .unwrap();
        assert_eq!(shared.instance_mode, InstanceMode::Shared);
        assert_eq!(sender_runtime.instance_mode, InstanceMode::Client);
        assert_eq!(receiver_runtime.instance_mode, InstanceMode::Client);
        tokio::time::sleep(Duration::from_millis(200)).await;

        let mut receiver_identity =
            DeliveryIdentity::new(Identity::new(), Some("Anonymous Peer".into()), Some(8)).unwrap();
        let receiver_hash = receiver_identity.destination_hash();
        let (delivery_tx, delivery_rx) = mpsc::channel(64);
        let (packet_tx, mut packet_rx) = mpsc::channel(8);
        let (resource_tx, mut resource_rx) = mpsc::channel(8);
        receiver_runtime
            .transport_tx
            .send(TransportMessage::RegisterDestination {
                hash: receiver_hash,
                app_name: DELIVERY_APP_NAME.to_string(),
                delivery_tx: Some(delivery_tx),
            })
            .await
            .unwrap();
        let mut manager = LinkManager::with_destination(
            receiver_runtime.transport_tx.clone(),
            delivery_rx,
            receiver_identity.identity(),
            DELIVERY_APP_NAME,
            receiver_identity.identity().get_signing_key(),
        );
        manager.set_link_packet_channel(packet_tx);
        manager.set_resource_completed_channel(resource_tx);
        let manager_task = tokio::spawn(manager.run());
        announce(&receiver_runtime, &mut receiver_identity)
            .await
            .unwrap();

        let mut sender_identity =
            DeliveryIdentity::new(Identity::new(), Some("Rust Sender".into()), Some(8)).unwrap();
        announce(&sender_runtime, &mut sender_identity)
            .await
            .unwrap();
        let receiver_public_key = receiver_identity.identity().get_public_key();
        let content = "network resource payload ".repeat(100);
        let send = send_direct(
            &sender_runtime,
            &sender_identity,
            receiver_hash,
            receiver_public_key,
            "Hi there",
            &content,
        );
        let receive = async {
            tokio::select! {
                packet = packet_rx.recv() => ("packet", packet.unwrap().0),
                resource = resource_rx.recv() => ("resource", resource.unwrap().0),
            }
        };
        let (receipt, (delivery_kind, payload)) = tokio::join!(send, receive);
        assert!(matches!(
            receipt.unwrap(),
            LinkPayloadSendReceipt::Resource { .. }
        ));
        assert_eq!(delivery_kind, "resource");
        let mut message = LxMessage::unpack(&payload).unwrap();
        verify_message(&mut message, &sender_identity.identity().get_public_key()).unwrap();
        assert!(message.signature_validated);
        assert_eq!(message.destination_hash, receiver_hash);
        assert_eq!(message.source_hash, sender_identity.destination_hash());
        assert_eq!(message.title, "Hi there");
        assert_eq!(message.content, content);

        manager_task.abort();
        receiver_shutdown.trigger();
        sender_shutdown.trigger();
        shared_shutdown.trigger();
        tokio::time::sleep(Duration::from_millis(100)).await;
        std::fs::remove_dir_all(base).unwrap();
    }
}
