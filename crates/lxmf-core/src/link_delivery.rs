//! Link-based LXMF message delivery (Python's Direct delivery mode).
//!
//! Establishes a link to the recipient, identifies the sender, and transfers the message either
//! as a single encrypted link packet or as a Resource over the link. Enables larger-than-MDU
//! messages via resource segmentation, delivery confirmation via link-level proofs, and sender
//! identity verification via link identification.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::time::{Duration, Instant};

use rns_crypto::ed25519::Ed25519PrivateKey;
use rns_identity::identity::Identity;
use rns_link::constants::{ESTABLISHMENT_TIMEOUT_PER_HOP, KEEPALIVE_DEFAULT};
use rns_link::link::LinkState;
use rns_runtime::link_client::{LinkPayloadSendReceipt, LinkSession, LinkSessionHandle};
use rns_runtime::reticulum::ReticulumHandle;
use rns_transport::messages::TransportMessage;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot};

use crate::constants::DeliveryRepresentation;
use crate::message::LxMessage;
use crate::propagation::hex_encode;

/// Upstream LXMF keeps reusable Direct links open for ten minutes of data
/// inactivity before tearing them down (`LXMRouter.LINK_MAX_INACTIVITY`).
const LINK_MAX_INACTIVITY: Duration = Duration::from_secs(600);
const BACKCHANNEL_SEND_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
const BACKCHANNEL_DELIVERY_TIMEOUT: Duration = Duration::from_secs(360);

/// State of a link-based delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryState {
    Idle,
    Establishing,
    Identifying,
    Transferring,
    AwaitingProof,
    Complete,
    Rejected,
    Failed,
}

/// An in-progress link-based delivery.
pub struct PendingDelivery {
    pub message: LxMessage,
    pub dest_hash: [u8; 16],
    pub packed_override: Option<Vec<u8>>,
    pub auto_compress: bool,
    link: OutboundDeliveryLink,
    pub state: DeliveryState,
    pub started_at: Instant,
    runtime_result: Option<oneshot::Receiver<Result<LinkPayloadSendReceipt, String>>>,
    /// Link establishment timeout. This intentionally excludes keepalive time:
    /// an initiator that never receives LRPROOF should fail on the Link
    /// establishment clock, not on the active-link inactivity clock.
    pub establishment_timeout: Duration,
    /// Full delivery timeout after the link has moved beyond establishment.
    pub timeout: Duration,
    pub msg_hash: Option<[u8; 32]>,
    pub failure_reason: Option<String>,
    /// Keep successful Direct links open for additional messages. Propagation
    /// deposits currently keep the old one-shot behavior.
    pub reusable: bool,
    /// Upstream identifies the initiator after the first successful Direct
    /// delivery, making the link usable as a peer backchannel.
    pub backchannel_identified: bool,
    /// LXMF-owned scheduling state. Link establishment and transfer state stay
    /// outside this queue so it can be retained when the network backend is
    /// replaced by a runtime-owned `LinkSession`.
    queue: DirectDeliveryQueue,
}

enum OutboundDeliveryLink {
    Runtime {
        handle: LinkSessionHandle,
        state: LinkState,
    },
}

impl OutboundDeliveryLink {
    fn id(&self) -> [u8; 16] {
        match self {
            Self::Runtime { handle, .. } => handle.id(),
        }
    }

    fn state(&self) -> LinkState {
        match self {
            Self::Runtime { state, .. } => *state,
        }
    }

    fn set_state(&mut self, new_state: LinkState) {
        match self {
            Self::Runtime { state, .. } => *state = new_state,
        }
    }

    fn is_active(&self) -> bool {
        self.state() == LinkState::Active
    }

    fn runtime_handle(&self) -> Option<&LinkSessionHandle> {
        match self {
            Self::Runtime { handle, .. } => Some(handle),
        }
    }
}

/// Message payload waiting for an existing Direct link to become active/idle.
struct QueuedDelivery {
    message: LxMessage,
    packed_override: Option<Vec<u8>>,
    auto_compress: bool,
    msg_hash: Option<[u8; 32]>,
    queued_at: Instant,
}

/// FIFO policy for messages sharing one reusable Direct Link.
///
/// This type deliberately contains no Reticulum Link or Resource state.
#[derive(Default)]
struct DirectDeliveryQueue {
    pending: VecDeque<QueuedDelivery>,
}

impl DirectDeliveryQueue {
    fn len(&self) -> usize {
        self.pending.len()
    }

    fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    fn push(&mut self, delivery: QueuedDelivery) {
        self.pending.push_back(delivery);
    }

    fn pop(&mut self) -> Option<QueuedDelivery> {
        self.pending.pop_front()
    }

    fn iter(&self) -> impl Iterator<Item = &QueuedDelivery> {
        self.pending.iter()
    }

    fn position_by_hash(&self, msg_hash: [u8; 32]) -> Option<usize> {
        self.pending
            .iter()
            .position(|delivery| delivery.msg_hash == Some(msg_hash))
    }

    fn remove(&mut self, index: usize) -> Option<QueuedDelivery> {
        self.pending.remove(index)
    }

    fn drain(&mut self) -> impl Iterator<Item = QueuedDelivery> + '_ {
        self.pending.drain(..)
    }
}

impl QueuedDelivery {
    fn new(message: LxMessage, packed_override: Option<Vec<u8>>, auto_compress: bool) -> Self {
        let msg_hash = message.hash;
        Self {
            message,
            packed_override,
            auto_compress,
            msg_hash,
            queued_at: Instant::now(),
        }
    }
}

impl PendingDelivery {
    fn active_delivery_count(&self) -> usize {
        let current = if self.state == DeliveryState::Idle {
            0
        } else {
            1
        };
        current + self.queue.len()
    }

    fn queue_delivery(
        &mut self,
        message: LxMessage,
        packed_override: Option<Vec<u8>>,
        auto_compress: bool,
    ) {
        self.queue
            .push(QueuedDelivery::new(message, packed_override, auto_compress));
    }

    fn start_queued_delivery(&mut self) -> bool {
        let Some(next) = self.queue.pop() else {
            return false;
        };
        self.message = next.message;
        self.packed_override = next.packed_override;
        self.auto_compress = next.auto_compress;
        self.started_at = Instant::now();
        self.msg_hash = next.msg_hash;
        self.failure_reason = None;
        self.state = DeliveryState::Identifying;
        tracing::debug!(
            link_id = %hex_encode(&self.link.id()),
            dest = %hex_encode(&self.dest_hash),
            queued_for_secs = next.queued_at.elapsed().as_secs_f64(),
            remaining_queue = self.queue.len(),
            "starting queued Direct link delivery"
        );
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum BackchannelProofKey {
    Packet([u8; 16], [u8; 32]),
    Resource([u8; 16], [u8; 32]),
}

struct PendingBackchannelStart {
    receiver: oneshot::Receiver<Result<BackchannelSendReceipt, BackchannelSendError>>,
    message: LxMessage,
    dest_hash: [u8; 16],
    link_id: [u8; 16],
    requested_at: Instant,
}

struct PendingBackchannelDelivery {
    message: LxMessage,
    dest_hash: [u8; 16],
    link_id: [u8; 16],
    representation: DeliveryRepresentation,
    started_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkDeliveryStartError {
    #[cfg(test)]
    TransportFull,
    #[cfg(test)]
    TransportClosed,
    RuntimeUnavailable,
    RemoteIdentityUnavailable,
}

impl fmt::Display for LinkDeliveryStartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(test)]
            Self::TransportFull => f.write_str("transport full"),
            #[cfg(test)]
            Self::TransportClosed => f.write_str("transport closed"),
            Self::RuntimeUnavailable => {
                f.write_str("Reticulum runtime is required for Link delivery")
            }
            Self::RemoteIdentityUnavailable => {
                f.write_str("remote identity public key is required for Link delivery")
            }
        }
    }
}

impl std::error::Error for LinkDeliveryStartError {}

#[derive(Debug)]
pub struct LinkDeliveryStartFailure {
    pub error: LinkDeliveryStartError,
    pub message: Box<LxMessage>,
}

/// How a Direct delivery was attached to Link state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectLinkStartKind {
    /// A new outbound Direct LinkRequest was queued.
    NewDirect,
    /// An existing active Link accepted the message immediately.
    ReusedActiveDirect,
    /// The message was queued behind a pending or busy reusable Link.
    QueuedOnDirect,
}

/// Start result with enough detail for callers to surface upstream-like Direct
/// delivery stages without reimplementing LinkDeliveryManager policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectLinkStartReport {
    pub link_id: [u8; 16],
    pub dest_hash: [u8; 16],
    pub kind: DirectLinkStartKind,
    pub link_state: LinkState,
    pub delivery_state: DeliveryState,
    pub queued_deliveries: usize,
    pub in_flight_deliveries: usize,
}

/// A proof-tracked send over an already-authenticated inbound delivery Link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackchannelSendReceipt {
    Packet {
        link_id: [u8; 16],
        packet_hash: [u8; 32],
    },
    Resource {
        link_id: [u8; 16],
        resource_hash: [u8; 32],
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackchannelSendError {
    LinkNotFound,
    LinkNotActive,
    NoSessionKeys,
    TransportUnavailable,
    ResourceStartFailed,
    Other(String),
}

impl fmt::Display for BackchannelSendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LinkNotFound => f.write_str("link not found"),
            Self::LinkNotActive => f.write_str("link is not active"),
            Self::NoSessionKeys => f.write_str("link session keys are unavailable"),
            Self::TransportUnavailable => f.write_str("transport channel is full or closed"),
            Self::ResourceStartFailed => f.write_str("resource transfer could not be started"),
            Self::Other(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for BackchannelSendError {}

/// Whether a link-delivery failure should be treated like upstream LXMF's
/// closed/pending Link path, where the message remains eligible for Direct
/// rediscovery instead of being terminally failed.
pub fn is_retryable_link_delivery_failure(reason: &str) -> bool {
    matches!(
        reason,
        "link establishment timeout"
            | "link closed"
            | "transport full"
            | "transport closed"
            // Backchannel adapters discover these only after asking the
            // embedding runtime to send over an externally-owned inbound Link.
            // They are equivalent to Python seeing direct_link.status == CLOSED.
            | "link not found"
            | "link is not active"
            | "link session keys are unavailable"
            | "transport channel is full or closed"
            | "backchannel send command timeout"
            | "backchannel send command closed"
    )
}

/// Command bridge used by embedders to send an LXMF payload over an inbound
/// authenticated Link that is owned by their Reticulum runtime.
pub struct BackchannelSendCommand {
    pub link_id: [u8; 16],
    pub payload: Vec<u8>,
    pub auto_compress: bool,
    pub result_tx: oneshot::Sender<Result<BackchannelSendReceipt, BackchannelSendError>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackchannelStartError {
    NoBackchannel,
    SenderUnavailable,
    CommandFull,
    CommandClosed,
    PackFailed,
}

impl fmt::Display for BackchannelStartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoBackchannel => f.write_str("backchannel link not found"),
            Self::SenderUnavailable => f.write_str("backchannel sender unavailable"),
            Self::CommandFull => f.write_str("backchannel command channel full"),
            Self::CommandClosed => f.write_str("backchannel command channel closed"),
            Self::PackFailed => f.write_str("failed to pack LXMF payload"),
        }
    }
}

impl std::error::Error for BackchannelStartError {}

#[derive(Debug)]
pub struct BackchannelStartFailure {
    pub error: BackchannelStartError,
    pub message: Box<LxMessage>,
}

impl fmt::Display for BackchannelStartFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for BackchannelStartFailure {}

/// Start result for a reusable inbound backchannel Link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackchannelStartReport {
    pub link_id: [u8; 16],
    pub dest_hash: [u8; 16],
    pub queued_deliveries: usize,
    pub in_flight_deliveries: usize,
}

/// Which link-delivery path emitted an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LxmfDeliveryEventMethod {
    Direct,
    PropagationDeposit,
}

/// Semantic delivery stages surfaced by [`LinkDeliveryManager`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LxmfDeliveryEventKind {
    LinkEstablishing,
    LinkEstablished,
    DirectLinkPending,
    DirectLinkReused,
    BackchannelLinkReused,
    TransferStarted,
    TransferProgress,
    AwaitingProof,
    Delivered,
    Rejected,
    Failed,
}

/// Upstream-like delivery progress event for embedders and UI adapters.
#[derive(Debug, Clone, PartialEq)]
pub struct LxmfDeliveryEvent {
    pub kind: LxmfDeliveryEventKind,
    pub method: LxmfDeliveryEventMethod,
    pub link_id: [u8; 16],
    pub dest_hash: [u8; 16],
    pub msg_hash: Option<[u8; 32]>,
    pub attempts: u32,
    pub progress: Option<f64>,
    pub representation: DeliveryRepresentation,
    pub link_state: LinkState,
    pub delivery_state: DeliveryState,
    pub queued_deliveries: usize,
    pub in_flight_deliveries: usize,
    pub reason: Option<String>,
}

/// Snapshot of a reusable Direct Link session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectLinkSnapshot {
    pub link_id: [u8; 16],
    pub dest_hash: [u8; 16],
    pub link_state: LinkState,
    pub delivery_state: DeliveryState,
    pub idle_expired: bool,
    pub queued_deliveries: usize,
    pub in_flight_deliveries: usize,
}

/// Snapshot of a message currently owned by link delivery.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MessageDeliverySnapshot {
    pub link_id: [u8; 16],
    pub dest_hash: [u8; 16],
    pub link_state: LinkState,
    pub delivery_state: DeliveryState,
    pub representation: DeliveryRepresentation,
    pub progress: f64,
    pub queued: bool,
    pub queued_deliveries: usize,
    pub in_flight_deliveries: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackchannelLinkSnapshot {
    pub link_id: [u8; 16],
    pub dest_hash: [u8; 16],
    pub queued_deliveries: usize,
    pub in_flight_deliveries: usize,
}

/// Aggregate LinkDeliveryManager state for diagnostics and UI event mapping.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinkDeliveryStats {
    pub sessions: usize,
    pub direct_sessions: usize,
    pub one_shot_sessions: usize,
    pub backchannel_sessions: usize,
    pub establishing_direct_sessions: usize,
    pub active_direct_sessions: usize,
    pub idle_direct_sessions: usize,
    pub queued_deliveries: usize,
    pub in_flight_deliveries: usize,
    pub pending_backchannel_starts: usize,
    pub pending_backchannel_deliveries: usize,
}

impl fmt::Display for LinkDeliveryStartFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for LinkDeliveryStartFailure {}

fn spawn_runtime_payload_send(
    handle: LinkSessionHandle,
    payload: Vec<u8>,
    auto_compress: bool,
    deadline: Duration,
    identify_before_send: bool,
) -> oneshot::Receiver<Result<LinkPayloadSendReceipt, String>> {
    let (result_tx, result_rx) = oneshot::channel();
    tokio::spawn(async move {
        if identify_before_send && let Err(error) = handle.identify().await {
            let _ = result_tx.send(Err(error.to_string()));
            return;
        }
        let result = handle
            .send_payload(payload, auto_compress, deadline)
            .await
            .map_err(|error| error.to_string());
        if result.is_ok() && !identify_before_send {
            let _ = handle.identify().await;
        }
        let _ = result_tx.send(result);
    });
    result_rx
}

fn launch_runtime_current_delivery(delivery: &mut PendingDelivery) -> Result<(), String> {
    let handle = delivery
        .link
        .runtime_handle()
        .cloned()
        .ok_or_else(|| "runtime Link session unavailable".to_string())?;
    let payload = delivery
        .packed_override
        .clone()
        .map(Ok)
        .unwrap_or_else(|| delivery.message.pack())
        .map_err(|error| format!("failed to pack LXMF payload: {error:?}"))?;
    let auto_compress = if delivery.packed_override.is_some() {
        delivery.auto_compress
    } else {
        delivery.message.auto_compress
    };
    delivery.runtime_result = Some(spawn_runtime_payload_send(
        handle,
        payload,
        auto_compress,
        delivery.timeout,
        false,
    ));
    delivery.state = DeliveryState::Transferring;
    delivery.started_at = Instant::now();
    delivery.message.progress = delivery.message.progress.max(0.05);
    Ok(())
}

/// Driver for outbound link-based LXMF deliveries.
///
/// Callers invoke [`Self::start_delivery`] to begin, [`Self::drain_events`] to route inbound
/// packets, and [`Self::tick`] periodically to advance transfers and enforce timeouts.
pub struct LinkDeliveryManager {
    transport_tx: mpsc::Sender<TransportMessage>,
    runtime: Option<ReticulumHandle>,
    runtime_identity: Option<Identity>,
    known_identities: HashMap<String, [u8; 64]>,
    /// Reusable upstream-style Direct links keyed by LXMF delivery destination hash.
    direct_links: HashMap<[u8; 16], [u8; 16]>,
    /// Reusable upstream-style inbound backchannels keyed by remote LXMF delivery destination hash.
    backchannel_links: HashMap<[u8; 16], [u8; 16]>,
    pending: HashMap<[u8; 16], PendingDelivery>,
    backchannel_tx: Option<mpsc::Sender<BackchannelSendCommand>>,
    inbound_packet_tx: Option<mpsc::Sender<(Vec<u8>, [u8; 16])>>,
    pending_backchannel_starts: Vec<PendingBackchannelStart>,
    pending_backchannel_deliveries: HashMap<BackchannelProofKey, PendingBackchannelDelivery>,
    delivery_events: VecDeque<LxmfDeliveryEvent>,
}

impl LinkDeliveryManager {
    pub fn new(
        transport_tx: mpsc::Sender<TransportMessage>,
        identity_pub: Option<[u8; 64]>,
        identity_key: Option<Ed25519PrivateKey>,
    ) -> Self {
        let _ = (identity_pub, identity_key);
        Self {
            transport_tx,
            runtime: None,
            runtime_identity: None,
            known_identities: HashMap::new(),
            direct_links: HashMap::new(),
            backchannel_links: HashMap::new(),
            pending: HashMap::new(),
            backchannel_tx: None,
            inbound_packet_tx: None,
            pending_backchannel_starts: Vec::new(),
            pending_backchannel_deliveries: HashMap::new(),
            delivery_events: VecDeque::new(),
        }
    }

    /// Use runtime-owned reusable Link sessions for new Direct deliveries.
    pub fn set_runtime(&mut self, runtime: ReticulumHandle, identity: Identity) {
        self.runtime = Some(runtime);
        self.runtime_identity = Some(identity);
    }

    /// Install the adapter used to send LXMF payloads over inbound
    /// authenticated backchannel Links owned by the embedding runtime.
    pub fn set_backchannel_sender(&mut self, tx: mpsc::Sender<BackchannelSendCommand>) {
        self.backchannel_tx = Some(tx);
    }

    /// Install the adapter used to deliver inbound LXMF payloads that arrive
    /// over outbound reusable Direct links. This is required for peer
    /// backchannels: the outbound Direct manager owns the link_id destination,
    /// so ordinary link DATA replies route back here rather than to the
    /// responder-side LinkManager.
    pub fn set_inbound_packet_sender(&mut self, tx: mpsc::Sender<(Vec<u8>, [u8; 16])>) {
        self.inbound_packet_tx = Some(tx);
    }

    /// Register an inbound authenticated Link as a reusable backchannel for a
    /// remote LXMF delivery destination.
    pub fn register_backchannel(&mut self, dest_hash: [u8; 16], link_id: [u8; 16]) {
        self.backchannel_links.insert(dest_hash, link_id);
        tracing::info!(
            link_id = %hex_encode(&link_id),
            dest = %hex_encode(&dest_hash),
            "registered LXMF delivery backchannel"
        );
    }

    pub fn remove_backchannel(&mut self, dest_hash: &[u8; 16]) -> Option<[u8; 16]> {
        self.backchannel_links.remove(dest_hash)
    }

    /// Remove cached backchannel state for a closed Link and fail any
    /// in-flight backchannel sends that were using it.
    pub fn fail_backchannel_link(
        &mut self,
        link_id: [u8; 16],
        reason: &str,
    ) -> Vec<DeliveryResult> {
        let mut results = Vec::new();
        let removed_destinations: Vec<_> = self
            .backchannel_links
            .iter()
            .filter_map(|(dest_hash, cached_link)| (*cached_link == link_id).then_some(*dest_hash))
            .collect();
        for dest_hash in &removed_destinations {
            self.backchannel_links.remove(dest_hash);
        }

        let starts = std::mem::take(&mut self.pending_backchannel_starts);
        for start in starts {
            if start.link_id == link_id {
                results.push(fail_backchannel_start(
                    &mut self.delivery_events,
                    start,
                    reason.to_string(),
                ));
            } else {
                self.pending_backchannel_starts.push(start);
            }
        }

        let delivery_keys: Vec<_> = self
            .pending_backchannel_deliveries
            .iter()
            .filter_map(|(key, delivery)| (delivery.link_id == link_id).then_some(*key))
            .collect();
        for key in delivery_keys {
            if let Some(delivery) = self.pending_backchannel_deliveries.remove(&key) {
                self.delivery_events.push_back(backchannel_delivery_event(
                    BackchannelDeliveryEventInput {
                        kind: LxmfDeliveryEventKind::Failed,
                        message: &delivery.message,
                        dest_hash: delivery.dest_hash,
                        link_id: delivery.link_id,
                        representation: delivery.representation,
                        progress: Some(delivery.message.progress),
                        reason: Some(reason.to_string()),
                        link_state: LinkState::Closed,
                        delivery_state: DeliveryState::Failed,
                    },
                ));
                results.push(DeliveryResult::Failed {
                    link_id: delivery.link_id,
                    msg_hash: delivery.message.hash,
                    dest_hash: delivery.dest_hash,
                    message: delivery.message,
                    reason: reason.to_string(),
                });
            }
        }

        if !removed_destinations.is_empty() || !results.is_empty() {
            tracing::debug!(
                link_id = %hex_encode(&link_id),
                removed_backchannels = removed_destinations.len(),
                failed_deliveries = results.len(),
                reason,
                "removed closed LXMF backchannel Link"
            );
        }

        results
    }

    /// Start a direct delivery and return the tracking `link_id`.
    pub fn start_delivery(
        &mut self,
        message: LxMessage,
        dest_hash: [u8; 16],
        hops: u8,
    ) -> Result<[u8; 16], LinkDeliveryStartFailure> {
        self.start_delivery_with_report(message, dest_hash, hops)
            .map(|report| report.link_id)
    }

    /// Start a Direct delivery and return whether it created, reused, or queued
    /// on reusable Link state.
    pub fn start_delivery_with_report(
        &mut self,
        message: LxMessage,
        dest_hash: [u8; 16],
        hops: u8,
    ) -> Result<DirectLinkStartReport, LinkDeliveryStartFailure> {
        self.start_direct_delivery(message, dest_hash, hops)
    }

    /// Start a link delivery with an already-packed payload.
    ///
    /// This is used for LXMF propagation deposits, whose link payload is the
    /// propagation wrapper rather than the regular signed LXMF representation.
    pub fn start_packed_delivery(
        &mut self,
        message: LxMessage,
        dest_hash: [u8; 16],
        hops: u8,
        packed_payload: Vec<u8>,
        auto_compress: bool,
    ) -> Result<[u8; 16], LinkDeliveryStartFailure> {
        if let (Some(runtime), Some(identity), Some(public_key)) = (
            self.runtime.as_ref(),
            self.runtime_identity.as_ref(),
            self.known_identities.get(&hex_encode(&dest_hash)),
        ) {
            let establishment_timeout_secs = ESTABLISHMENT_TIMEOUT_PER_HOP * (hops.max(1) as f64);
            let timeout = Duration::from_secs_f64(establishment_timeout_secs + KEEPALIVE_DEFAULT);
            let prepared = LinkSession::prepare_with_public_key(
                runtime,
                identity.clone(),
                dest_hash,
                *public_key,
                hops,
            );
            let link_id = prepared.id();
            let handle = prepared.spawn(Duration::from_secs_f64(establishment_timeout_secs));
            let runtime_result = spawn_runtime_payload_send(
                handle.clone(),
                packed_payload,
                auto_compress,
                timeout,
                true,
            );
            let msg_hash = message.hash;
            self.pending.insert(
                link_id,
                PendingDelivery {
                    message,
                    dest_hash,
                    packed_override: None,
                    auto_compress,
                    link: OutboundDeliveryLink::Runtime {
                        handle,
                        state: LinkState::Pending,
                    },
                    state: DeliveryState::Establishing,
                    started_at: Instant::now(),
                    runtime_result: Some(runtime_result),
                    establishment_timeout: Duration::from_secs_f64(establishment_timeout_secs),
                    timeout,
                    msg_hash,
                    failure_reason: None,
                    reusable: false,
                    backchannel_identified: true,
                    queue: DirectDeliveryQueue::default(),
                },
            );
            return Ok(link_id);
        }

        Err(LinkDeliveryStartFailure {
            error: if self.runtime.is_none() || self.runtime_identity.is_none() {
                LinkDeliveryStartError::RuntimeUnavailable
            } else {
                LinkDeliveryStartError::RemoteIdentityUnavailable
            },
            message: Box::new(message),
        })
    }

    /// Start a Direct delivery over a registered inbound backchannel Link.
    pub fn start_backchannel_delivery(
        &mut self,
        message: LxMessage,
        dest_hash: [u8; 16],
    ) -> Result<BackchannelStartReport, BackchannelStartFailure> {
        let Some(link_id) = self.backchannel_links.get(&dest_hash).copied() else {
            return Err(BackchannelStartFailure {
                error: BackchannelStartError::NoBackchannel,
                message: Box::new(message),
            });
        };
        let Some(command_tx) = self.backchannel_tx.as_ref() else {
            return Err(BackchannelStartFailure {
                error: BackchannelStartError::SenderUnavailable,
                message: Box::new(message),
            });
        };

        let payload = match message.pack() {
            Ok(payload) => payload,
            Err(error) => {
                tracing::warn!(
                    dest = %hex_encode(&dest_hash),
                    error = ?error,
                    "failed to pack LXMF for backchannel delivery"
                );
                return Err(BackchannelStartFailure {
                    error: BackchannelStartError::PackFailed,
                    message: Box::new(message),
                });
            }
        };
        let auto_compress = message.auto_compress;
        let msg_hash = message.hash;
        let attempts = message.delivery_attempts;
        let (result_tx, result_rx) = oneshot::channel();
        let command = BackchannelSendCommand {
            link_id,
            payload,
            auto_compress,
            result_tx,
        };

        match command_tx.try_send(command) {
            Ok(()) => {
                tracing::info!(
                    link_id = %hex_encode(&link_id),
                    dest = %hex_encode(&dest_hash),
                    "routing Direct LXMF message over authenticated backchannel Link"
                );
                self.delivery_events.push_back(LxmfDeliveryEvent {
                    kind: LxmfDeliveryEventKind::BackchannelLinkReused,
                    method: LxmfDeliveryEventMethod::Direct,
                    link_id,
                    dest_hash,
                    msg_hash,
                    attempts,
                    progress: Some(0.05),
                    representation: DeliveryRepresentation::Unknown,
                    link_state: LinkState::Active,
                    delivery_state: DeliveryState::Transferring,
                    queued_deliveries: self.pending_backchannel_starts.len(),
                    in_flight_deliveries: self.pending_backchannel_deliveries.len() + 1,
                    reason: None,
                });
                self.pending_backchannel_starts
                    .push(PendingBackchannelStart {
                        receiver: result_rx,
                        message,
                        dest_hash,
                        link_id,
                        requested_at: Instant::now(),
                    });
                Ok(BackchannelStartReport {
                    link_id,
                    dest_hash,
                    queued_deliveries: self.pending_backchannel_starts.len(),
                    in_flight_deliveries: self.pending_backchannel_deliveries.len() + 1,
                })
            }
            Err(err) => {
                self.backchannel_links.remove(&dest_hash);
                let error = match err {
                    TrySendError::Full(_) => BackchannelStartError::CommandFull,
                    TrySendError::Closed(_) => BackchannelStartError::CommandClosed,
                };
                tracing::warn!(
                    link_id = %hex_encode(&link_id),
                    dest = %hex_encode(&dest_hash),
                    error = %error,
                    "failed to queue LXMF backchannel send command"
                );
                Err(BackchannelStartFailure {
                    error,
                    message: Box::new(message),
                })
            }
        }
    }

    fn start_direct_delivery(
        &mut self,
        message: LxMessage,
        dest_hash: [u8; 16],
        hops: u8,
    ) -> Result<DirectLinkStartReport, LinkDeliveryStartFailure> {
        if let Some(link_id) = self.direct_links.get(&dest_hash).copied() {
            let idle_expired = self
                .pending
                .get(&link_id)
                .is_some_and(|delivery| delivery.reusable && direct_link_idle_expired(delivery));
            if idle_expired {
                tracing::debug!(
                    link_id = %hex_encode(&link_id),
                    dest = %hex_encode(&dest_hash),
                    "discarding inactive cached Direct link before reuse"
                );
                if let Some(mut delivery) = self.pending.remove(&link_id) {
                    close_outbound_delivery_link(&self.transport_tx, &link_id, &mut delivery.link);
                    let _ = self
                        .transport_tx
                        .try_send(TransportMessage::DeregisterDestination { hash: link_id });
                }
                self.direct_links.remove(&dest_hash);
            } else if let Some(delivery) = self.pending.get_mut(&link_id)
                && delivery.reusable
            {
                let msg_hash = message.hash;
                let attempts = message.delivery_attempts;
                let state = delivery.state;
                let link_state = delivery.link.state();
                let kind = if state == DeliveryState::Idle && delivery.link.is_active() {
                    delivery.queue_delivery(message, None, true);
                    let _ = delivery.start_queued_delivery();
                    DirectLinkStartKind::ReusedActiveDirect
                } else {
                    delivery.queue_delivery(message, None, true);
                    DirectLinkStartKind::QueuedOnDirect
                };
                tracing::debug!(
                    link_id = %hex_encode(&link_id),
                    dest = %hex_encode(&dest_hash),
                    state = ?state,
                    link_state = ?link_state,
                    queued = delivery.queue.len(),
                    pending_count = delivery.active_delivery_count(),
                    "reusing cached Direct link delivery session"
                );
                let report = DirectLinkStartReport {
                    link_id,
                    dest_hash,
                    kind,
                    link_state,
                    delivery_state: delivery.state,
                    queued_deliveries: delivery.queue.len(),
                    in_flight_deliveries: usize::from(delivery.state != DeliveryState::Idle),
                };
                self.delivery_events.push_back(LxmfDeliveryEvent {
                    kind: match kind {
                        DirectLinkStartKind::ReusedActiveDirect => {
                            LxmfDeliveryEventKind::DirectLinkReused
                        }
                        DirectLinkStartKind::QueuedOnDirect => {
                            LxmfDeliveryEventKind::DirectLinkPending
                        }
                        DirectLinkStartKind::NewDirect => LxmfDeliveryEventKind::LinkEstablishing,
                    },
                    method: LxmfDeliveryEventMethod::Direct,
                    link_id,
                    dest_hash,
                    msg_hash,
                    attempts,
                    progress: Some(if link_state == LinkState::Active {
                        0.05
                    } else {
                        0.03
                    }),
                    representation: DeliveryRepresentation::Unknown,
                    link_state: report.link_state,
                    delivery_state: report.delivery_state,
                    queued_deliveries: report.queued_deliveries,
                    in_flight_deliveries: report.in_flight_deliveries,
                    reason: None,
                });
                return Ok(report);
            } else {
                self.direct_links.remove(&dest_hash);
            }
        }

        let msg_hash = message.hash;
        let attempts = message.delivery_attempts;
        if let (Some(runtime), Some(identity), Some(public_key)) = (
            self.runtime.as_ref(),
            self.runtime_identity.as_ref(),
            self.known_identities.get(&hex_encode(&dest_hash)),
        ) && let Ok(packed) = message.pack()
        {
            let establishment_timeout_secs = ESTABLISHMENT_TIMEOUT_PER_HOP * (hops.max(1) as f64);
            let timeout = Duration::from_secs_f64(establishment_timeout_secs + KEEPALIVE_DEFAULT);
            let prepared = LinkSession::prepare_with_public_key(
                runtime,
                identity.clone(),
                dest_hash,
                *public_key,
                hops,
            );
            let link_id = prepared.id();
            let handle = prepared.spawn(Duration::from_secs_f64(establishment_timeout_secs));
            if let Some(inbound_tx) = self.inbound_packet_tx.clone() {
                let inbound_handle = handle.clone();
                tokio::spawn(async move {
                    while let Ok(payload) = inbound_handle.recv().await {
                        if inbound_tx.send((payload, link_id)).await.is_err() {
                            break;
                        }
                    }
                });
            }
            let runtime_result = spawn_runtime_payload_send(
                handle.clone(),
                packed,
                message.auto_compress,
                timeout,
                false,
            );
            self.pending.insert(
                link_id,
                PendingDelivery {
                    message,
                    dest_hash,
                    packed_override: None,
                    auto_compress: true,
                    link: OutboundDeliveryLink::Runtime {
                        handle,
                        state: LinkState::Pending,
                    },
                    state: DeliveryState::Establishing,
                    started_at: Instant::now(),
                    runtime_result: Some(runtime_result),
                    establishment_timeout: Duration::from_secs_f64(establishment_timeout_secs),
                    timeout,
                    msg_hash,
                    failure_reason: None,
                    reusable: true,
                    backchannel_identified: false,
                    queue: DirectDeliveryQueue::default(),
                },
            );
            self.direct_links.insert(dest_hash, link_id);
            let report = DirectLinkStartReport {
                link_id,
                dest_hash,
                kind: DirectLinkStartKind::NewDirect,
                link_state: LinkState::Pending,
                delivery_state: DeliveryState::Establishing,
                queued_deliveries: 0,
                in_flight_deliveries: 1,
            };
            self.delivery_events.push_back(LxmfDeliveryEvent {
                kind: LxmfDeliveryEventKind::LinkEstablishing,
                method: LxmfDeliveryEventMethod::Direct,
                link_id,
                dest_hash,
                msg_hash,
                attempts,
                progress: Some(0.03),
                representation: DeliveryRepresentation::Unknown,
                link_state: report.link_state,
                delivery_state: report.delivery_state,
                queued_deliveries: 0,
                in_flight_deliveries: 1,
                reason: None,
            });
            return Ok(report);
        }

        Err(LinkDeliveryStartFailure {
            error: if self.runtime.is_none() || self.runtime_identity.is_none() {
                LinkDeliveryStartError::RuntimeUnavailable
            } else {
                LinkDeliveryStartError::RemoteIdentityUnavailable
            },
            message: Box::new(message),
        })
    }

    /// Refresh destination public keys used when opening runtime-owned links.
    pub fn drain_events(&mut self, known_identities: &HashMap<String, [u8; 64]>) {
        self.known_identities.clone_from(known_identities);
        #[cfg(any())]
        {
            let mut events = Vec::new();
            while let Ok(event) = self.event_rx.try_recv() {
                events.push(event);
            }

            for event in events {
                match event {
                    DestinationEvent::LinkClosed { link_id } => {
                        self.handle_link_closed(&link_id, None);
                    }
                    DestinationEvent::InboundPacket { raw, .. } => {
                        let (header, data_offset) =
                            match rns_wire::header::PacketHeader::unpack(&raw) {
                                Ok(h) => h,
                                Err(_) => continue,
                            };
                        let data = if raw.len() > data_offset {
                            &raw[data_offset..]
                        } else {
                            &[]
                        };
                        let link_id = header.destination_hash;

                        match header.context {
                            rns_wire::context::PacketContext::Lrproof
                                if header.flags.packet_type
                                    == rns_wire::flags::PacketType::Proof =>
                            {
                                let dest_hex =
                                    self.pending.get(&link_id).map(|d| hex_encode(&d.dest_hash));

                                if let Some(dest_hex) = dest_hex {
                                    if let Some(pub_key) = known_identities.get(&dest_hex) {
                                        let ed25519_bytes: [u8; 32] = pub_key[32..64]
                                        .try_into()
                                        .expect("known_identities values are [u8; 64]; slice [32..64] is always 32 bytes");
                                        if let Ok(verify_key) =
                                            Ed25519PublicKey::from_bytes(&ed25519_bytes)
                                        {
                                            self.handle_link_proof(
                                                &link_id,
                                                data,
                                                &verify_key,
                                                &ed25519_bytes,
                                            );
                                        }
                                    } else {
                                        tracing::warn!(
                                            link_id = %hex_encode(&link_id),
                                            dest = %dest_hex,
                                            "LRPROOF received but destination identity key is not cached; ignoring proof"
                                        );
                                    }
                                }
                            }
                            rns_wire::context::PacketContext::None
                                if header.flags.packet_type
                                    == rns_wire::flags::PacketType::Proof =>
                            {
                                // Python `Link.prove_packet()` sends packet proofs on a LINK
                                // destination with PROOF type and the default/None context. LRPROOF
                                // handling also accepts None on some older paths, so disambiguate by
                                // the delivery state.
                                if self
                                    .pending
                                    .get(&link_id)
                                    .is_some_and(|d| d.state == DeliveryState::AwaitingProof)
                                {
                                    self.handle_link_packet_proof(&link_id, data);
                                } else {
                                    let dest_hex = self
                                        .pending
                                        .get(&link_id)
                                        .map(|d| hex_encode(&d.dest_hash));

                                    if let Some(dest_hex) = dest_hex {
                                        if let Some(pub_key) = known_identities.get(&dest_hex) {
                                            let ed25519_bytes: [u8; 32] = pub_key[32..64]
                                            .try_into()
                                            .expect("known_identities values are [u8; 64]; slice [32..64] is always 32 bytes");
                                            if let Ok(verify_key) =
                                                Ed25519PublicKey::from_bytes(&ed25519_bytes)
                                            {
                                                self.handle_link_proof(
                                                    &link_id,
                                                    data,
                                                    &verify_key,
                                                    &ed25519_bytes,
                                                );
                                            }
                                        } else {
                                            tracing::warn!(
                                                link_id = %hex_encode(&link_id),
                                                dest = %dest_hex,
                                                "LRPROOF received but destination identity key is not cached; ignoring proof"
                                            );
                                        }
                                    }
                                }
                            }
                            rns_wire::context::PacketContext::LinkProof
                                if header.flags.packet_type
                                    == rns_wire::flags::PacketType::Proof =>
                            {
                                self.handle_link_packet_proof(&link_id, data);
                            }
                            rns_wire::context::PacketContext::None
                                if header.flags.packet_type
                                    == rns_wire::flags::PacketType::Data =>
                            {
                                self.handle_inbound_link_packet(
                                    &link_id,
                                    &raw,
                                    header.flags.header_type,
                                    data,
                                );
                            }
                            rns_wire::context::PacketContext::ResourceHmu => {
                                let plaintext = self
                                    .pending
                                    .get(&link_id)
                                    .and_then(|d| d.link.decrypt(data).ok());
                                if let Some(pt) = plaintext {
                                    self.handle_hmu(&link_id, &pt);
                                }
                            }
                            rns_wire::context::PacketContext::ResourceReq => {
                                // Python `Resource.request_next` may arrive before any HMU and be the
                                // only signal to advance the transfer, so drive it here directly.
                                let plaintext = self
                                    .pending
                                    .get(&link_id)
                                    .and_then(|d| d.link.decrypt(data).ok());
                                if let Some(pt) = plaintext {
                                    self.handle_request(&link_id, &pt);
                                }
                            }
                            rns_wire::context::PacketContext::ResourcePrf => {
                                // PROOF+RESOURCE_PRF is plaintext on a Proof packet (Packet.py:195-197).
                                // Body = resource_hash(32) || proof(32); pass through without decrypt.
                                self.handle_resource_proof(&link_id, data);
                            }
                            rns_wire::context::PacketContext::ResourceRcl => {
                                // Receiver-cancel/reject packets are link-encrypted and carry
                                // the rejected resource_hash.
                                let plaintext = self
                                    .pending
                                    .get(&link_id)
                                    .and_then(|d| d.link.decrypt(data).ok());
                                if let Some(pt) = plaintext {
                                    self.handle_resource_reject(&link_id, &pt);
                                }
                            }
                            rns_wire::context::PacketContext::Keepalive => {
                                if let Some(delivery) = self.pending.get_mut(&link_id) {
                                    delivery.link.record_inbound();
                                }
                            }
                            rns_wire::context::PacketContext::LinkClose => {
                                self.handle_link_closed(&link_id, Some(data));
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Validate an inbound `LRPROOF`, complete the handshake, and transition to
    /// [`DeliveryState::Identifying`].
    #[cfg(any())]
    fn handle_link_proof(
        &mut self,
        link_id: &[u8; 16],
        proof_data: &[u8],
        identity_verify_key: &Ed25519PublicKey,
        identity_ed25519_pub: &[u8; 32],
    ) -> bool {
        let Some(delivery) = self.pending.get_mut(link_id) else {
            return false;
        };

        if delivery.state != DeliveryState::Establishing {
            return false;
        }

        match delivery
            .link
            .validate_proof(proof_data, identity_verify_key, identity_ed25519_pub)
        {
            Ok(rtt_data) => {
                // Message 3 of the handshake: RTT.
                let rtt_flags = rns_wire::flags::PacketFlags {
                    header_type: rns_wire::flags::HeaderType::Header1,
                    context_flag: false,
                    transport_type: rns_wire::flags::TransportType::Broadcast,
                    destination_type: rns_wire::flags::DestinationType::Link,
                    packet_type: rns_wire::flags::PacketType::Data,
                };
                let rtt_header = rns_wire::header::PacketHeader {
                    flags: rtt_flags,
                    hops: 0,
                    transport_id: None,
                    destination_hash: *link_id,
                    context: rns_wire::context::PacketContext::Lrrtt,
                };
                let mut rtt_raw = rtt_header.pack();
                rtt_raw.extend_from_slice(&rtt_data);

                let _ = self
                    .transport_tx
                    .try_send(TransportMessage::Outbound(OutboundRequest {
                        raw: Bytes::from(rtt_raw),
                        destination_hash: *link_id,
                    }));

                delivery.state = DeliveryState::Identifying;
                true
            }
            Err(e) => {
                let _ = e;
                delivery.state = DeliveryState::Failed;
                delivery.failure_reason = Some("link proof validation failed".to_string());
                false
            }
        }
    }

    #[cfg(any())]
    fn handle_inbound_link_packet(
        &mut self,
        link_id: &[u8; 16],
        raw: &[u8],
        header_type: rns_wire::flags::HeaderType,
        encrypted_data: &[u8],
    ) -> bool {
        let Some(delivery) = self.pending.get_mut(link_id) else {
            return false;
        };
        if !delivery.reusable || !delivery.link.is_active() {
            return false;
        }

        delivery.link.record_inbound();
        delivery.link.record_rx(encrypted_data.len());
        let Ok(plaintext) = delivery.link.decrypt(encrypted_data) else {
            return false;
        };

        if let Some(ref tx) = self.inbound_packet_tx {
            let _ = tx.try_send((plaintext, *link_id));
        }

        let packet_hash = rns_wire::hash::packet_hash(raw, header_type);
        if let Ok(proof_data) = delivery.link.prove_packet_with_link_key(&packet_hash) {
            let proof_header = rns_wire::header::PacketHeader {
                flags: rns_wire::flags::PacketFlags {
                    header_type: rns_wire::flags::HeaderType::Header1,
                    context_flag: false,
                    transport_type: rns_wire::flags::TransportType::Broadcast,
                    destination_type: rns_wire::flags::DestinationType::Link,
                    packet_type: rns_wire::flags::PacketType::Proof,
                },
                hops: 0,
                transport_id: None,
                destination_hash: *link_id,
                context: rns_wire::context::PacketContext::LinkProof,
            };
            let mut proof_raw = proof_header.pack();
            proof_raw.extend_from_slice(&proof_data);
            let _ = self
                .transport_tx
                .try_send(TransportMessage::Outbound(OutboundRequest {
                    raw: Bytes::from(proof_raw),
                    destination_hash: *link_id,
                }));
        }

        true
    }

    /// Drive pending deliveries forward; call periodically after [`Self::drain_events`].
    pub fn tick(&mut self) -> Vec<DeliveryResult> {
        let mut results = self.tick_backchannels();
        let mut to_remove = Vec::new();

        for (link_id, delivery) in &mut self.pending {
            let mut remove_session = false;

            if delivery.link.runtime_handle().is_some() {
                if delivery.state == DeliveryState::Idle
                    && !delivery.queue.is_empty()
                    && delivery.start_queued_delivery()
                    && let Err(reason) = launch_runtime_current_delivery(delivery)
                {
                    delivery.state = DeliveryState::Failed;
                    delivery.failure_reason = Some(reason);
                }

                let runtime_result = delivery.runtime_result.as_mut().and_then(|receiver| {
                    match receiver.try_recv() {
                        Ok(result) => Some(result),
                        Err(oneshot::error::TryRecvError::Empty) => None,
                        Err(oneshot::error::TryRecvError::Closed) => {
                            Some(Err("Link session task stopped".to_string()))
                        }
                    }
                });

                if let Some(runtime_result) = runtime_result {
                    delivery.runtime_result = None;
                    match runtime_result {
                        Ok(receipt) => {
                            delivery.link.set_state(LinkState::Active);
                            delivery.message.representation = match receipt {
                                LinkPayloadSendReceipt::Packet { .. } => {
                                    DeliveryRepresentation::Packet
                                }
                                LinkPayloadSendReceipt::Resource { .. } => {
                                    DeliveryRepresentation::Resource
                                }
                            };
                            delivery.message.progress = 1.0;
                            delivery.state = DeliveryState::Complete;
                            self.delivery_events.push_back(delivery_event(
                                LxmfDeliveryEventKind::Delivered,
                                *link_id,
                                delivery,
                                Some(1.0),
                                None,
                            ));
                            results.push(DeliveryResult::Complete {
                                link_id: *link_id,
                                msg_hash: delivery.msg_hash,
                            });
                            if delivery.reusable {
                                delivery.state = DeliveryState::Idle;
                                delivery.started_at = Instant::now();
                            } else {
                                remove_session = true;
                            }
                        }
                        Err(reason) => {
                            delivery.link.set_state(LinkState::Closed);
                            push_failed_delivery_and_queue(
                                &mut results,
                                &mut self.delivery_events,
                                *link_id,
                                delivery,
                                &reason,
                            );
                            remove_session = true;
                        }
                    }
                } else if delivery.state != DeliveryState::Idle
                    && delivery.started_at.elapsed() > delivery.timeout
                {
                    push_failed_delivery_and_queue(
                        &mut results,
                        &mut self.delivery_events,
                        *link_id,
                        delivery,
                        "delivery timeout",
                    );
                    remove_session = true;
                }

                if remove_session {
                    to_remove.push(*link_id);
                }
                continue;
            }

            #[cfg(not(test))]
            unreachable!("production delivery must use a runtime-owned Link session");

            #[cfg(any())]
            {
                if delivery.state == DeliveryState::Idle
                    && !delivery.queue.is_empty()
                    && delivery.link.is_active()
                {
                    let _ = delivery.start_queued_delivery();
                }

                if matches!(
                    delivery.state,
                    DeliveryState::Establishing
                        | DeliveryState::Identifying
                        | DeliveryState::Transferring
                        | DeliveryState::AwaitingProof
                ) {
                    let elapsed = delivery.started_at.elapsed();
                    let (timed_out, timeout, reason) =
                        if delivery.state == DeliveryState::Establishing {
                            (
                                elapsed > delivery.establishment_timeout,
                                delivery.establishment_timeout,
                                "link establishment timeout",
                            )
                        } else {
                            (
                                elapsed > delivery.timeout,
                                delivery.timeout,
                                "delivery timeout",
                            )
                        };

                    if timed_out {
                        let state = delivery.state;
                        delivery.state = DeliveryState::Failed;
                        delivery.failure_reason = Some(reason.to_string());
                        tracing::warn!(
                            link_id = %hex_encode(link_id),
                            dest = %hex_encode(&delivery.dest_hash),
                            state = ?state,
                            age_secs = elapsed.as_secs_f64(),
                            timeout_secs = timeout.as_secs_f64(),
                            reason,
                            queued = delivery.queue.len(),
                            "link delivery timed out"
                        );
                        push_failed_delivery_and_queue(
                            &mut results,
                            &mut self.delivery_events,
                            *link_id,
                            delivery,
                            reason,
                        );
                        remove_session = true;
                    }
                }

                if !remove_session {
                    match delivery.state {
                        DeliveryState::Idle => {}
                        DeliveryState::Identifying if delivery.link.is_active() => {
                            if !delivery.reusable
                                && let (Some(pub_key), Some(sign_key)) =
                                    (&self.identity_pub, &self.identity_key)
                                && let Ok(identify_data) = delivery.link.identify(pub_key, sign_key)
                            {
                                let id_header = rns_wire::header::PacketHeader {
                                    flags: rns_wire::flags::PacketFlags {
                                        header_type: rns_wire::flags::HeaderType::Header1,
                                        context_flag: false,
                                        transport_type: rns_wire::flags::TransportType::Broadcast,
                                        destination_type: rns_wire::flags::DestinationType::Link,
                                        packet_type: rns_wire::flags::PacketType::Data,
                                    },
                                    hops: 0,
                                    transport_id: None,
                                    destination_hash: *link_id,
                                    context: rns_wire::context::PacketContext::LinkIdentify,
                                };
                                let mut id_raw = id_header.pack();
                                id_raw.extend_from_slice(&identify_data);
                                let _ = self.transport_tx.try_send(TransportMessage::Outbound(
                                    OutboundRequest {
                                        raw: Bytes::from(id_raw),
                                        destination_hash: *link_id,
                                    },
                                ));
                            }
                            // Reusable Direct links follow upstream LXMF and identify
                            // after a successful delivery, not before the transfer.
                            // One-shot propagation links keep the previous pre-transfer
                            // identify behavior for compatibility with existing callers.
                            delivery.state = DeliveryState::Transferring;
                            if delivery.message.progress < 0.05 {
                                delivery.message.progress = 0.05;
                            }
                            self.delivery_events.push_back(delivery_event(
                                LxmfDeliveryEventKind::LinkEstablished,
                                *link_id,
                                delivery,
                                Some(0.05),
                                None,
                            ));

                            let packed = if let Some(ref packed) = delivery.packed_override {
                                Ok(packed.clone())
                            } else {
                                delivery.message.pack()
                            };
                            if let Ok(packed) = packed {
                                let packet_limit = if delivery.packed_override.is_some() {
                                    delivery.link.mdu.saturating_sub(LXMF_OVERHEAD)
                                } else {
                                    delivery.link.mdu
                                };
                                if packed.len() <= packet_limit {
                                    // Python LXMessage sends Direct messages that fit in Link.MDU
                                    // as a single encrypted link packet, then waits for LINKPROOF.
                                    delivery.message.representation =
                                        DeliveryRepresentation::Packet;
                                    match send_link_packet(
                                        link_id,
                                        delivery,
                                        &self.transport_tx,
                                        &packed,
                                    ) {
                                        Some(packet_hash) => {
                                            delivery.network_transfer.packet_proof_hash =
                                                Some(packet_hash);
                                            delivery.state = DeliveryState::AwaitingProof;
                                            delivery.message.progress = 0.50;
                                            self.delivery_events.push_back(delivery_event(
                                                LxmfDeliveryEventKind::AwaitingProof,
                                                *link_id,
                                                delivery,
                                                Some(0.50),
                                                None,
                                            ));
                                        }
                                        None => {
                                            delivery.state = DeliveryState::Failed;
                                            delivery.failure_reason =
                                                Some("link packet encryption failed".to_string());
                                        }
                                    }
                                } else {
                                    delivery.message.representation =
                                        DeliveryRepresentation::Resource;
                                    // Python's Resource encrypts the blob with link session keys
                                    // BEFORE chunking (Resource.py:424), and resource parts are sent
                                    // on the wire WITHOUT additional packet-layer encryption
                                    // (Packet.py:201-204).
                                    let rtt =
                                        delivery.link.rtt.unwrap_or(Duration::from_millis(500));
                                    let auto_compress = if delivery.packed_override.is_some() {
                                        delivery.auto_compress
                                    } else {
                                        delivery.message.auto_compress
                                    };
                                    let transfer_result = build_resource_transfer(
                                        &delivery.link,
                                        packed,
                                        auto_compress,
                                        rtt,
                                    );
                                    match transfer_result {
                                        Ok((transfer, remaining_segments)) => {
                                            delivery.network_transfer.transfer = Some(transfer);
                                            delivery.network_transfer.remaining_segments =
                                                remaining_segments;
                                            delivery.message.progress = 0.10;
                                            self.delivery_events.push_back(delivery_event(
                                                LxmfDeliveryEventKind::TransferStarted,
                                                *link_id,
                                                delivery,
                                                Some(0.10),
                                                None,
                                            ));
                                        }
                                        Err(e) => {
                                            let _ = e;
                                            delivery.state = DeliveryState::Failed;
                                            delivery.failure_reason =
                                                Some("resource transfer build failed".to_string());
                                        }
                                    }
                                }
                            }
                        }
                        DeliveryState::Identifying => {}
                        DeliveryState::Transferring => {
                            // Process up to a full window of actions per tick so the 500ms tick rate
                            // doesn't throttle us below link speed.
                            let max_actions = 16;
                            for _ in 0..max_actions {
                                if delivery.state != DeliveryState::Transferring {
                                    break;
                                }
                                let Some(ref mut transfer) = delivery.network_transfer.transfer
                                else {
                                    break;
                                };
                                let action = transfer.tick();
                                let reports_resource_progress =
                                    matches!(&action, TransferAction::SendPart(_, _));
                                match dispatch_action(link_id, delivery, &self.transport_tx, action)
                                {
                                    ActionOutcome::Continue => {
                                        if reports_resource_progress {
                                            maybe_push_resource_progress_event(
                                                &mut self.delivery_events,
                                                *link_id,
                                                delivery,
                                            );
                                        }
                                        continue;
                                    }
                                    ActionOutcome::Break => break,
                                    ActionOutcome::Complete => {
                                        delivery.message.progress = 1.0;
                                        self.delivery_events.push_back(delivery_event(
                                            LxmfDeliveryEventKind::Delivered,
                                            *link_id,
                                            delivery,
                                            Some(1.0),
                                            None,
                                        ));
                                        results.push(DeliveryResult::Complete {
                                            link_id: *link_id,
                                            msg_hash: delivery.msg_hash,
                                        });
                                        if delivery.reusable
                                            && delivery.link.state() != LinkState::Closed
                                        {
                                            finish_reusable_delivery(
                                                &self.transport_tx,
                                                &self.identity_pub,
                                                &self.identity_key,
                                                link_id,
                                                delivery,
                                            );
                                        } else {
                                            fail_queued_deliveries(
                                                &mut results,
                                                &mut self.delivery_events,
                                                *link_id,
                                                delivery,
                                                "link closed",
                                            );
                                            remove_session = true;
                                        }
                                    }
                                    ActionOutcome::Fail(reason) => {
                                        push_failed_delivery_and_queue(
                                            &mut results,
                                            &mut self.delivery_events,
                                            *link_id,
                                            delivery,
                                            &reason,
                                        );
                                        remove_session = true;
                                    }
                                }
                            }
                        }
                        DeliveryState::Complete => {
                            delivery.message.progress = 1.0;
                            self.delivery_events.push_back(delivery_event(
                                LxmfDeliveryEventKind::Delivered,
                                *link_id,
                                delivery,
                                Some(1.0),
                                None,
                            ));
                            results.push(DeliveryResult::Complete {
                                link_id: *link_id,
                                msg_hash: delivery.msg_hash,
                            });
                            if delivery.reusable && delivery.link.state() != LinkState::Closed {
                                finish_reusable_delivery(
                                    &self.transport_tx,
                                    &self.identity_pub,
                                    &self.identity_key,
                                    link_id,
                                    delivery,
                                );
                            } else {
                                fail_queued_deliveries(
                                    &mut results,
                                    &mut self.delivery_events,
                                    *link_id,
                                    delivery,
                                    "link closed",
                                );
                                remove_session = true;
                            }
                        }
                        DeliveryState::Rejected => {
                            let reason = delivery
                                .failure_reason
                                .take()
                                .unwrap_or_else(|| "resource rejected".to_string());
                            self.delivery_events.push_back(delivery_event(
                                LxmfDeliveryEventKind::Rejected,
                                *link_id,
                                delivery,
                                Some(delivery.message.progress),
                                Some(reason.clone()),
                            ));
                            results.push(DeliveryResult::Rejected {
                                link_id: *link_id,
                                msg_hash: delivery.msg_hash,
                                dest_hash: delivery.dest_hash,
                                message: delivery.message.clone(),
                                reason,
                            });
                            if delivery.reusable && delivery.link.state() != LinkState::Closed {
                                finish_unsuccessful_reusable_delivery(delivery);
                            } else {
                                fail_queued_deliveries(
                                    &mut results,
                                    &mut self.delivery_events,
                                    *link_id,
                                    delivery,
                                    "link closed",
                                );
                                remove_session = true;
                            }
                        }
                        DeliveryState::Failed => {
                            let reason = delivery
                                .failure_reason
                                .take()
                                .unwrap_or_else(|| "delivery failed".to_string());
                            push_failed_delivery_and_queue(
                                &mut results,
                                &mut self.delivery_events,
                                *link_id,
                                delivery,
                                &reason,
                            );
                            remove_session = true;
                        }
                        DeliveryState::Establishing | DeliveryState::AwaitingProof => {}
                    }
                }

                if !remove_session && delivery.reusable {
                    if delivery.link.state() == LinkState::Closed {
                        fail_queued_deliveries(
                            &mut results,
                            &mut self.delivery_events,
                            *link_id,
                            delivery,
                            "link closed",
                        );
                        remove_session = true;
                    } else if delivery.state == DeliveryState::Idle
                        && delivery.queue.is_empty()
                        && delivery.link.is_active()
                        && direct_link_idle_expired(delivery)
                    {
                        tracing::debug!(
                            link_id = %hex_encode(link_id),
                            dest = %hex_encode(&delivery.dest_hash),
                            idle_secs = link_data_idle_for(&delivery.link).as_secs_f64(),
                            "tearing down inactive Direct link"
                        );
                        send_link_teardown(&self.transport_tx, link_id, &mut delivery.link);
                        remove_session = true;
                    } else if drive_link_action(&self.transport_tx, link_id, delivery.link.tick()) {
                        if !matches!(
                            delivery.state,
                            DeliveryState::Idle | DeliveryState::Complete
                        ) {
                            push_failed_delivery_and_queue(
                                &mut results,
                                &mut self.delivery_events,
                                *link_id,
                                delivery,
                                "link closed",
                            );
                        } else {
                            fail_queued_deliveries(
                                &mut results,
                                &mut self.delivery_events,
                                *link_id,
                                delivery,
                                "link closed",
                            );
                        }
                        remove_session = true;
                    }
                }

                if remove_session {
                    to_remove.push(*link_id);
                }
            }
        }

        for link_id in to_remove {
            if let Some(delivery) = self.pending.remove(&link_id) {
                if delivery.reusable {
                    self.direct_links.remove(&delivery.dest_hash);
                }
                if let Some(handle) = delivery.link.runtime_handle().cloned() {
                    tokio::spawn(async move {
                        let _ = handle.close().await;
                    });
                }
            }
        }

        results
    }

    fn tick_backchannels(&mut self) -> Vec<DeliveryResult> {
        let mut results = Vec::new();

        let starts = std::mem::take(&mut self.pending_backchannel_starts);
        let mut still_waiting = Vec::new();
        for mut start in starts {
            match start.receiver.try_recv() {
                Ok(Ok(receipt)) => {
                    let (key, representation, progress, kind) = match receipt {
                        BackchannelSendReceipt::Packet {
                            link_id,
                            packet_hash,
                        } => (
                            BackchannelProofKey::Packet(link_id, packet_hash),
                            DeliveryRepresentation::Packet,
                            0.50,
                            LxmfDeliveryEventKind::AwaitingProof,
                        ),
                        BackchannelSendReceipt::Resource {
                            link_id,
                            resource_hash,
                        } => (
                            BackchannelProofKey::Resource(link_id, resource_hash),
                            DeliveryRepresentation::Resource,
                            0.10,
                            LxmfDeliveryEventKind::TransferStarted,
                        ),
                    };
                    self.delivery_events.push_back(backchannel_delivery_event(
                        BackchannelDeliveryEventInput {
                            kind,
                            message: &start.message,
                            dest_hash: start.dest_hash,
                            link_id: start.link_id,
                            representation,
                            progress: Some(progress),
                            reason: None,
                            link_state: LinkState::Active,
                            delivery_state: DeliveryState::AwaitingProof,
                        },
                    ));
                    self.pending_backchannel_deliveries.insert(
                        key,
                        PendingBackchannelDelivery {
                            message: start.message,
                            dest_hash: start.dest_hash,
                            link_id: start.link_id,
                            representation,
                            started_at: Instant::now(),
                        },
                    );
                }
                Ok(Err(err)) => {
                    let reason = err.to_string();
                    self.backchannel_links.remove(&start.dest_hash);
                    tracing::warn!(
                        link_id = %hex_encode(&start.link_id),
                        dest = %hex_encode(&start.dest_hash),
                        reason = %reason,
                        "LXMF backchannel send failed"
                    );
                    results.push(fail_backchannel_start(
                        &mut self.delivery_events,
                        start,
                        reason,
                    ));
                }
                Err(oneshot::error::TryRecvError::Empty) => {
                    if start.requested_at.elapsed() > BACKCHANNEL_SEND_COMMAND_TIMEOUT {
                        let reason = "backchannel send command timeout".to_string();
                        self.backchannel_links.remove(&start.dest_hash);
                        tracing::warn!(
                            link_id = %hex_encode(&start.link_id),
                            dest = %hex_encode(&start.dest_hash),
                            "LXMF backchannel send command timed out"
                        );
                        results.push(fail_backchannel_start(
                            &mut self.delivery_events,
                            start,
                            reason,
                        ));
                    } else {
                        still_waiting.push(start);
                    }
                }
                Err(oneshot::error::TryRecvError::Closed) => {
                    let reason = "backchannel send command closed".to_string();
                    self.backchannel_links.remove(&start.dest_hash);
                    results.push(fail_backchannel_start(
                        &mut self.delivery_events,
                        start,
                        reason,
                    ));
                }
            }
        }
        self.pending_backchannel_starts = still_waiting;

        let expired: Vec<_> = self
            .pending_backchannel_deliveries
            .iter()
            .filter_map(|(key, delivery)| {
                (delivery.started_at.elapsed() > BACKCHANNEL_DELIVERY_TIMEOUT).then_some(*key)
            })
            .collect();
        for key in expired {
            if let Some(delivery) = self.pending_backchannel_deliveries.remove(&key) {
                self.backchannel_links.remove(&delivery.dest_hash);
                let reason = "backchannel delivery timeout".to_string();
                self.delivery_events.push_back(backchannel_delivery_event(
                    BackchannelDeliveryEventInput {
                        kind: LxmfDeliveryEventKind::Failed,
                        message: &delivery.message,
                        dest_hash: delivery.dest_hash,
                        link_id: delivery.link_id,
                        representation: delivery.representation,
                        progress: Some(delivery.message.progress),
                        reason: Some(reason.clone()),
                        link_state: LinkState::Closed,
                        delivery_state: DeliveryState::Failed,
                    },
                ));
                results.push(DeliveryResult::Failed {
                    link_id: delivery.link_id,
                    msg_hash: delivery.message.hash,
                    dest_hash: delivery.dest_hash,
                    message: delivery.message,
                    reason,
                });
            }
        }

        results
    }

    #[cfg(any())]
    fn handle_hmu(&mut self, link_id: &[u8; 16], hmu_data: &[u8]) {
        let event = if let Some(delivery) = self.pending.get_mut(link_id)
            && let Some(ref mut transfer) = delivery.network_transfer.transfer
        {
            transfer.handle_hmu(hmu_data);
            let progress = delivery_resource_progress(delivery);
            if let Some(progress) = progress
                && should_update_resource_progress(delivery.message.progress, progress)
            {
                delivery.message.progress = progress;
            }
            progress.map(|_| {
                delivery_event(
                    LxmfDeliveryEventKind::TransferProgress,
                    *link_id,
                    delivery,
                    Some(delivery.message.progress),
                    None,
                )
            })
        } else {
            None
        };
        if let Some(event) = event {
            self.delivery_events.push_back(event);
        }
    }

    /// Handle an inbound `RESOURCE_REQ` (receiver's `request_next`).
    ///
    /// The request returns a list of parts the receiver still needs; dispatch the resulting
    /// `SendPart` actions immediately rather than waiting for the next [`Self::tick`], since
    /// the receiver may time out and retry first.
    #[cfg(any())]
    fn handle_request(&mut self, link_id: &[u8; 16], request_data: &[u8]) {
        let event = {
            let Some(delivery) = self.pending.get_mut(link_id) else {
                return;
            };
            let Some(ref mut transfer) = delivery.network_transfer.transfer else {
                return;
            };
            let actions = transfer.handle_request(request_data);
            for action in actions {
                match dispatch_action(link_id, delivery, &self.transport_tx, action) {
                    ActionOutcome::Continue | ActionOutcome::Break => {}
                    ActionOutcome::Complete => {
                        break;
                    }
                    ActionOutcome::Fail(reason) => {
                        delivery.failure_reason = Some(reason);
                        // Terminal state is surfaced on the next tick() via delivery.state.
                        break;
                    }
                }
            }
            let progress = delivery_resource_progress(delivery);
            if let Some(progress) = progress
                && should_update_resource_progress(delivery.message.progress, progress)
            {
                delivery.message.progress = progress;
            }
            progress.map(|_| {
                delivery_event(
                    LxmfDeliveryEventKind::TransferProgress,
                    *link_id,
                    delivery,
                    Some(delivery.message.progress),
                    None,
                )
            })
        };
        if let Some(event) = event {
            self.delivery_events.push_back(event);
        }
    }

    /// Apply an inbound resource proof; returns `true` when the proof was accepted.
    #[cfg(any())]
    fn handle_resource_proof(&mut self, link_id: &[u8; 16], proof_data: &[u8]) -> bool {
        let mut event = None;
        let accepted = if let Some(delivery) = self.pending.get_mut(link_id)
            && let Some(ref mut transfer) = delivery.network_transfer.transfer
            && transfer.handle_proof(proof_data)
        {
            let progress = delivery_resource_proof_progress(delivery).unwrap_or(1.0);
            delivery.message.progress = progress;
            event = Some(delivery_event(
                LxmfDeliveryEventKind::TransferProgress,
                *link_id,
                delivery,
                Some(progress),
                None,
            ));
            if delivery.network_transfer.remaining_segments.is_empty() {
                delivery.state = DeliveryState::Complete;
            } else {
                let rtt = delivery.link.rtt.unwrap_or(Duration::from_millis(500));
                let next_segment = delivery.network_transfer.remaining_segments.remove(0);
                delivery.network_transfer.transfer =
                    Some(OutboundTransfer::from_prebuilt(next_segment, rtt));
                delivery.state = DeliveryState::Transferring;
            }
            true
        } else {
            false
        };
        if let Some(event) = event {
            self.delivery_events.push_back(event);
        }
        accepted
    }

    /// Apply an inbound receiver-cancel/reject for the current outbound resource.
    #[cfg(any())]
    fn handle_resource_reject(&mut self, link_id: &[u8; 16], reject_data: &[u8]) -> bool {
        if reject_data.len() < 32 {
            return false;
        }

        let mut rejected_hash = [0u8; 32];
        rejected_hash.copy_from_slice(&reject_data[..32]);

        if let Some(delivery) = self.pending.get_mut(link_id)
            && let Some(ref mut transfer) = delivery.network_transfer.transfer
            && transfer.resource.resource_hash == rejected_hash
        {
            transfer.handle_cancel();
            delivery.network_transfer.remaining_segments.clear();
            delivery.message.mark_rejected();
            delivery.state = DeliveryState::Rejected;
            delivery.failure_reason = Some("resource rejected".to_string());
            return true;
        }

        false
    }

    #[cfg(any())]
    fn handle_link_closed(
        &mut self,
        link_id: &[u8; 16],
        encrypted_teardown: Option<&[u8]>,
    ) -> bool {
        let Some(delivery) = self.pending.get_mut(link_id) else {
            return false;
        };

        let verified = match encrypted_teardown {
            Some(data) => delivery.link.receive_teardown(data),
            None => {
                delivery.link.mark_closed(CloseReason::DestinationClosed);
                true
            }
        };

        if verified {
            if delivery.state == DeliveryState::Complete {
                return true;
            }
            if delivery.state == DeliveryState::Idle {
                delivery.failure_reason = Some("link closed".to_string());
                return true;
            }
            delivery.network_transfer = LinkTransferState::default();
            delivery.state = DeliveryState::Failed;
            delivery.failure_reason = Some("link closed".to_string());
        }

        verified
    }

    /// Apply an inbound link-packet proof; returns `true` when the packet delivery is complete.
    #[cfg(any())]
    fn handle_link_packet_proof(&mut self, link_id: &[u8; 16], proof_data: &[u8]) -> bool {
        if let Some(delivery) = self.pending.get_mut(link_id)
            && delivery.state == DeliveryState::AwaitingProof
            && let Some(packet_hash) = delivery.network_transfer.packet_proof_hash
            && delivery
                .link
                .validate_packet_proof(&packet_hash, proof_data)
        {
            delivery.state = DeliveryState::Complete;
            return true;
        }
        false
    }

    pub fn handle_backchannel_packet_proof(
        &mut self,
        link_id: [u8; 16],
        packet_hash: [u8; 32],
    ) -> Option<DeliveryResult> {
        self.complete_backchannel_delivery(BackchannelProofKey::Packet(link_id, packet_hash))
    }

    pub fn handle_backchannel_resource_proof(
        &mut self,
        link_id: [u8; 16],
        resource_hash: [u8; 32],
    ) -> Option<DeliveryResult> {
        self.complete_backchannel_delivery(BackchannelProofKey::Resource(link_id, resource_hash))
    }

    fn complete_backchannel_delivery(
        &mut self,
        key: BackchannelProofKey,
    ) -> Option<DeliveryResult> {
        let delivery = self.pending_backchannel_deliveries.remove(&key)?;
        self.delivery_events
            .push_back(backchannel_delivery_event(BackchannelDeliveryEventInput {
                kind: LxmfDeliveryEventKind::Delivered,
                message: &delivery.message,
                dest_hash: delivery.dest_hash,
                link_id: delivery.link_id,
                representation: delivery.representation,
                progress: Some(1.0),
                reason: None,
                link_state: LinkState::Active,
                delivery_state: DeliveryState::Complete,
            }));
        tracing::info!(
            link_id = %hex_encode(&delivery.link_id),
            dest = %hex_encode(&delivery.dest_hash),
            age_secs = delivery.started_at.elapsed().as_secs_f64(),
            "LXMF backchannel delivery proved"
        );
        Some(DeliveryResult::Complete {
            link_id: delivery.link_id,
            msg_hash: delivery.message.hash,
        })
    }

    pub fn pending_count(&self) -> usize {
        self.pending
            .values()
            .map(PendingDelivery::active_delivery_count)
            .sum::<usize>()
            + self.pending_backchannel_starts.len()
            + self.pending_backchannel_deliveries.len()
    }

    pub fn fail_delivery_by_message_hash(
        &mut self,
        msg_hash: [u8; 32],
        reason: &str,
    ) -> Vec<DeliveryResult> {
        let mut results = Vec::new();
        let mut remove_direct_session = None;

        for (link_id, delivery) in &mut self.pending {
            if delivery.msg_hash == Some(msg_hash) {
                push_failed_delivery_and_queue(
                    &mut results,
                    &mut self.delivery_events,
                    *link_id,
                    delivery,
                    reason,
                );
                remove_direct_session = Some((*link_id, delivery.dest_hash));
                break;
            }

            if let Some(pos) = delivery.queue.position_by_hash(msg_hash) {
                if let Some(queued) = delivery.queue.remove(pos) {
                    self.delivery_events.push_back(queued_delivery_event(
                        LxmfDeliveryEventKind::Failed,
                        *link_id,
                        delivery.dest_hash,
                        &queued,
                        Some(reason.to_string()),
                    ));
                    results.push(DeliveryResult::Failed {
                        link_id: *link_id,
                        msg_hash: queued.msg_hash,
                        dest_hash: delivery.dest_hash,
                        message: queued.message,
                        reason: reason.to_string(),
                    });
                }
                break;
            }
        }

        if let Some((link_id, dest_hash)) = remove_direct_session {
            self.pending.remove(&link_id);
            if self.direct_links.get(&dest_hash) == Some(&link_id) {
                self.direct_links.remove(&dest_hash);
            }
        }

        if !results.is_empty() {
            return results;
        }

        if let Some(pos) = self
            .pending_backchannel_starts
            .iter()
            .position(|start| start.message.hash == Some(msg_hash))
        {
            let start = self.pending_backchannel_starts.remove(pos);
            self.backchannel_links.remove(&start.dest_hash);
            results.push(fail_backchannel_start(
                &mut self.delivery_events,
                start,
                reason.to_string(),
            ));
            return results;
        }

        let pending_key = self
            .pending_backchannel_deliveries
            .iter()
            .find_map(|(key, delivery)| (delivery.message.hash == Some(msg_hash)).then_some(*key));
        if let Some(key) = pending_key
            && let Some(delivery) = self.pending_backchannel_deliveries.remove(&key)
        {
            self.backchannel_links.remove(&delivery.dest_hash);
            self.delivery_events.push_back(backchannel_delivery_event(
                BackchannelDeliveryEventInput {
                    kind: LxmfDeliveryEventKind::Failed,
                    message: &delivery.message,
                    dest_hash: delivery.dest_hash,
                    link_id: delivery.link_id,
                    representation: delivery.representation,
                    progress: Some(delivery.message.progress),
                    reason: Some(reason.to_string()),
                    link_state: LinkState::Closed,
                    delivery_state: DeliveryState::Failed,
                },
            ));
            results.push(DeliveryResult::Failed {
                link_id: delivery.link_id,
                msg_hash: delivery.message.hash,
                dest_hash: delivery.dest_hash,
                message: delivery.message,
                reason: reason.to_string(),
            });
        }

        results
    }

    pub fn cancel_delivery_by_message_hash(&mut self, msg_hash: [u8; 32]) -> bool {
        let mut remove_direct_session = None;
        let mut cancelled = false;

        for (link_id, delivery) in &mut self.pending {
            if delivery.msg_hash == Some(msg_hash) {
                if let Some(handle) = delivery.link.runtime_handle().cloned() {
                    tokio::spawn(async move {
                        let _ = handle.close().await;
                    });
                    delivery.link.set_state(LinkState::Closed);
                }
                if delivery.reusable && delivery.link.is_active() {
                    finish_unsuccessful_reusable_delivery(delivery);
                } else {
                    remove_direct_session = Some((*link_id, delivery.dest_hash));
                }
                cancelled = true;
                break;
            }

            if let Some(pos) = delivery.queue.position_by_hash(msg_hash) {
                delivery.queue.remove(pos);
                cancelled = true;
                break;
            }
        }

        if let Some((link_id, dest_hash)) = remove_direct_session {
            if let Some(mut delivery) = self.pending.remove(&link_id) {
                close_outbound_delivery_link(&self.transport_tx, &link_id, &mut delivery.link);
            }
            if self.direct_links.get(&dest_hash) == Some(&link_id) {
                self.direct_links.remove(&dest_hash);
            }
        }

        if cancelled {
            return true;
        }

        if let Some(pos) = self
            .pending_backchannel_starts
            .iter()
            .position(|start| start.message.hash == Some(msg_hash))
        {
            self.pending_backchannel_starts.remove(pos);
            return true;
        }

        let pending_key = self
            .pending_backchannel_deliveries
            .iter()
            .find_map(|(key, delivery)| (delivery.message.hash == Some(msg_hash)).then_some(*key));
        if let Some(key) = pending_key {
            self.pending_backchannel_deliveries.remove(&key);
            return true;
        }

        false
    }

    pub fn take_delivery_events(&mut self) -> Vec<LxmfDeliveryEvent> {
        self.delivery_events.drain(..).collect()
    }

    pub fn message_delivery_snapshot(&self, msg_hash: [u8; 32]) -> Option<MessageDeliverySnapshot> {
        for (link_id, delivery) in &self.pending {
            let in_flight_deliveries = delivery.active_delivery_count();
            if delivery.state != DeliveryState::Idle && delivery.msg_hash == Some(msg_hash) {
                return Some(MessageDeliverySnapshot {
                    link_id: *link_id,
                    dest_hash: delivery.dest_hash,
                    link_state: delivery.link.state(),
                    delivery_state: delivery.state,
                    representation: delivery.message.representation,
                    progress: delivery.message.progress,
                    queued: false,
                    queued_deliveries: delivery.queue.len(),
                    in_flight_deliveries,
                });
            }

            if let Some(queued) = delivery
                .queue
                .iter()
                .find(|queued| queued.msg_hash == Some(msg_hash))
            {
                return Some(MessageDeliverySnapshot {
                    link_id: *link_id,
                    dest_hash: delivery.dest_hash,
                    link_state: delivery.link.state(),
                    delivery_state: delivery.state,
                    representation: queued.message.representation,
                    progress: queued.message.progress,
                    queued: true,
                    queued_deliveries: delivery.queue.len(),
                    in_flight_deliveries,
                });
            }
        }

        for start in &self.pending_backchannel_starts {
            if start.message.hash == Some(msg_hash) {
                return Some(MessageDeliverySnapshot {
                    link_id: start.link_id,
                    dest_hash: start.dest_hash,
                    link_state: LinkState::Active,
                    delivery_state: DeliveryState::Transferring,
                    representation: DeliveryRepresentation::Unknown,
                    progress: start.message.progress,
                    queued: true,
                    queued_deliveries: 1,
                    in_flight_deliveries: 0,
                });
            }
        }

        for (key, delivery) in &self.pending_backchannel_deliveries {
            if delivery.message.hash == Some(msg_hash) {
                let link_id = match key {
                    BackchannelProofKey::Packet(link_id, _)
                    | BackchannelProofKey::Resource(link_id, _) => *link_id,
                };
                return Some(MessageDeliverySnapshot {
                    link_id,
                    dest_hash: delivery.dest_hash,
                    link_state: LinkState::Active,
                    delivery_state: DeliveryState::AwaitingProof,
                    representation: delivery.representation,
                    progress: delivery.message.progress,
                    queued: false,
                    queued_deliveries: 0,
                    in_flight_deliveries: 1,
                });
            }
        }

        None
    }

    pub fn delivery_link_available(&self, dest_hash: &[u8; 16]) -> bool {
        self.direct_links
            .get(dest_hash)
            .and_then(|link_id| self.pending.get(link_id))
            .is_some_and(|delivery| {
                delivery.reusable
                    && delivery.link.state() != LinkState::Closed
                    && !direct_link_idle_expired(delivery)
            })
            || self.backchannel_links.contains_key(dest_hash)
    }

    pub fn direct_link_snapshot(&self, dest_hash: [u8; 16]) -> Option<DirectLinkSnapshot> {
        let link_id = *self.direct_links.get(&dest_hash)?;
        let delivery = self.pending.get(&link_id)?;
        Some(DirectLinkSnapshot {
            link_id,
            dest_hash,
            link_state: delivery.link.state(),
            delivery_state: delivery.state,
            idle_expired: direct_link_idle_expired(delivery),
            queued_deliveries: delivery.queue.len(),
            in_flight_deliveries: usize::from(delivery.state != DeliveryState::Idle),
        })
    }

    pub fn backchannel_link_snapshot(
        &self,
        dest_hash: [u8; 16],
    ) -> Option<BackchannelLinkSnapshot> {
        let link_id = *self.backchannel_links.get(&dest_hash)?;
        let queued_deliveries = self
            .pending_backchannel_starts
            .iter()
            .filter(|start| start.dest_hash == dest_hash)
            .count();
        let in_flight_deliveries = self
            .pending_backchannel_deliveries
            .values()
            .filter(|delivery| delivery.dest_hash == dest_hash)
            .count();
        Some(BackchannelLinkSnapshot {
            link_id,
            dest_hash,
            queued_deliveries,
            in_flight_deliveries,
        })
    }

    pub fn stats(&self) -> LinkDeliveryStats {
        let mut stats = LinkDeliveryStats {
            sessions: self.pending.len(),
            direct_sessions: self.pending.values().filter(|d| d.reusable).count(),
            one_shot_sessions: self.pending.values().filter(|d| !d.reusable).count(),
            backchannel_sessions: self.backchannel_links.len(),
            pending_backchannel_starts: self.pending_backchannel_starts.len(),
            pending_backchannel_deliveries: self.pending_backchannel_deliveries.len(),
            ..LinkDeliveryStats::default()
        };
        for delivery in self.pending.values() {
            stats.queued_deliveries += delivery.queue.len();
            if delivery.state != DeliveryState::Idle {
                stats.in_flight_deliveries += 1;
            }
            if delivery.reusable {
                if delivery.state == DeliveryState::Establishing {
                    stats.establishing_direct_sessions += 1;
                }
                if delivery.link.is_active() {
                    stats.active_direct_sessions += 1;
                }
                if delivery.state == DeliveryState::Idle {
                    stats.idle_direct_sessions += 1;
                }
            }
        }
        stats.queued_deliveries += self.pending_backchannel_starts.len();
        stats.in_flight_deliveries += self.pending_backchannel_deliveries.len();
        stats
    }

    pub fn session_count(&self) -> usize {
        self.pending.len()
    }
}

fn delivery_event(
    kind: LxmfDeliveryEventKind,
    link_id: [u8; 16],
    delivery: &PendingDelivery,
    progress: Option<f64>,
    reason: Option<String>,
) -> LxmfDeliveryEvent {
    LxmfDeliveryEvent {
        kind,
        method: if delivery.reusable {
            LxmfDeliveryEventMethod::Direct
        } else {
            LxmfDeliveryEventMethod::PropagationDeposit
        },
        link_id,
        dest_hash: delivery.dest_hash,
        msg_hash: delivery.msg_hash,
        attempts: delivery.message.delivery_attempts,
        progress,
        representation: delivery.message.representation,
        link_state: delivery.link.state(),
        delivery_state: delivery.state,
        queued_deliveries: delivery.queue.len(),
        in_flight_deliveries: usize::from(delivery.state != DeliveryState::Idle),
        reason,
    }
}

fn queued_delivery_event(
    kind: LxmfDeliveryEventKind,
    link_id: [u8; 16],
    dest_hash: [u8; 16],
    queued: &QueuedDelivery,
    reason: Option<String>,
) -> LxmfDeliveryEvent {
    LxmfDeliveryEvent {
        kind,
        method: LxmfDeliveryEventMethod::Direct,
        link_id,
        dest_hash,
        msg_hash: queued.msg_hash,
        attempts: queued.message.delivery_attempts,
        progress: Some(queued.message.progress),
        representation: queued.message.representation,
        link_state: LinkState::Closed,
        delivery_state: DeliveryState::Failed,
        queued_deliveries: 0,
        in_flight_deliveries: 0,
        reason,
    }
}

struct BackchannelDeliveryEventInput<'a> {
    kind: LxmfDeliveryEventKind,
    message: &'a LxMessage,
    dest_hash: [u8; 16],
    link_id: [u8; 16],
    representation: DeliveryRepresentation,
    progress: Option<f64>,
    reason: Option<String>,
    link_state: LinkState,
    delivery_state: DeliveryState,
}

fn backchannel_delivery_event(input: BackchannelDeliveryEventInput<'_>) -> LxmfDeliveryEvent {
    LxmfDeliveryEvent {
        kind: input.kind,
        method: LxmfDeliveryEventMethod::Direct,
        link_id: input.link_id,
        dest_hash: input.dest_hash,
        msg_hash: input.message.hash,
        attempts: input.message.delivery_attempts,
        progress: input.progress,
        representation: input.representation,
        link_state: input.link_state,
        delivery_state: input.delivery_state,
        queued_deliveries: 0,
        in_flight_deliveries: usize::from(matches!(
            input.delivery_state,
            DeliveryState::Transferring | DeliveryState::AwaitingProof
        )),
        reason: input.reason,
    }
}

fn fail_backchannel_start(
    events: &mut VecDeque<LxmfDeliveryEvent>,
    start: PendingBackchannelStart,
    reason: String,
) -> DeliveryResult {
    events.push_back(backchannel_delivery_event(BackchannelDeliveryEventInput {
        kind: LxmfDeliveryEventKind::Failed,
        message: &start.message,
        dest_hash: start.dest_hash,
        link_id: start.link_id,
        representation: DeliveryRepresentation::Unknown,
        progress: Some(start.message.progress),
        reason: Some(reason.clone()),
        link_state: LinkState::Closed,
        delivery_state: DeliveryState::Failed,
    }));
    DeliveryResult::Failed {
        link_id: start.link_id,
        msg_hash: start.message.hash,
        dest_hash: start.dest_hash,
        message: start.message,
        reason,
    }
}

#[cfg(any())]
fn delivery_resource_progress(delivery: &PendingDelivery) -> Option<f64> {
    let transfer = delivery.network_transfer.transfer.as_ref()?;
    let total_segments = transfer.resource.total_segments.max(1);
    let completed_segments = transfer.resource.segment_index.saturating_sub(1);
    let aggregate = (completed_segments as f64 + transfer.progress()) / total_segments as f64;
    Some((0.10 + aggregate * 0.90).clamp(0.10, 0.99))
}

#[cfg(any())]
fn delivery_resource_proof_progress(delivery: &PendingDelivery) -> Option<f64> {
    let transfer = delivery.network_transfer.transfer.as_ref()?;
    let total_segments = transfer.resource.total_segments.max(1);
    let completed_segments = transfer.resource.segment_index.min(total_segments);
    let aggregate = completed_segments as f64 / total_segments as f64;
    Some((0.10 + aggregate * 0.90).clamp(0.10, 1.0))
}

#[cfg(any())]
fn should_update_resource_progress(current: f64, next: f64) -> bool {
    next > current && ((next * 100.0).floor() > (current * 100.0).floor() || next >= 0.99)
}

#[cfg(any())]
fn maybe_push_resource_progress_event(
    events: &mut VecDeque<LxmfDeliveryEvent>,
    link_id: [u8; 16],
    delivery: &mut PendingDelivery,
) {
    let Some(progress) = delivery_resource_progress(delivery) else {
        return;
    };
    if !should_update_resource_progress(delivery.message.progress, progress) {
        return;
    }
    delivery.message.progress = progress;
    events.push_back(delivery_event(
        LxmfDeliveryEventKind::TransferProgress,
        link_id,
        delivery,
        Some(progress),
        None,
    ));
}

#[cfg(any())]
fn finish_reusable_delivery(
    transport_tx: &mpsc::Sender<TransportMessage>,
    identity_pub: &Option<[u8; 64]>,
    identity_key: &Option<Ed25519PrivateKey>,
    link_id: &[u8; 16],
    delivery: &mut PendingDelivery,
) {
    if !delivery.backchannel_identified
        && let (Some(pub_key), Some(sign_key)) = (identity_pub, identity_key)
    {
        delivery.backchannel_identified =
            send_link_identify(transport_tx, link_id, &delivery.link, pub_key, sign_key);
    }

    delivery.network_transfer = LinkTransferState::default();
    delivery.failure_reason = None;

    if delivery.link.is_active() && delivery.start_queued_delivery() {
        return;
    }

    delivery.state = DeliveryState::Idle;
}

fn finish_unsuccessful_reusable_delivery(delivery: &mut PendingDelivery) {
    delivery.failure_reason = None;

    if delivery.link.is_active() && delivery.start_queued_delivery() {
        return;
    }

    delivery.state = DeliveryState::Idle;
}

#[cfg(any())]
fn cancel_current_delivery(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link_id: &[u8; 16],
    delivery: &mut PendingDelivery,
) {
    if let Some(resource_hash) = delivery
        .network_transfer
        .transfer
        .as_ref()
        .map(|transfer| transfer.resource.resource_hash)
    {
        let _ = dispatch_action(
            link_id,
            delivery,
            transport_tx,
            TransferAction::SendCancel(rns_protocol::resource::CancelType::Icl, resource_hash),
        );
    }
}

fn push_failed_delivery_and_queue(
    results: &mut Vec<DeliveryResult>,
    events: &mut VecDeque<LxmfDeliveryEvent>,
    link_id: [u8; 16],
    delivery: &mut PendingDelivery,
    reason: &str,
) {
    events.push_back(delivery_event(
        LxmfDeliveryEventKind::Failed,
        link_id,
        delivery,
        Some(delivery.message.progress),
        Some(reason.to_string()),
    ));
    results.push(DeliveryResult::Failed {
        link_id,
        msg_hash: delivery.msg_hash,
        dest_hash: delivery.dest_hash,
        message: delivery.message.clone(),
        reason: reason.to_string(),
    });
    fail_queued_deliveries(results, events, link_id, delivery, reason);
}

fn fail_queued_deliveries(
    results: &mut Vec<DeliveryResult>,
    events: &mut VecDeque<LxmfDeliveryEvent>,
    link_id: [u8; 16],
    delivery: &mut PendingDelivery,
    reason: &str,
) {
    for queued in delivery.queue.drain() {
        events.push_back(queued_delivery_event(
            LxmfDeliveryEventKind::Failed,
            link_id,
            delivery.dest_hash,
            &queued,
            Some(reason.to_string()),
        ));
        results.push(DeliveryResult::Failed {
            link_id,
            msg_hash: queued.msg_hash,
            dest_hash: delivery.dest_hash,
            message: queued.message,
            reason: reason.to_string(),
        });
    }
}

#[cfg(any())]
fn send_link_identify(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link_id: &[u8; 16],
    link: &Link,
    identity_pub: &[u8; 64],
    identity_key: &Ed25519PrivateKey,
) -> bool {
    let Ok(identify_data) = link.identify(identity_pub, identity_key) else {
        return false;
    };
    let id_header = rns_wire::header::PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Link,
            packet_type: rns_wire::flags::PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination_hash: *link_id,
        context: rns_wire::context::PacketContext::LinkIdentify,
    };
    let mut id_raw = id_header.pack();
    id_raw.extend_from_slice(&identify_data);
    transport_tx
        .try_send(TransportMessage::Outbound(OutboundRequest {
            raw: Bytes::from(id_raw),
            destination_hash: *link_id,
        }))
        .is_ok()
}

#[cfg(any())]
fn drive_link_action(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link_id: &[u8; 16],
    action: LinkAction,
) -> bool {
    match action {
        LinkAction::SendKeepalive => {
            send_keepalive_packet(transport_tx, link_id);
            false
        }
        LinkAction::TransitionedToStale => {
            // Python sends one more keepalive when an initiator transitions stale.
            send_keepalive_packet(transport_tx, link_id);
            false
        }
        LinkAction::SendTeardownAndClose(teardown_data) => {
            if !teardown_data.is_empty() {
                send_link_close_payload(transport_tx, link_id, &teardown_data);
            }
            true
        }
        LinkAction::Closed(_) => true,
        LinkAction::None => false,
    }
}

#[cfg(any())]
fn send_keepalive_packet(transport_tx: &mpsc::Sender<TransportMessage>, link_id: &[u8; 16]) {
    let header = rns_wire::header::PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Link,
            packet_type: rns_wire::flags::PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination_hash: *link_id,
        context: rns_wire::context::PacketContext::Keepalive,
    };
    let mut raw = header.pack();
    raw.push(rns_link::constants::KEEPALIVE_REQUEST);
    let _ = transport_tx.try_send(TransportMessage::Outbound(OutboundRequest {
        raw: Bytes::from(raw),
        destination_hash: *link_id,
    }));
}

#[cfg(any())]
fn send_link_close_payload(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link_id: &[u8; 16],
    teardown_data: &[u8],
) {
    let header = rns_wire::header::PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Link,
            packet_type: rns_wire::flags::PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination_hash: *link_id,
        context: rns_wire::context::PacketContext::LinkClose,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(teardown_data);
    let _ = transport_tx.try_send(TransportMessage::Outbound(OutboundRequest {
        raw: Bytes::from(raw),
        destination_hash: *link_id,
    }));
}

#[cfg(any())]
fn link_data_idle_for(link: &Link) -> Duration {
    link.no_data_for().min(link.no_outbound_for())
}

fn direct_link_idle_expired(delivery: &PendingDelivery) -> bool {
    if delivery.state != DeliveryState::Idle
        || !delivery.queue.is_empty()
        || !delivery.link.is_active()
    {
        return false;
    }
    delivery.started_at.elapsed() > LINK_MAX_INACTIVITY
}

#[cfg(any())]
fn build_resource_transfer(
    link: &Link,
    packed: Vec<u8>,
    auto_compress: bool,
    rtt: Duration,
) -> Result<(OutboundTransfer, Vec<OutboundResource>), ResourceError> {
    if packed.len() <= MAX_EFFICIENT_SIZE {
        let transfer = match link.session_keys() {
            Some(keys) => {
                OutboundTransfer::new_encrypted(packed, auto_compress, rtt, keys.clone())?
            }
            None => OutboundTransfer::new(packed, auto_compress, rtt)?,
        };
        return Ok((transfer, Vec::new()));
    }

    let multi = match link.session_keys() {
        Some(keys) => {
            let keys = keys.clone();
            let encrypt_fn = |plaintext: &[u8]| -> Vec<u8> {
                rns_link::encryption::link_encrypt(&keys, plaintext)
                    .unwrap_or_else(|_| plaintext.to_vec())
            };
            MultiSegmentOutbound::with_encrypt(packed, auto_compress, Some(&encrypt_fn))?
        }
        None => MultiSegmentOutbound::new(packed, auto_compress)?,
    };

    let mut segments = multi.segments.into_iter();
    let first = segments.next().ok_or(ResourceError::Incomplete)?;
    Ok((
        OutboundTransfer::from_prebuilt(first, rtt),
        segments.collect(),
    ))
}

/// Result of a delivery tick.
#[derive(Debug)]
pub enum DeliveryResult {
    Complete {
        link_id: [u8; 16],
        msg_hash: Option<[u8; 32]>,
    },
    Rejected {
        link_id: [u8; 16],
        msg_hash: Option<[u8; 32]>,
        dest_hash: [u8; 16],
        message: LxMessage,
        reason: String,
    },
    Failed {
        link_id: [u8; 16],
        msg_hash: Option<[u8; 32]>,
        dest_hash: [u8; 16],
        message: LxMessage,
        reason: String,
    },
}

/// Outcome of dispatching one [`TransferAction`] onto the wire.
#[cfg(any())]
enum ActionOutcome {
    /// Action dispatched, continue draining.
    Continue,
    /// No-op; stop draining for this cycle.
    Break,
    /// Transfer completed; `delivery.state` is already [`DeliveryState::Complete`].
    Complete,
    /// Transfer failed; `delivery.state` is already [`DeliveryState::Failed`].
    Fail(String),
}

/// Send a single LXMF packet over an active link and return the full packet hash that the peer
/// must prove with `LINKPROOF`.
#[cfg(any())]
fn send_link_packet(
    link_id: &[u8; 16],
    delivery: &mut PendingDelivery,
    transport_tx: &mpsc::Sender<TransportMessage>,
    packed: &[u8],
) -> Option<[u8; 32]> {
    let encrypted = delivery.link.encrypt(packed).ok()?;
    let header = rns_wire::header::PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Link,
            packet_type: rns_wire::flags::PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination_hash: *link_id,
        context: rns_wire::context::PacketContext::None,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(&encrypted);
    let packet_hash = rns_wire::hash::packet_hash(&raw, rns_wire::flags::HeaderType::Header1);
    let _ = transport_tx.try_send(TransportMessage::Outbound(OutboundRequest {
        raw: Bytes::from(raw),
        destination_hash: *link_id,
    }));
    delivery.link.record_tx(encrypted.len());
    Some(packet_hash)
}

#[cfg(any())]
fn send_link_teardown(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link_id: &[u8; 16],
    link: &mut Link,
) {
    let Some(teardown_data) = link.teardown(CloseReason::InitiatorClosed) else {
        return;
    };
    let header = rns_wire::header::PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            header_type: rns_wire::flags::HeaderType::Header1,
            context_flag: false,
            transport_type: rns_wire::flags::TransportType::Broadcast,
            destination_type: rns_wire::flags::DestinationType::Link,
            packet_type: rns_wire::flags::PacketType::Data,
        },
        hops: 0,
        transport_id: None,
        destination_hash: *link_id,
        context: rns_wire::context::PacketContext::LinkClose,
    };
    let mut raw = header.pack();
    raw.extend_from_slice(&teardown_data);
    let _ = transport_tx.try_send(TransportMessage::Outbound(OutboundRequest {
        raw: Bytes::from(raw),
        destination_hash: *link_id,
    }));
}

fn close_outbound_delivery_link(
    transport_tx: &mpsc::Sender<TransportMessage>,
    link_id: &[u8; 16],
    link: &mut OutboundDeliveryLink,
) {
    if let Some(handle) = link.runtime_handle().cloned() {
        tokio::spawn(async move {
            let _ = handle.close().await;
        });
    }
    let _ = (transport_tx, link_id);
}

/// Serialize a [`TransferAction`] onto the link and enqueue it for transport.
///
/// Kept as a free function so it can be called from [`LinkDeliveryManager::tick`] and
/// [`LinkDeliveryManager::handle_request`] without double-mutable-borrow conflicts on the
/// manager.
#[cfg(any())]
fn dispatch_action(
    link_id: &[u8; 16],
    delivery: &mut PendingDelivery,
    transport_tx: &mpsc::Sender<TransportMessage>,
    action: TransferAction,
) -> ActionOutcome {
    let base_flags = rns_wire::flags::PacketFlags {
        header_type: rns_wire::flags::HeaderType::Header1,
        context_flag: false,
        transport_type: rns_wire::flags::TransportType::Broadcast,
        destination_type: rns_wire::flags::DestinationType::Link,
        packet_type: rns_wire::flags::PacketType::Data,
    };
    let make_header = |context, packet_type| rns_wire::header::PacketHeader {
        flags: rns_wire::flags::PacketFlags {
            packet_type,
            ..base_flags
        },
        hops: 0,
        transport_id: None,
        destination_hash: *link_id,
        context,
    };
    let send = |header: rns_wire::header::PacketHeader, body: &[u8]| {
        let mut raw = header.pack();
        raw.extend_from_slice(body);
        let _ = transport_tx.try_send(TransportMessage::Outbound(OutboundRequest {
            raw: Bytes::from(raw),
            destination_hash: *link_id,
        }));
    };

    match action {
        TransferAction::SendAdvertisement(adv_data) => {
            if let Ok(encrypted) = delivery.link.encrypt(&adv_data) {
                send(
                    make_header(
                        rns_wire::context::PacketContext::ResourceAdv,
                        rns_wire::flags::PacketType::Data,
                    ),
                    &encrypted,
                );
                delivery.link.record_tx(encrypted.len());
            }
            ActionOutcome::Continue
        }
        TransferAction::SendPart(_, part_data) => {
            // Parts are already ciphertext (pre-chunk blob encryption). `context=Resource`
            // packets are not packet-layer encrypted (Packet.py:201-204).
            send(
                make_header(
                    rns_wire::context::PacketContext::Resource,
                    rns_wire::flags::PacketType::Data,
                ),
                &part_data,
            );
            delivery.link.record_tx(part_data.len());
            ActionOutcome::Continue
        }
        TransferAction::SendHmu(hmu_data) => {
            if let Ok(encrypted) = delivery.link.encrypt(&hmu_data) {
                send(
                    make_header(
                        rns_wire::context::PacketContext::ResourceHmu,
                        rns_wire::flags::PacketType::Data,
                    ),
                    &encrypted,
                );
                delivery.link.record_tx(encrypted.len());
            }
            ActionOutcome::Continue
        }
        TransferAction::SendRequest(req_data) => {
            if let Ok(encrypted) = delivery.link.encrypt(&req_data) {
                send(
                    make_header(
                        rns_wire::context::PacketContext::ResourceReq,
                        rns_wire::flags::PacketType::Data,
                    ),
                    &encrypted,
                );
                delivery.link.record_tx(encrypted.len());
            }
            ActionOutcome::Continue
        }
        TransferAction::SendProof(proof_data) => {
            // PROOF+RESOURCE_PRF is plaintext on a Proof packet (Packet.py:195-197). Body =
            // resource_hash(32) || proof(32).
            send(
                make_header(
                    rns_wire::context::PacketContext::ResourcePrf,
                    rns_wire::flags::PacketType::Proof,
                ),
                &proof_data,
            );
            delivery.link.record_tx(proof_data.len());
            ActionOutcome::Continue
        }
        TransferAction::Complete => {
            delivery.state = DeliveryState::Complete;
            ActionOutcome::Complete
        }
        TransferAction::Failed(reason) => {
            delivery.state = DeliveryState::Failed;
            ActionOutcome::Fail(reason)
        }
        TransferAction::SendCancel(cancel_type, resource_hash) => {
            if let Ok(encrypted) = delivery.link.encrypt(&resource_hash) {
                let context = match cancel_type {
                    rns_protocol::resource::CancelType::Icl => {
                        rns_wire::context::PacketContext::ResourceIcl
                    }
                    rns_protocol::resource::CancelType::Rcl => {
                        rns_wire::context::PacketContext::ResourceRcl
                    }
                };
                send(
                    make_header(context, rns_wire::flags::PacketType::Data),
                    &encrypted,
                );
                delivery.link.record_tx(encrypted.len());
            }
            delivery.state = DeliveryState::Failed;
            ActionOutcome::Fail("resource transfer cancelled".to_string())
        }
        TransferAction::None => ActionOutcome::Break,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_link_delivery_manager_creation() {
        let (tx, _rx) = mpsc::channel(16);
        let mgr = LinkDeliveryManager::new(tx, None, None);
        assert_eq!(mgr.pending_count(), 0);
    }

    #[test]
    fn test_backchannel_delivery_uses_registered_link_and_packet_proof() {
        let (tx, _rx) = mpsc::channel(16);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        mgr.set_backchannel_sender(cmd_tx);

        let dest_hash = [0xD1; 16];
        let link_id = [0xE1; 16];
        let packet_hash = [0xF1; 32];
        mgr.register_backchannel(dest_hash, link_id);
        assert!(mgr.delivery_link_available(&dest_hash));
        assert_eq!(
            mgr.backchannel_link_snapshot(dest_hash).unwrap().link_id,
            link_id
        );

        let sign_key = Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Backchannel",
            "packet proof",
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        let msg_hash = msg.hash;

        let report = mgr.start_backchannel_delivery(msg, dest_hash).unwrap();
        assert_eq!(report.link_id, link_id);
        assert_eq!(mgr.pending_count(), 1);
        let events = mgr.take_delivery_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, LxmfDeliveryEventKind::BackchannelLinkReused);
        assert_eq!(events[0].progress, Some(0.05));

        let command = cmd_rx.try_recv().expect("backchannel send command");
        assert_eq!(command.link_id, link_id);
        assert!(!command.payload.is_empty());
        assert!(
            command
                .result_tx
                .send(Ok(BackchannelSendReceipt::Packet {
                    link_id,
                    packet_hash,
                }))
                .is_ok()
        );

        assert!(mgr.tick().is_empty());
        let events = mgr.take_delivery_events();
        assert!(events.iter().any(|event| {
            event.kind == LxmfDeliveryEventKind::AwaitingProof
                && event.progress == Some(0.50)
                && event.representation == DeliveryRepresentation::Packet
        }));
        assert_eq!(mgr.pending_count(), 1);
        assert_eq!(mgr.stats().pending_backchannel_deliveries, 1);

        let result = mgr
            .handle_backchannel_packet_proof(link_id, packet_hash)
            .expect("packet proof completes backchannel delivery");
        assert!(matches!(
            result,
            DeliveryResult::Complete {
                link_id: id,
                msg_hash: hash,
            } if id == link_id && hash == msg_hash
        ));
        let events = mgr.take_delivery_events();
        assert!(events.iter().any(|event| {
            event.kind == LxmfDeliveryEventKind::Delivered && event.progress == Some(1.0)
        }));
        assert_eq!(mgr.pending_count(), 0);
        assert_eq!(mgr.stats().backchannel_sessions, 1);
    }

    #[test]
    fn test_backchannel_send_error_removes_link_and_fails_message() {
        let (tx, _rx) = mpsc::channel(16);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        mgr.set_backchannel_sender(cmd_tx);

        let dest_hash = [0xD2; 16];
        let link_id = [0xE2; 16];
        mgr.register_backchannel(dest_hash, link_id);

        let sign_key = Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Backchannel",
            "send failure",
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        let msg_hash = msg.hash;

        mgr.start_backchannel_delivery(msg, dest_hash).unwrap();
        let command = cmd_rx.try_recv().expect("backchannel send command");
        assert!(
            command
                .result_tx
                .send(Err(BackchannelSendError::LinkNotActive))
                .is_ok()
        );

        let results = mgr.tick();
        assert!(results.iter().any(|result| matches!(
            result,
            DeliveryResult::Failed {
                link_id: id,
                msg_hash: hash,
                dest_hash: dest,
                reason,
                ..
            } if *id == link_id
                && *hash == msg_hash
                && *dest == dest_hash
                && reason == "link is not active"
                && is_retryable_link_delivery_failure(reason)
        )));
        assert!(!mgr.delivery_link_available(&dest_hash));
        let events = mgr.take_delivery_events();
        assert!(
            events
                .iter()
                .any(|event| event.kind == LxmfDeliveryEventKind::Failed)
        );
    }

    #[test]
    fn test_fail_backchannel_link_removes_cached_link() {
        let (tx, _rx) = mpsc::channel(16);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        let link_id = [0xEA; 16];
        let first_dest = [0xD4; 16];
        let second_dest = [0xD5; 16];
        let other_dest = [0xD6; 16];
        mgr.register_backchannel(first_dest, link_id);
        mgr.register_backchannel(second_dest, link_id);
        mgr.register_backchannel(other_dest, [0xEB; 16]);

        let results = mgr.fail_backchannel_link(link_id, "link closed");

        assert!(results.is_empty());
        assert!(!mgr.delivery_link_available(&first_dest));
        assert!(!mgr.delivery_link_available(&second_dest));
        assert!(mgr.delivery_link_available(&other_dest));
    }

    #[test]
    fn test_fail_backchannel_link_fails_pending_delivery() {
        let (tx, _rx) = mpsc::channel(16);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(16);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        mgr.set_backchannel_sender(cmd_tx);

        let dest_hash = [0xD7; 16];
        let link_id = [0xE7; 16];
        let packet_hash = [0xF7; 32];
        mgr.register_backchannel(dest_hash, link_id);

        let sign_key = Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Backchannel",
            "closed while awaiting proof",
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        let msg_hash = msg.hash;

        mgr.start_backchannel_delivery(msg, dest_hash).unwrap();
        let command = cmd_rx.try_recv().expect("backchannel send command");
        assert!(
            command
                .result_tx
                .send(Ok(BackchannelSendReceipt::Packet {
                    link_id,
                    packet_hash,
                }))
                .is_ok()
        );
        assert!(mgr.tick().is_empty());
        assert_eq!(mgr.stats().pending_backchannel_deliveries, 1);

        let results = mgr.fail_backchannel_link(link_id, "link closed");

        assert!(matches!(
            results.as_slice(),
            [DeliveryResult::Failed {
                link_id: id,
                msg_hash: hash,
                dest_hash: dest,
                reason,
                ..
            }] if *id == link_id
                && *hash == msg_hash
                && *dest == dest_hash
                && reason == "link closed"
        ));
        assert!(!mgr.delivery_link_available(&dest_hash));
        assert_eq!(mgr.stats().pending_backchannel_deliveries, 0);
    }

    #[test]
    fn test_retryable_link_delivery_failure_includes_stale_backchannels() {
        assert!(is_retryable_link_delivery_failure(
            "link establishment timeout"
        ));
        assert!(is_retryable_link_delivery_failure("link closed"));
        assert!(is_retryable_link_delivery_failure("link not found"));
        assert!(is_retryable_link_delivery_failure("link is not active"));
        assert!(is_retryable_link_delivery_failure(
            "link session keys are unavailable"
        ));
        assert!(is_retryable_link_delivery_failure(
            "transport channel is full or closed"
        ));
        assert!(is_retryable_link_delivery_failure(
            "backchannel send command timeout"
        ));
        assert!(!is_retryable_link_delivery_failure(
            "resource transfer could not be started"
        ));
    }

    #[test]
    fn test_fail_delivery_by_message_hash_aborts_backchannel_start() {
        let (tx, _rx) = mpsc::channel(16);
        let (cmd_tx, _cmd_rx) = mpsc::channel(16);
        let mut mgr = LinkDeliveryManager::new(tx, None, None);
        mgr.set_backchannel_sender(cmd_tx);

        let dest_hash = [0xD4; 16];
        let link_id = [0xE4; 16];
        let sign_key = Ed25519PrivateKey::generate();
        let mut msg = LxMessage::new(
            [0xAA; 16],
            [0xBB; 16],
            "Backchannel",
            "stale backchannel delivery",
            crate::constants::DeliveryMethod::Direct,
        );
        msg.sign(&sign_key).unwrap();
        let msg_hash = msg.hash.unwrap();

        mgr.register_backchannel(dest_hash, link_id);
        mgr.start_backchannel_delivery(msg, dest_hash).unwrap();

        let results = mgr.fail_delivery_by_message_hash(msg_hash, "direct fallback timeout");
        assert_eq!(results.len(), 1);
        assert!(matches!(
            &results[0],
            DeliveryResult::Failed {
                link_id: id,
                msg_hash: Some(hash),
                dest_hash: dest,
                reason,
                ..
            } if *id == link_id
                && *hash == msg_hash
                && *dest == dest_hash
                && reason == "direct fallback timeout"
        ));
        assert_eq!(mgr.pending_count(), 0);
        assert!(!mgr.delivery_link_available(&dest_hash));
    }
}
