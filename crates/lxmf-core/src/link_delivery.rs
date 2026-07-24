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
    RuntimeUnavailable,
    RemoteIdentityUnavailable,
}

impl fmt::Display for LinkDeliveryStartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
                    close_outbound_delivery_link(&mut delivery.link);
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
                close_outbound_delivery_link(&mut delivery.link);
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

fn finish_unsuccessful_reusable_delivery(delivery: &mut PendingDelivery) {
    delivery.failure_reason = None;

    if delivery.link.is_active() && delivery.start_queued_delivery() {
        return;
    }

    delivery.state = DeliveryState::Idle;
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

fn direct_link_idle_expired(delivery: &PendingDelivery) -> bool {
    if delivery.state != DeliveryState::Idle
        || !delivery.queue.is_empty()
        || !delivery.link.is_active()
    {
        return false;
    }
    delivery.started_at.elapsed() > LINK_MAX_INACTIVITY
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

fn close_outbound_delivery_link(link: &mut OutboundDeliveryLink) {
    if let Some(handle) = link.runtime_handle().cloned() {
        tokio::spawn(async move {
            let _ = handle.close().await;
        });
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
