//! Outbound LXMF propagation peer sync over Reticulum's public Link API.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rns_crypto::ed25519::Ed25519PrivateKey;
use rns_runtime::link_client::LinkSession;
use rns_runtime::reticulum::ReticulumHandle;
use rns_transport::messages::TransportMessage;
use tokio::sync::mpsc;

use crate::constants::OFFER_REQUEST_PATH;
use crate::peer::LxmPeer;
use crate::propagation::hex_encode;
use crate::propagation_node::{PropagationNode, PropagationNodeConfig};
use crate::sync::OfferResponse;
use crate::types::PropagationTransientId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncTaskState {
    Idle,
    Establishing,
    Offering,
    AwaitingResponse,
    Transferring,
    Complete,
    Failed,
}

pub struct PropagationSyncTask {
    node_dest_hash: Option<[u8; 16]>,
    pub propagation_node: Arc<Mutex<PropagationNode>>,
    pub state: SyncTaskState,
    last_sync: Instant,
    sync_interval: Duration,
    sync_started: Option<Instant>,
    sync_timeout: Duration,
    peer: Option<LxmPeer>,
    runtime: Option<ReticulumHandle>,
    identity_pub: Option<[u8; 64]>,
    identity_key: Option<Ed25519PrivateKey>,
    known_identities: HashMap<String, [u8; 64]>,
    workflow_tx: mpsc::UnboundedSender<bool>,
    workflow_rx: mpsc::UnboundedReceiver<bool>,
    workflow_active: bool,
}

impl PropagationSyncTask {
    pub fn new(_transport_tx: mpsc::Sender<TransportMessage>, dest_hash: [u8; 16]) -> Self {
        Self::from_node(Arc::new(Mutex::new(PropagationNode::new(
            PropagationNodeConfig::default(),
            dest_hash,
        ))))
    }

    pub fn with_storage(
        _transport_tx: mpsc::Sender<TransportMessage>,
        dest_hash: [u8; 16],
        storage_path: std::path::PathBuf,
    ) -> std::io::Result<Self> {
        Ok(Self::from_node(Arc::new(Mutex::new(
            PropagationNode::with_storage(
                PropagationNodeConfig::default(),
                dest_hash,
                storage_path,
            )?,
        ))))
    }

    pub fn with_shared_node(
        _transport_tx: mpsc::Sender<TransportMessage>,
        propagation_node: Arc<Mutex<PropagationNode>>,
    ) -> Self {
        Self::from_node(propagation_node)
    }

    fn from_node(propagation_node: Arc<Mutex<PropagationNode>>) -> Self {
        let (workflow_tx, workflow_rx) = mpsc::unbounded_channel();
        Self {
            node_dest_hash: None,
            propagation_node,
            state: SyncTaskState::Idle,
            last_sync: Instant::now(),
            sync_interval: Duration::from_secs(300),
            sync_started: None,
            sync_timeout: Duration::from_secs(120),
            peer: None,
            runtime: None,
            identity_pub: None,
            identity_key: None,
            known_identities: HashMap::new(),
            workflow_tx,
            workflow_rx,
            workflow_active: false,
        }
    }

    pub fn set_runtime_and_identity(
        &mut self,
        runtime: ReticulumHandle,
        identity_pub: [u8; 64],
        identity_key: Ed25519PrivateKey,
    ) {
        self.runtime = Some(runtime);
        self.identity_pub = Some(identity_pub);
        self.identity_key = Some(identity_key);
    }

    pub fn set_node(&mut self, dest_hash: [u8; 16]) {
        self.node_dest_hash = Some(dest_hash);
    }

    pub fn request_sync_now(&mut self, dest_hash: [u8; 16]) {
        self.node_dest_hash = Some(dest_hash);
        if self.state == SyncTaskState::Idle {
            self.start_sync(dest_hash);
            self.last_sync = Instant::now();
        }
    }

    pub fn node_dest_hash(&self) -> Option<[u8; 16]> {
        self.node_dest_hash
    }

    pub fn accept_message(&mut self, msg: &crate::message::LxMessage) -> bool {
        self.propagation_node
            .lock()
            .map(|mut node| node.accept_message(msg))
            .unwrap_or(false)
    }

    /// LinkSession owns the destination events. This method only updates the
    /// announce-recalled identity cache used when the next sync starts.
    pub fn drain_events(&mut self, known_identities: &HashMap<String, [u8; 64]>) {
        self.known_identities.clone_from(known_identities);
    }

    pub fn tick(&mut self) {
        if let Ok(success) = self.workflow_rx.try_recv() {
            self.workflow_active = false;
            self.state = if success {
                SyncTaskState::Complete
            } else {
                SyncTaskState::Failed
            };
        }
        if self.workflow_active {
            if self
                .sync_started
                .is_some_and(|started| started.elapsed() > self.sync_timeout)
            {
                // The LinkSession operation owns its deadline and will report
                // the final result; retain the state until then.
                self.state = SyncTaskState::Failed;
            }
            return;
        }

        match self.state {
            SyncTaskState::Idle => {
                if self.last_sync.elapsed() >= self.sync_interval
                    && let Some(node_hash) = self.node_dest_hash
                {
                    if self.message_count() > 0 {
                        self.start_sync(node_hash);
                    } else {
                        self.last_sync = Instant::now();
                    }
                }
            }
            SyncTaskState::Complete | SyncTaskState::Failed => {
                if let Some(peer) = self.peer.as_mut() {
                    peer.link_closed();
                }
                self.peer = None;
                self.sync_started = None;
                self.last_sync = Instant::now();
                self.state = SyncTaskState::Idle;
            }
            _ => {}
        }
    }

    fn start_sync(&mut self, node_hash: [u8; 16]) -> bool {
        let Some(runtime) = self.runtime.clone() else {
            self.state = SyncTaskState::Failed;
            return false;
        };
        let Some(remote_public_key) = self.known_identities.get(&hex_encode(&node_hash)).copied()
        else {
            self.state = SyncTaskState::Failed;
            return false;
        };
        let (Some(identity_pub), Some(identity_key)) = (
            self.identity_pub,
            self.identity_key
                .as_ref()
                .map(|key| Ed25519PrivateKey::from_bytes(&key.to_bytes())),
        ) else {
            self.state = SyncTaskState::Failed;
            return false;
        };

        let Some((offer_data, offered_messages)) = self.prepare_offer(node_hash) else {
            self.state = SyncTaskState::Failed;
            return false;
        };
        let result_tx = self.workflow_tx.clone();
        self.workflow_active = true;
        self.state = SyncTaskState::Establishing;
        self.sync_started = Some(Instant::now());
        let mut peer = LxmPeer::new(node_hash);
        peer.begin_sync();
        self.peer = Some(peer);
        tokio::spawn(async move {
            let success = propagation_sync_workflow(
                runtime,
                node_hash,
                remote_public_key,
                identity_pub,
                identity_key,
                offer_data,
                offered_messages,
            )
            .await;
            let _ = result_tx.send(success);
        });
        true
    }

    fn prepare_offer(
        &self,
        node_hash: [u8; 16],
    ) -> Option<(Vec<u8>, Vec<(PropagationTransientId, Vec<u8>)>)> {
        let mut node = self.propagation_node.lock().ok()?;
        let offer = node.prepare_sync_offer(node_hash);
        let ids = offer
            .transient_ids
            .iter()
            .cloned()
            .map(rmpv::Value::Binary)
            .collect();
        let data = crate::encode_value(&rmpv::Value::Array(vec![
            rmpv::Value::Binary(offer.peering_key),
            rmpv::Value::Array(ids),
        ]));
        let offered_ids: Vec<PropagationTransientId> = offer
            .transient_ids
            .iter()
            .filter_map(|id| id.as_slice().try_into().ok())
            .collect();
        let plan = node.plan_message_reads(&offered_ids);
        drop(node);
        Some((data, crate::propagation_node::read_planned_messages(&plan)))
    }

    pub fn message_count(&self) -> usize {
        self.propagation_node
            .lock()
            .map(|node| node.message_count())
            .unwrap_or(0)
    }

    pub fn peer(&self) -> Option<&LxmPeer> {
        self.peer.as_ref()
    }
}

async fn propagation_sync_workflow(
    runtime: ReticulumHandle,
    node_hash: [u8; 16],
    remote_public_key: [u8; 64],
    identity_pub: [u8; 64],
    identity_key: Ed25519PrivateKey,
    offer_data: Vec<u8>,
    offered_messages: Vec<(PropagationTransientId, Vec<u8>)>,
) -> bool {
    let workflow = async {
        let mut link = LinkSession::open_with_public_key(
            &runtime,
            rns_identity::identity::Identity::new(),
            node_hash,
            remote_public_key,
            1,
            Duration::from_secs(30),
        )
        .await?;
        link.identify_with(&identity_pub, &identity_key).await?;
        let response = link
            .request(
                OFFER_REQUEST_PATH,
                Some(&offer_data),
                Duration::from_secs(60),
            )
            .await?;
        let wanted = match OfferResponse::from_msgpack(&response) {
            OfferResponse::WantAll => offered_messages
                .iter()
                .map(|(id, _)| *id)
                .collect::<Vec<_>>(),
            OfferResponse::HaveAll => Vec::new(),
            OfferResponse::WantSome(ids) => ids
                .into_iter()
                .filter_map(|id| id.as_slice().try_into().ok())
                .collect(),
            _ => return Err("peer rejected propagation offer".into()),
        };
        for (_, message) in offered_messages
            .into_iter()
            .filter(|(id, _)| wanted.contains(id))
        {
            link.send_resource(message, true, Duration::from_secs(120))
                .await?;
        }
        link.close().await?;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;
    if let Err(error) = workflow {
        tracing::warn!(
            error = %error,
            peer = %hex::encode(node_hash),
            "propagation sync over LinkSession failed"
        );
        false
    } else {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_starts_idle() {
        let (tx, _) = mpsc::channel(1);
        let task = PropagationSyncTask::new(tx, [0xAA; 16]);
        assert_eq!(task.state, SyncTaskState::Idle);
        assert_eq!(task.message_count(), 0);
    }

    #[test]
    fn sync_without_runtime_fails_cleanly() {
        let (tx, _) = mpsc::channel(1);
        let mut task = PropagationSyncTask::new(tx, [0xAA; 16]);
        task.request_sync_now([0xBB; 16]);
        assert_eq!(task.state, SyncTaskState::Failed);
    }

    #[test]
    fn shared_node_is_preserved() {
        let (tx, _) = mpsc::channel(1);
        let node = Arc::new(Mutex::new(PropagationNode::new(
            PropagationNodeConfig::default(),
            [0xAA; 16],
        )));
        let task = PropagationSyncTask::with_shared_node(tx, node.clone());
        assert!(Arc::ptr_eq(&task.propagation_node, &node));
    }
}
