//! Client-side LXMF propagation download over Reticulum's public Link API.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use rns_crypto::ed25519::Ed25519PrivateKey;
use rns_runtime::link_client::{LinkClientError, LinkSession};
use rns_runtime::reticulum::ReticulumHandle;
use rns_transport::messages::TransportMessage;
use tokio::sync::mpsc;

use crate::constants::{DELIVERY_LIMIT, MESSAGE_GET_PATH};
use crate::types::PropagationTransientId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagationClientState {
    Idle,
    LinkEstablishing,
    Identifying,
    RequestingList,
    RequestingMessages,
    Purging,
    Complete,
    Failed,
}

pub struct PropagationClient {
    pub outbound_propagation_node: Option<[u8; 16]>,
    pub state: PropagationClientState,
    identity_pub: Option<[u8; 64]>,
    identity_key: Option<Ed25519PrivateKey>,
    available_messages: Vec<Vec<u8>>,
    local_messages: HashSet<Vec<u8>>,
    received_messages: Vec<Vec<u8>>,
    delivery_limit: Option<f64>,
    started_at: Option<Instant>,
    timeout: Duration,
    runtime: Option<ReticulumHandle>,
    workflow_tx: mpsc::UnboundedSender<PropagationWorkflowResult>,
    workflow_rx: mpsc::UnboundedReceiver<PropagationWorkflowResult>,
    workflow_active: bool,
}

struct PropagationWorkflowResult {
    available_messages: Vec<Vec<u8>>,
    received_messages: Vec<Vec<u8>>,
    success: bool,
}

impl PropagationClient {
    /// The transport argument is retained for source compatibility. Network
    /// operations are performed through the runtime installed by
    /// [`Self::set_runtime`].
    pub fn new(
        _transport_tx: mpsc::Sender<TransportMessage>,
        identity_pub: Option<[u8; 64]>,
        identity_key: Option<Ed25519PrivateKey>,
    ) -> Self {
        let (workflow_tx, workflow_rx) = mpsc::unbounded_channel();
        Self {
            outbound_propagation_node: None,
            state: PropagationClientState::Idle,
            identity_pub,
            identity_key,
            available_messages: Vec::new(),
            local_messages: HashSet::new(),
            received_messages: Vec::new(),
            delivery_limit: Some(DELIVERY_LIMIT as f64),
            started_at: None,
            timeout: Duration::from_secs(120),
            runtime: None,
            workflow_tx,
            workflow_rx,
            workflow_active: false,
        }
    }

    pub fn set_runtime(&mut self, runtime: ReticulumHandle) {
        self.runtime = Some(runtime);
    }

    pub fn set_propagation_node(&mut self, dest_hash: [u8; 16]) {
        self.outbound_propagation_node = Some(dest_hash);
    }

    /// KB per transfer.
    pub fn set_delivery_limit(&mut self, limit_kb: f64) {
        self.delivery_limit = Some(limit_kb);
    }

    pub fn add_local_message(&mut self, transient_id: PropagationTransientId) {
        self.local_messages.insert(transient_id.to_vec());
    }

    pub fn add_local_message_id(&mut self, transient_id: Vec<u8>) {
        self.local_messages.insert(transient_id);
    }

    pub fn available_messages(&self) -> &[Vec<u8>] {
        &self.available_messages
    }

    pub fn take_received_messages(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.received_messages)
    }

    /// Start a download, resolving the remote identity through Reticulum's
    /// announce recall API.
    pub fn start_download(&mut self) -> bool {
        self.start_download_inner(None)
    }

    /// Start a download with an already recalled remote public key.
    pub fn start_download_with_public_key(&mut self, remote_public_key: [u8; 64]) -> bool {
        self.start_download_inner(Some(remote_public_key))
    }

    fn start_download_inner(&mut self, remote_public_key: Option<[u8; 64]>) -> bool {
        let Some(runtime) = self.runtime.clone() else {
            return false;
        };
        let Some(node_hash) = self.outbound_propagation_node else {
            return false;
        };
        let (Some(identity_pub), Some(identity_key)) = (
            self.identity_pub,
            self.identity_key
                .as_ref()
                .map(|key| Ed25519PrivateKey::from_bytes(&key.to_bytes())),
        ) else {
            return false;
        };
        if self.workflow_active {
            return false;
        }

        let result_tx = self.workflow_tx.clone();
        let local_messages = self.local_messages.clone();
        let delivery_limit = self.delivery_limit;
        let timeout = self.timeout;
        self.workflow_active = true;
        self.state = PropagationClientState::LinkEstablishing;
        self.started_at = Some(Instant::now());
        tokio::spawn(async move {
            let result = propagation_download_workflow(
                runtime,
                node_hash,
                remote_public_key,
                identity_pub,
                identity_key,
                local_messages,
                delivery_limit,
                timeout,
            )
            .await;
            let _ = result_tx.send(result);
        });
        true
    }

    /// Compatibility no-op: LinkSession owns and drains its destination events.
    pub fn drain_events(
        &mut self,
        _known_identities: &std::collections::HashMap<String, [u8; 64]>,
    ) {
    }

    pub fn tick(&mut self) {
        if let Ok(result) = self.workflow_rx.try_recv() {
            self.workflow_active = false;
            self.available_messages = result.available_messages;
            self.received_messages.extend(result.received_messages);
            self.state = if result.success {
                PropagationClientState::Complete
            } else {
                PropagationClientState::Failed
            };
        }
        if !self.workflow_active
            && matches!(
                self.state,
                PropagationClientState::Complete | PropagationClientState::Failed
            )
        {
            self.started_at = None;
            self.state = PropagationClientState::Idle;
        }
    }

    pub fn received_count(&self) -> usize {
        self.received_messages.len()
    }
}

#[allow(clippy::too_many_arguments)]
async fn propagation_download_workflow(
    runtime: ReticulumHandle,
    node_hash: [u8; 16],
    remote_public_key: Option<[u8; 64]>,
    identity_pub: [u8; 64],
    identity_key: Ed25519PrivateKey,
    local_messages: HashSet<Vec<u8>>,
    delivery_limit: Option<f64>,
    timeout: Duration,
) -> PropagationWorkflowResult {
    let mut result = PropagationWorkflowResult {
        available_messages: Vec::new(),
        received_messages: Vec::new(),
        success: false,
    };
    let workflow = async {
        let identity = rns_identity::identity::Identity::new();
        let mut link = match remote_public_key {
            Some(public_key) => {
                LinkSession::open_with_public_key(
                    &runtime,
                    identity,
                    node_hash,
                    public_key,
                    1,
                    Duration::from_secs(30),
                )
                .await?
            }
            None => {
                LinkSession::open(&runtime, identity, node_hash, 1, Duration::from_secs(30)).await?
            }
        };
        link.identify_with(&identity_pub, &identity_key).await?;

        let list_request = crate::encode_value(&rmpv::Value::Array(vec![
            rmpv::Value::Nil,
            rmpv::Value::Nil,
        ]));
        let list_response = link
            .request(MESSAGE_GET_PATH, Some(&list_request), timeout)
            .await?;
        result.available_messages = decode_binary_array(&list_response, Some(32))?;

        let wants: Vec<rmpv::Value> = result
            .available_messages
            .iter()
            .filter(|id| !local_messages.contains(*id))
            .cloned()
            .map(rmpv::Value::Binary)
            .collect();
        let haves: Vec<rmpv::Value> = result
            .available_messages
            .iter()
            .filter(|id| local_messages.contains(*id))
            .cloned()
            .map(rmpv::Value::Binary)
            .collect();

        let mut received_ids = Vec::new();
        if !wants.is_empty() {
            let mut request = vec![rmpv::Value::Array(wants), rmpv::Value::Array(haves.clone())];
            if let Some(limit) = delivery_limit {
                request.push(rmpv::Value::F64(limit));
            }
            let response = link
                .request(
                    MESSAGE_GET_PATH,
                    Some(&crate::encode_value(&rmpv::Value::Array(request))),
                    timeout,
                )
                .await?;
            result.received_messages = decode_binary_array(&response, None)?;
            received_ids.extend(
                result
                    .received_messages
                    .iter()
                    .map(|message| rns_crypto::sha::full_hash(message).to_vec()),
            );
        }

        let purge_ids = if received_ids.is_empty() {
            haves
        } else {
            received_ids.into_iter().map(rmpv::Value::Binary).collect()
        };
        if !purge_ids.is_empty() {
            let purge = crate::encode_value(&rmpv::Value::Array(vec![
                rmpv::Value::Nil,
                rmpv::Value::Array(purge_ids),
            ]));
            link.request(MESSAGE_GET_PATH, Some(&purge), timeout)
                .await?;
        }
        link.close().await?;
        Ok::<(), LinkClientError>(())
    }
    .await;
    result.success = workflow.is_ok();
    if let Err(error) = workflow {
        tracing::warn!(
            error = %error,
            node = %hex::encode(node_hash),
            "propagation download over LinkSession failed"
        );
    }
    result
}

fn decode_binary_array(
    mut data: &[u8],
    exact_length: Option<usize>,
) -> Result<Vec<Vec<u8>>, LinkClientError> {
    let value = rmpv::decode::read_value(&mut data)
        .map_err(|error| LinkClientError::Resource(error.to_string()))?;
    let array = value
        .as_array()
        .ok_or_else(|| LinkClientError::Resource("expected msgpack array".into()))?;
    Ok(array
        .iter()
        .filter_map(|item| item.as_slice())
        .filter(|item| exact_length.is_none_or(|length| item.len() == length))
        .map(ToOwned::to_owned)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};

    use rns_identity::destination::Destination;
    use rns_identity::identity::Identity;
    use rns_runtime::lifecycle::ShutdownSignal;
    use rns_runtime::link_manager::LinkManager;
    use rns_runtime::reticulum::{InstanceMode, init};

    async fn free_tcp_port_pair() -> (u16, u16) {
        let first = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        (
            first.local_addr().unwrap().port(),
            second.local_addr().unwrap().port(),
        )
    }

    #[test]
    fn binary_array_filters_invalid_ids() {
        let encoded = crate::encode_value(&rmpv::Value::Array(vec![
            rmpv::Value::Binary(vec![1; 32]),
            rmpv::Value::Binary(vec![2; 16]),
            rmpv::Value::String("not binary".into()),
        ]));
        assert_eq!(
            decode_binary_array(&encoded, Some(32)).unwrap(),
            vec![vec![1; 32]]
        );
    }

    #[test]
    fn client_requires_runtime_and_node() {
        let (tx, _) = mpsc::channel(1);
        let mut client = PropagationClient::new(tx, None, None);
        assert!(!client.start_download());
        client.set_propagation_node([1; 16]);
        assert!(!client.start_download());
    }

    #[test]
    fn take_received_messages_drains_queue() {
        let (tx, _) = mpsc::channel(1);
        let mut client = PropagationClient::new(tx, None, None);
        client.received_messages = vec![vec![1], vec![2]];
        assert_eq!(client.take_received_messages(), vec![vec![1], vec![2]]);
        assert_eq!(client.received_count(), 0);
    }

    #[tokio::test]
    async fn propagation_download_and_peer_sync_cross_shared_instance() {
        let (port, control_port) = free_tcp_port_pair().await;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("lxmf_shared_propagation_{nonce}"));
        let shared_dir = base.join("shared");
        let server_dir = base.join("server");
        let client_dir = base.join("client");
        for dir in [&shared_dir, &server_dir, &client_dir] {
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

        let shared_shutdown = ShutdownSignal::new();
        let server_shutdown = ShutdownSignal::new();
        let client_shutdown = ShutdownSignal::new();
        let shared = init(
            Some(shared_dir.to_str().unwrap()),
            None,
            shared_shutdown.clone(),
            Arc::new(AtomicBool::new(true)),
        )
        .await
        .unwrap();
        let server = init(
            Some(server_dir.to_str().unwrap()),
            None,
            server_shutdown.clone(),
            Arc::new(AtomicBool::new(true)),
        )
        .await
        .unwrap();
        let client = init(
            Some(client_dir.to_str().unwrap()),
            None,
            client_shutdown.clone(),
            Arc::new(AtomicBool::new(true)),
        )
        .await
        .unwrap();
        assert_eq!(shared.instance_mode, InstanceMode::Shared);
        assert_eq!(server.instance_mode, InstanceMode::Client);
        assert_eq!(client.instance_mode, InstanceMode::Client);

        let server_identity = Identity::new();
        let server_public_key = server_identity.get_public_key();
        let server_hash = Destination::hash_from_name_and_identity(
            "lxmf.propagation",
            Some(&server_identity.hash),
        );
        let (delivery_tx, delivery_rx) = mpsc::channel(64);
        server
            .transport_tx
            .send(TransportMessage::RegisterDestination {
                hash: server_hash,
                app_name: "lxmf.propagation".into(),
                delivery_tx: Some(delivery_tx),
            })
            .await
            .unwrap();

        let node = Arc::new(Mutex::new(crate::propagation_node::PropagationNode::new(
            crate::propagation_node::PropagationNodeConfig::default(),
            server_hash,
        )));
        let mut manager = LinkManager::with_destination(
            server.transport_tx.clone(),
            delivery_rx,
            &server_identity,
            "lxmf.propagation",
            server_identity.get_signing_key(),
        );
        let link_identities = manager.link_identities_handle();
        let server_identity_hash = server_identity.hash;
        let handler_node = node.clone();
        let offer_path_hash =
            rns_crypto::sha::truncated_hash(crate::constants::OFFER_REQUEST_PATH.as_bytes());
        let get_path_hash =
            rns_crypto::sha::truncated_hash(crate::constants::MESSAGE_GET_PATH.as_bytes());
        manager.set_request_handler(move |link_id, path_hash, data| {
            let remote_identity = link_identities
                .lock()
                .ok()
                .and_then(|identities| identities.get(&link_id).copied());
            let handler = crate::handlers::PropagationRequestHandler::new(server_identity_hash);
            let mut node = handler_node.lock().ok()?;
            if path_hash == offer_path_hash {
                Some(handler.handle_offer_request(remote_identity.as_ref(), &data, &mut node))
            } else if path_hash == get_path_hash {
                Some(
                    handler
                        .handle_message_get_request(
                            remote_identity.as_ref(),
                            &[0; 16],
                            &data,
                            &mut node,
                        )
                        .into_response(),
                )
            } else {
                None
            }
        });
        let manager_task = tokio::spawn(manager.run());
        tokio::time::sleep(Duration::from_millis(200)).await;

        let download_identity = Identity::new();
        let download = propagation_download_workflow(
            client.clone(),
            server_hash,
            Some(server_public_key),
            download_identity.get_public_key(),
            download_identity.get_signing_key().unwrap(),
            HashSet::new(),
            Some(DELIVERY_LIMIT as f64),
            Duration::from_secs(10),
        )
        .await;
        assert!(download.success);
        assert!(download.available_messages.is_empty());

        let sync_identity = Identity::new();
        let mut sync_node = crate::propagation_node::PropagationNode::new(
            crate::propagation_node::PropagationNodeConfig::default(),
            sync_identity.hash,
        );
        let mut offer = sync_node.prepare_sync_offer(server_hash);
        let mut peer = crate::peer::LxmPeer::new(server_hash);
        assert!(peer.generate_peering_key(&server_identity.hash, &sync_identity.hash));
        offer.peering_key = peer
            .peering_key
            .as_ref()
            .map(|(key, _)| key.to_vec())
            .unwrap();
        let offer_data = crate::encode_value(&rmpv::Value::Array(vec![
            rmpv::Value::Binary(offer.peering_key),
            rmpv::Value::Array(Vec::new()),
        ]));
        assert!(
            crate::propagation_sync::propagation_sync_workflow(
                client,
                server_hash,
                server_public_key,
                sync_identity.get_public_key(),
                sync_identity.get_signing_key().unwrap(),
                offer_data,
                Vec::new(),
            )
            .await
        );

        manager_task.abort();
        client_shutdown.trigger();
        server_shutdown.trigger();
        shared_shutdown.trigger();
        tokio::time::sleep(Duration::from_millis(100)).await;
        std::fs::remove_dir_all(base).unwrap();
    }
}
