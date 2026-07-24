//! Small application-facing helpers corresponding to the common
//! `LXMRouter.register_delivery_identity()` workflow.

use rns_identity::destination::{DestType, Destination, DestinationError, Direction};
use rns_identity::identity::Identity;
use thiserror::Error;

use crate::constants::DeliveryMethod;
use crate::handlers::get_announce_app_data;
use crate::message::{LxMessage, MessageError};

/// Canonical Reticulum aspect used for ordinary LXMF delivery destinations.
pub const DELIVERY_APP_NAME: &str = "lxmf.delivery";

/// A local LXMF delivery identity and its Reticulum destination.
///
/// This type keeps the pieces applications otherwise have to assemble
/// manually: the identity, canonical destination, display/stamp announce
/// metadata and message signing.
pub struct DeliveryIdentity {
    identity: Identity,
    destination: Destination,
    display_name: Option<String>,
    stamp_cost: Option<u8>,
}

#[derive(Debug, Error)]
pub enum ApplicationError {
    #[error("destination: {0}")]
    Destination(#[from] DestinationError),
    #[error("identity has no signing key")]
    MissingSigningKey,
    #[error("message: {0}")]
    Message(#[from] MessageError),
}

impl DeliveryIdentity {
    /// Register the conceptual equivalent of a Python LXMF delivery identity.
    ///
    /// Network registration is intentionally performed by the runtime adapter;
    /// this constructor creates the application object without hidden I/O.
    pub fn new(
        identity: Identity,
        display_name: Option<String>,
        stamp_cost: Option<u8>,
    ) -> Result<Self, ApplicationError> {
        let destination = Destination::new(
            Some(&identity),
            Direction::In,
            DestType::Single,
            DELIVERY_APP_NAME,
        )?;
        Ok(Self {
            identity,
            destination,
            display_name,
            stamp_cost,
        })
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn destination(&self) -> &Destination {
        &self.destination
    }

    pub fn destination_hash(&self) -> [u8; 16] {
        self.destination.hash
    }

    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    pub fn stamp_cost(&self) -> Option<u8> {
        self.stamp_cost
    }

    /// LXMF delivery announce application data.
    pub fn announce_app_data(&self) -> Vec<u8> {
        get_announce_app_data(self.display_name(), self.stamp_cost)
    }

    /// Construct a complete Reticulum announce packet ready for transport.
    pub fn announce_packet(&mut self, now: f64) -> Result<Vec<u8>, ApplicationError> {
        let app_data = self.announce_app_data();
        Ok(self.destination.announce_packet(
            &self.identity,
            Some(&app_data),
            None,
            false,
            None,
            now,
        )?)
    }

    /// Create and sign an outbound LXMF message from this identity.
    pub fn message(
        &self,
        destination_hash: [u8; 16],
        title: &str,
        content: &str,
        method: DeliveryMethod,
    ) -> Result<LxMessage, ApplicationError> {
        let mut message = LxMessage::new(
            destination_hash,
            self.destination_hash(),
            title,
            content,
            method,
        );
        let signing_key = self
            .identity
            .get_signing_key()
            .ok_or(ApplicationError::MissingSigningKey)?;
        message.sign(&signing_key)?;
        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::parse_announce_app_data;

    #[test]
    fn delivery_identity_builds_announce_and_signed_message() {
        let mut local =
            DeliveryIdentity::new(Identity::new(), Some("Example".into()), Some(8)).unwrap();
        let (name, cost) = parse_announce_app_data(&local.announce_app_data()).unwrap();
        assert_eq!(name.as_deref(), Some("Example"));
        assert_eq!(cost, Some(8));
        assert!(!local.announce_packet(1_700_000_000.0).unwrap().is_empty());

        let message = local
            .message([0x22; 16], "Title", "Content", DeliveryMethod::Direct)
            .unwrap();
        assert!(message.signature.is_some());
        assert!(message.hash.is_some());
        assert_eq!(message.source_hash, local.destination_hash());
    }
}
