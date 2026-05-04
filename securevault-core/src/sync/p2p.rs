//! P2P Implementation

use super::{SyncConfig, SyncPeer, SyncMessage, SyncMessageType, SyncStatus, SyncEvent};
use crate::error::{Error, Result};
use crate::crypto::{self, chacha20};
use crate::securemem::{SecureVec, SecureZeroize};

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// P2P Sync Manager with secure session key handling
pub struct P2PSync {
    config: SyncConfig,
    status: SyncStatus,
    peers: Arc<RwLock<HashMap<String, SyncPeer>>>,
    /// Session key - automatically zeroized on drop
    session_key: Option<SecureVec>,
    device_id: String,
}

impl P2PSync {
    /// Create new P2P sync instance
    pub fn new(config: SyncConfig) -> Self {
        let device_id = format!("pq-vault-{}", uuid::Uuid::new_v4());
        
        Self {
            config,
            status: SyncStatus::Idle,
            peers: Arc::new(RwLock::new(HashMap::new())),
            session_key: None,
            device_id,
        }
    }

    /// Start discovery
    pub fn start_discovery(&mut self) -> Result<()> {
        self.status = SyncStatus::Discovering;
        
        // In production, would start UDP broadcast listener
        // For now, just set status
        Ok(())
    }

    /// Stop discovery
    pub fn stop_discovery(&mut self) -> Result<()> {
        self.status = SyncStatus::Idle;
        Ok(())
    }

    /// Generate discovery packet
    pub fn generate_discovery_packet(&self) -> Result<Vec<u8>> {
        #[derive(serde::Serialize)]
        struct DiscoveryPacket {
            device_id: String,
            device_name: String,
            version: String,
            capabilities: Vec<String>,
        }
        
        let packet = DiscoveryPacket {
            device_id: self.device_id.clone(),
            device_name: "PQ Vault Device".to_string(),
            version: "1.0.0".to_string(),
            capabilities: vec!["sync".to_string(), "pq-encryption".to_string()],
        };
        
        Ok(serde_json::to_vec(&packet)?)
    }

    /// Parse discovery packet
    pub fn parse_discovery_packet(data: &[u8]) -> Result<SyncPeer> {
        #[derive(serde::Deserialize)]
        struct DiscoveryPacket {
            device_id: String,
            device_name: String,
            version: String,
            capabilities: Vec<String>,
        }
        
        let packet: DiscoveryPacket = serde_json::from_slice(data)?;
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Ok(SyncPeer {
            id: packet.device_id,
            name: packet.device_name,
            address: String::new(), // Will be set from socket
            port: 0, // Will be set from socket
            last_seen: now,
            capabilities: packet.capabilities,
        })
    }

    /// Connect to peer
    pub fn connect_to_peer(&mut self, peer: &SyncPeer) -> Result<()> {
        self.status = SyncStatus::Connecting;
        
        // Generate session key for this peer
        let session_key = crypto::generate_key()?;
        self.session_key = Some(SecureVec::new(session_key));
        
        self.status = SyncStatus::Connected;
        
        Ok(())
    }

    /// Disconnect from peer
    pub fn disconnect(&mut self) -> Result<()> {
        // Clear session key securely - SecureVec will zeroize on drop
        if let Some(ref mut key) = self.session_key {
            key.secure_zero();
        }
        self.session_key = None;
        self.status = SyncStatus::Idle;
        Ok(())
    }

    /// Create sync message
    pub fn create_message(&self, msg_type: SyncMessageType, payload: Vec<u8>) -> Result<SyncMessage> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Ok(SyncMessage {
            msg_type,
            peer_id: self.device_id.clone(),
            timestamp: now,
            payload,
        })
    }

    /// Encrypt sync message
    pub fn encrypt_message(&self, message: &SyncMessage) -> Result<Vec<u8>> {
        let key = self.session_key.as_ref()
            .ok_or(Error::Sync("No session key".to_string()))?;
        
        let key_slice = key.as_slice();
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(key_slice);
        
        let json = serde_json::to_vec(message)?;
        
        // Generate nonce
        let nonce = crypto::rng::generate_nonce_12()?;
        
        let encrypted = chacha20::encrypt_chacha20poly1305(&json, &key_arr, &nonce)?;
        
        // Combine nonce + encrypted
        let mut result = nonce.to_vec();
        result.extend(encrypted);
        
        Ok(result)
    }

    /// Decrypt sync message
    pub fn decrypt_message(&self, data: &[u8]) -> Result<SyncMessage> {
        if data.len() < 12 {
            return Err(Error::Sync("Data too short".to_string()));
        }
        
        let key = self.session_key.as_ref()
            .ok_or(Error::Sync("No session key".to_string()))?;
        
        let key_slice = key.as_slice();
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(key_slice);
        
        // Extract nonce from the beginning of the encrypted data
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(&data[..12]);
        
        let decrypted = chacha20::decrypt_chacha20poly1305(&data[12..], &key_arr, &nonce_arr)?;
        
        let message: SyncMessage = serde_json::from_slice(&decrypted)?;
        
        Ok(message)
    }

    /// Get current status
    pub fn status(&self) -> &SyncStatus {
        &self.status
    }

    /// Get connected peers
    pub fn get_peers(&self) -> Vec<SyncPeer> {
        self.peers.read().unwrap().values().cloned().collect()
    }

    /// Add peer
    pub fn add_peer(&self, peer: SyncPeer) -> Result<()> {
        self.peers.write().unwrap().insert(peer.id.clone(), peer);
        Ok(())
    }

    /// Remove peer
    pub fn remove_peer(&self, peer_id: &str) -> Result<()> {
        self.peers.write().unwrap().remove(peer_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_sync() {
        let sync = P2PSync::new(SyncConfig::default());
        
        assert!(matches!(sync.status(), SyncStatus::Idle));
    }

    #[test]
    fn test_discovery_packet() {
        let sync = P2PSync::new(SyncConfig::default());
        
        let packet = sync.generate_discovery_packet().unwrap();
        
        assert!(!packet.is_empty());
    }

    #[test]
    fn test_message_creation() {
        let sync = P2PSync::new(SyncConfig::default());
        
        let msg = sync.create_message(
            SyncMessageType::Ping,
            vec![1, 2, 3],
        ).unwrap();
        
        assert_eq!(msg.msg_type, SyncMessageType::Ping);
    }

    #[test]
    fn test_peer_management() {
        let sync = P2PSync::new(SyncConfig::default());
        
        let peer = SyncPeer {
            id: "peer1".to_string(),
            name: "Test".to_string(),
            address: "192.168.1.1".to_string(),
            port: 45679,
            last_seen: 123456,
            capabilities: vec![],
        };
        
        sync.add_peer(peer.clone()).unwrap();
        
        let peers = sync.get_peers();
        
        assert_eq!(peers.len(), 1);
    }
}