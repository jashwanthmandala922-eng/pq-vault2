//! P2P Synchronization Module
//!
//! Local network peer-to-peer synchronization for PQ-Vault

pub mod p2p;

pub use p2p::{P2PSync, SyncMessage, SyncPeer, SyncConfig};

use serde::{Deserialize, Serialize};

/// Sync status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncStatus {
    Idle,
    Discovering,
    Connecting,
    Syncing,
    Connected,
    Error(String),
}

/// Sync event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncEvent {
    PeerFound(SyncPeer),
    PeerConnected(SyncPeer),
    SyncStarted,
    SyncProgress(u8),
    SyncComplete,
    PeerDisconnected(SyncPeer),
    Error(String),
}

/// Sync configuration
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// UDP discovery port
    pub discovery_port: u16,
    /// TCP sync port
    pub sync_port: u16,
    /// Discovery interval (seconds)
    pub discovery_interval: u64,
    /// Peer timeout (seconds)
    pub peer_timeout: u64,
    /// Auto-sync on change
    pub auto_sync: bool,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            discovery_port: 45678,
            sync_port: 45679,
            discovery_interval: 5,
            peer_timeout: 30,
            auto_sync: true,
        }
    }
}

/// Sync peer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncPeer {
    pub id: String,
    pub name: String,
    pub address: String,
    pub port: u16,
    pub last_seen: u64,
    pub capabilities: Vec<String>,
}

/// Sync message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncMessageType {
    Ping,
    Pong,
    Discovery,
    ConnectRequest,
    ConnectResponse,
    SyncRequest,
    SyncResponse,
    EntryUpdate,
    EntryDelete,
    SyncComplete,
}

/// Sync message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncMessage {
    pub msg_type: SyncMessageType,
    pub peer_id: String,
    pub timestamp: u64,
    pub payload: Vec<u8>,
}

/// Sync entry (for transfer)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncEntry {
    pub id: String,
    pub operation: SyncOperation,
    pub data: Vec<u8>,
}

/// Sync operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncOperation {
    Create,
    Update,
    Delete,
}

impl SyncConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_ports(discovery: u16, sync: u16) -> Self {
        Self {
            discovery_port: discovery,
            sync_port: sync,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_config_default() {
        let config = SyncConfig::default();
        
        assert_eq!(config.discovery_port, 45678);
        assert_eq!(config.sync_port, 45679);
    }

    #[test]
    fn test_sync_config_with_ports() {
        let config = SyncConfig::with_ports(50000, 50001);
        
        assert_eq!(config.discovery_port, 50000);
        assert_eq!(config.sync_port, 50001);
    }

    #[test]
    fn test_sync_peer() {
        let peer = SyncPeer {
            id: "test-peer-1".to_string(),
            name: "Test Device".to_string(),
            address: "192.168.1.100".to_string(),
            port: 45679,
            last_seen: 1234567890,
            capabilities: vec!["sync".to_string()],
        };
        
        assert_eq!(peer.id, "test-peer-1");
    }
}