use crate::Result;
use crate::consensus::types::ConsensusMsg;
use tokio::sync::mpsc;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Serialize, Deserialize};

pub const MAX_PEERS: usize = 50;
pub const PING_INTERVAL: u64 = 30; // seconds
pub const CONNECTION_TIMEOUT: u64 = 60; // seconds

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMsg {
    Consensus(ConsensusMsg),
    Ping,
    Pong,
    PeerList(Vec<SocketAddr>),
    Connect(SocketAddr),
    Disconnect(SocketAddr),
}

#[derive(Debug)]
pub struct Peer {
    pub address: SocketAddr,
    pub last_seen: u64,
    pub is_connected: bool,
}

pub struct Network {
    peers: HashMap<SocketAddr, Peer>,
    listener: TcpListener,
    consensus_tx: mpsc::Sender<ConsensusMsg>,
    consensus_rx: mpsc::Receiver<ConsensusMsg>,
}

impl Network {
    pub async fn new(addr: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let (consensus_tx, consensus_rx) = mpsc::channel(100);
        
        Ok(Self {
            peers: HashMap::new(),
            listener,
            consensus_tx,
            consensus_rx,
        })
    }
    
    pub async fn start(&mut self) -> Result<()> {
        // Start listening for incoming connections
        tokio::spawn(async move {
            while let Ok((stream, addr)) = self.listener.accept().await {
                self.handle_connection(stream, addr).await?;
            }
            Ok::<(), crate::StrazError>(())
        });
        
        // Start peer discovery
        tokio::spawn(async move {
            self.discover_peers().await?;
            Ok::<(), crate::StrazError>(())
        });
        
        // Start message handling
        tokio::spawn(async move {
            self.handle_messages().await?;
            Ok::<(), crate::StrazError>(())
        });
        
        Ok(())
    }
    
    async fn handle_connection(&mut self, mut stream: TcpStream, addr: SocketAddr) -> Result<()> {
        let mut buffer = vec![0; 1024];
        let n = stream.read(&mut buffer).await?;
        
        if n == 0 {
            return Ok(());
        }
        
        let msg: NetworkMsg = bincode::deserialize(&buffer[..n])?;
        
        match msg {
            NetworkMsg::Connect(peer_addr) => {
                if self.peers.len() < MAX_PEERS {
                    self.peers.insert(peer_addr, Peer {
                        address: peer_addr,
                        last_seen: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                        is_connected: true,
                    });
                }
            }
            NetworkMsg::Disconnect(peer_addr) => {
                self.peers.remove(&peer_addr);
            }
            NetworkMsg::Consensus(msg) => {
                self.consensus_tx.send(msg).await?;
            }
            NetworkMsg::Ping => {
                let response = NetworkMsg::Pong;
                let data = bincode::serialize(&response)?;
                stream.write_all(&data).await?;
            }
            NetworkMsg::Pong => {
                if let Some(peer) = self.peers.get_mut(&addr) {
                    peer.last_seen = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                }
            }
            NetworkMsg::PeerList(peers) => {
                for peer_addr in peers {
                    if self.peers.len() < MAX_PEERS {
                        self.peers.insert(peer_addr, Peer {
                            address: peer_addr,
                            last_seen: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs(),
                            is_connected: false,
                        });
                    }
                }
            }
        }
        
        Ok(())
    }
    
    async fn discover_peers(&mut self) -> Result<()> {
        // Implement peer discovery logic (e.g., using a seed node or DHT)
        Ok(())
    }
    
    async fn handle_messages(&mut self) -> Result<()> {
        while let Some(msg) = self.consensus_rx.recv().await {
            // Broadcast consensus messages to all peers
            self.broadcast_consensus(msg).await?;
        }
        Ok(())
    }
    
    pub async fn broadcast_consensus(&self, msg: ConsensusMsg) -> Result<()> {
        let network_msg = NetworkMsg::Consensus(msg);
        let data = bincode::serialize(&network_msg)?;
        
        for peer in self.peers.values() {
            if peer.is_connected {
                if let Ok(mut stream) = TcpStream::connect(peer.address).await {
                    stream.write_all(&data).await?;
                }
            }
        }
        
        Ok(())
    }
    
    pub async fn connect_to_peer(&mut self, addr: SocketAddr) -> Result<()> {
        if self.peers.len() >= MAX_PEERS {
            return Err(crate::StrazError::Network("Maximum peer limit reached".into()));
        }
        
        let mut stream = TcpStream::connect(addr).await?;
        let msg = NetworkMsg::Connect(addr);
        let data = bincode::serialize(&msg)?;
        stream.write_all(&data).await?;
        
        self.peers.insert(addr, Peer {
            address: addr,
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            is_connected: true,
        });
        
        Ok(())
    }
    
    pub async fn disconnect_from_peer(&mut self, addr: SocketAddr) -> Result<()> {
        if let Some(peer) = self.peers.get(&addr) {
            if peer.is_connected {
                let mut stream = TcpStream::connect(addr).await?;
                let msg = NetworkMsg::Disconnect(addr);
                let data = bincode::serialize(&msg)?;
                stream.write_all(&data).await?;
            }
        }
        
        self.peers.remove(&addr);
        Ok(())
    }
} 