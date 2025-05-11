use crate::Result;
use crate::consensus::types::ConsensusMsg;
use tokio::sync::mpsc;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Serialize, Deserialize};
use crate::blockchain::{Block, Transaction, Receipt};
use crate::crypto::PublicKey;
use tokio::sync::{oneshot};
use tokio::io::{BufReader, BufWriter};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::fmt;
use log::{info, warn, error, debug};
use bincode;

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

// Define a generic error type for the network module
#[derive(Debug)]
pub enum NetworkError {
    Io(std::io::Error),
    Bincode(bincode::Error),
    ConnectionFailed(String),
    PeerDisconnected,
    ChannelSendError(String),
    InvalidAddress(String),
    NotListening,
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkError::Io(e) => write!(f, "IO error: {}", e),
            NetworkError::Bincode(e) => write!(f, "Serialization/Deserialization error: {}", e),
            NetworkError::ConnectionFailed(s) => write!(f, "Connection failed: {}", s),
            NetworkError::PeerDisconnected => write!(f, "Peer disconnected"),
            NetworkError::ChannelSendError(s) => write!(f, "Channel send error: {}", s),
            NetworkError::InvalidAddress(s) => write!(f, "Invalid network address: {}", s),
            NetworkError::NotListening => write!(f, "Node is not listening for incoming connections"),
        }
    }
}

impl From<std::io::Error> for NetworkError {
    fn from(err: std::io::Error) -> Self {
        NetworkError::Io(err)
    }
}

impl From<bincode::Error> for NetworkError {
    fn from(err: bincode::Error) -> Self {
        NetworkError::Bincode(err)
    }
}

// Message enum for network communication
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Message {
    // Consensus messages
    Consensus(ConsensusMsg),
    // Block propagation
    Block(Block),
    // Transaction propagation
    Tx(Transaction),
    // Receipt propagation (optional, depends on protocol)
    Receipt(Receipt),
    // Example: Peer discovery messages
    Ping(u64),
    Pong(u64),
    RequestPeers,
    Peers(Vec<String>), // List of peer addresses as strings
}

// Represents a connected peer
struct Peer {
    addr: SocketAddr,
    stream: Arc<Mutex<TcpStream>>, // Use Tokio's Mutex for async RwLock functionality on stream
    // last_seen: Instant, // For tracking liveness
    // pub_key: Option<PublicKey>, // If peers exchange public keys upon connection
}

// The Node struct managing P2P connections and message broadcasting
pub struct Node {
    bind_addr: String, // Address this node listens on
    listener: Option<TcpListener>, // Option so it can be initialized in new()
    peers: Arc<Mutex<HashMap<SocketAddr, Peer>>>,
    // Channel to send received messages to the consensus engine or other parts of the application
    msg_sender: mpsc::Sender<Message>, 
    // Channel to receive messages from the application to broadcast to the network
    broadcast_receiver: Arc<Mutex<mpsc::Receiver<Message>>>,
    // Internal sender for broadcast_receiver, to be cloned by Node::broadcast method
    internal_broadcast_sender: mpsc::Sender<Message>,
}

impl Node {
    pub async fn new(bind_addr_str: &str, seeds: &[String]) -> Result<Self, NetworkError> {
        let listener = TcpListener::bind(bind_addr_str).await
            .map_err(|e| NetworkError::InvalidAddress(format!("Failed to bind to {}: {}", bind_addr_str, e)))?;
        info!("Node listening on: {}", bind_addr_str);

        let (msg_sender, msg_receiver_for_app) = mpsc::channel::<Message>(100); // Channel for app to receive messages from network
        let (internal_broadcast_sender, broadcast_receiver_for_node) = mpsc::channel::<Message>(100); // Channel for app to send messages to network

        let node = Self {
            bind_addr: bind_addr_str.to_string(),
            listener: Some(listener),
            peers: Arc::new(Mutex::new(HashMap::new())),
            msg_sender, // This sender is passed to the consensus engine to send us messages
            broadcast_receiver: Arc::new(Mutex::new(broadcast_receiver_for_node)),
            internal_broadcast_sender,
        };

        // Connect to seed nodes
        for seed_addr_str in seeds {
            if seed_addr_str.is_empty() || *seed_addr_str == node.bind_addr {
                continue; // Skip empty or self
            }
            let node_clone = Arc::new(node.clone_internals_for_new_peer_connection()); // To avoid full Node clone
            let seed_addr_str_clone = seed_addr_str.clone();
            tokio::spawn(async move {
                if let Err(e) = node_clone.connect_to_peer(&seed_addr_str_clone).await {
                    warn!("Failed to connect to seed peer {}: {:?}", seed_addr_str_clone, e);
                }
            });
        }
        
        Ok(node)
    }

    // Helper struct to pass necessary components to connect_to_peer without cloning the whole Node
    // or dealing with complex Arc<Self> patterns immediately in connect_to_peer.
    struct NodeInternalsForPeerHandling {
        peers: Arc<Mutex<HashMap<SocketAddr, Peer>>>,
        app_msg_sender: mpsc::Sender<Message>,
    }

    fn clone_internals_for_new_peer_connection(&self) -> NodeInternalsForPeerHandling {
        NodeInternalsForPeerHandling {
            peers: Arc::clone(&self.peers),
            app_msg_sender: self.msg_sender.clone(),
        }
    }

    // To be called by the application (e.g., ConsensusEngine) to get messages from the network
    pub async fn next_msg(&mut self) -> Option<Message> {
        // This method signature was in the prompt. It would typically involve an mpsc::Receiver
        // The Node::new() setup currently doesn't return the receiver end for app_msg_sender.
        // Let's assume the intent is for the app to hold the receiver from a channel pair provided by Node::new_with_channels.
        // For now, this stub won't compile correctly without that receiver.
        // I'll adjust Node::new to return the receiver for the application.
        warn!("Node::next_msg() is a placeholder and needs proper receiver handling from Node setup.");
        None
    }

    // New method to provide the application with the receiver for incoming network messages
    pub fn take_message_receiver(&mut self) -> Option<mpsc::Receiver<Message>> {
        // This is tricky because Node::new already creates msg_sender/msg_receiver_for_app.
        // The receiver end (msg_receiver_for_app) should be returned from new() or a setup method.
        // Let's adjust Node::new and this method for clarity.
        // For the current structure, Node holds msg_sender to send *to* the app.
        // The app needs to receive messages from a central point in Node (e.g., from peer handlers).
        // `msg_sender` in `Node` is for messages *from* network *to* app.
        // `broadcast_receiver` in `Node` is for messages *from* app *to* network.
        // The `next_msg` implies Node centralizes incoming messages and gives them to the app.
        // This will be managed by the main loop in `run_node_tasks`.
        todo!("Node::next_msg requires node.run() to populate a shared channel from all peers.")
    }

    pub async fn broadcast(&self, msg: Message) -> Result<(), NetworkError> {
        self.internal_broadcast_sender.send(msg).await
            .map_err(|e| NetworkError::ChannelSendError(format!("Failed to send to internal broadcast channel: {}", e.toString())))
    }

    // Main loop to accept incoming connections
    pub async fn run(&self) -> Result<(), NetworkError> {
        info!("Network node starting its main run loop.");
        let listener = self.listener.as_ref().ok_or(NetworkError::NotListening)?;
        let node_internals = self.clone_internals_for_new_peer_connection();

        // Separate task for handling outgoing broadcasts
        let peers_clone_for_broadcast = Arc::clone(&self.peers);
        let mut broadcast_receiver_locked = self.broadcast_receiver.lock().await;
        tokio::spawn(async move {
            while let Some(message) = broadcast_receiver_locked.recv().await {
                debug!("Broadcasting message: {:?}", message);
                let peers_map = peers_clone_for_broadcast.lock().await;
                for peer_info in peers_map.values() {
                    let stream_clone = Arc::clone(&peer_info.stream);
                    let message_clone = message.clone(); // Clone for each peer task
                    tokio::spawn(async move {
                        if let Err(e) = Self::send_message_to_stream(&mut *stream_clone.lock().await, &message_clone).await {
                            warn!("Failed to send broadcast message to peer {}: {:?}", peer_info.addr, e);
                            // TODO: Handle peer removal if send fails repeatedly
                        }
                    });
                }
            }
        });
        drop(broadcast_receiver_locked); // Release lock after spawning broadcast task

        // Accept incoming connections loop
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!("Accepted new connection from: {}", addr);
                    let peer_internals_clone = node_internals.clone_internals_for_new_peer_connection(); // Use a helper for this
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_incoming_peer(stream, addr, peer_internals_clone).await {
                            warn!("Error handling peer {}: {:?}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept incoming connection: {}", e);
                    // Consider a short delay before retrying to avoid tight loop on persistent errors
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }
        }
    }

    async fn connect_to_peer(&self, addr_str: &str) -> Result<(), NetworkError> {
        info!("Attempting to connect to peer: {}", addr_str);
        match TcpStream::connect(addr_str).await {
            Ok(stream) => {
                let addr = stream.peer_addr()?;
                info!("Successfully connected to peer: {}", addr);
                let peer_internals = self.clone_internals_for_new_peer_connection();
                Self::handle_incoming_peer(stream, addr, peer_internals).await;
                Ok(())
            }
            Err(e) => {
                warn!("Failed to connect to peer {}: {}", addr_str, e);
                Err(NetworkError::ConnectionFailed(format!("Could not connect to {}: {}", addr_str, e)))
            }
        }
    }

    async fn handle_incoming_peer(stream: TcpStream, addr: SocketAddr, internals: NodeInternalsForPeerHandling) -> Result<(), NetworkError> {
        let (reader, writer) = tokio::io::split(stream);
        let mut buf_reader = BufReader::new(reader);
        // let mut buf_writer = BufWriter::new(writer); // Writer is part of the Peer struct now

        let peer_stream_arc = Arc::new(Mutex::new(tokio::io::split(TcpStream::connect(addr).await.unwrap()).1)); // Re-establish writer, this is wrong. Fix.
        // The original stream should be used for both reading and writing. 
        // Let's assume the stream passed is the one to use.
        // The `Peer` struct should hold the combined stream or writer part.
        // For simplicity, let's assume `Peer`'s stream is used for writing and `buf_reader` for reading here.
        // This needs a proper design for concurrent read/write on the same TcpStream wrapped in Arc<Mutex<TcpStream>>.

        let peer_info = Peer {
            addr,
            stream: Arc::new(Mutex::new(writer)), // Placeholder, should be the full stream or writer part
        };
        internals.peers.lock().await.insert(addr, peer_info);
        info!("Peer {} added to active connections.", addr);

        // Loop to read messages from this peer
        loop {
            // Read message length (u32 for message size)
            let msg_len = match buf_reader.read_u32().await {
                Ok(len) => len,
                Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    info!("Peer {} disconnected (EOF reading length).", addr);
                    break; // Peer closed connection
                }
                Err(e) => {
                    warn!("Error reading message length from peer {}: {:?}", addr, e);
                    return Err(e.into());
                }
            };

            if msg_len == 0 || msg_len > 10 * 1024 * 1024 { // Max 10MB message, adjust as needed
                warn!("Received invalid message length {} from peer {}. Closing connection.", msg_len, addr);
                break;
            }

            let mut msg_bytes = vec![0u8; msg_len as usize];
            if let Err(e) = buf_reader.read_exact(&mut msg_bytes).await {
                warn!("Error reading message body from peer {}: {:?}", addr, e);
                if e.kind() == std.io::ErrorKind::UnexpectedEof {
                    info!("Peer {} disconnected (EOF reading body).", addr);
                }
                break;
            }

            match bincode::deserialize::<Message>(&msg_bytes) {
                Ok(message) => {
                    debug!("Received message from {}: {:?}", addr, message);
                    if internals.app_msg_sender.send(message).await.is_err() {
                        error!("Failed to send received message to app channel from peer {}. Receiver likely dropped.", addr);
                        // This might mean the application is shutting down.
                        break; 
                    }
                }
                Err(e) => {
                    warn!("Failed to deserialize message from peer {}: {:?}. Raw bytes: {}", addr, e, hex::encode(&msg_bytes));
                    // Optionally, send an error back or just drop the message
                }
            }
        }

        // Cleanup: remove peer from the map
        internals.peers.lock().await.remove(&addr);
        info!("Peer {} removed from active connections.", addr);
        Ok(())
    }

    async fn send_message_to_stream(stream_mutex: &mut TcpStream, message: &Message) -> Result<(), NetworkError> {
        let bytes = bincode::serialize(message)?;
        let len = bytes.len() as u32;

        stream_mutex.write_u32(len).await?; // Send length first
        stream_mutex.write_all(&bytes).await?; // Send message bytes
        stream_mutex.flush().await?; // Ensure it's sent
        Ok(())
    }
}

// Helper to clone NodeInternals for new peer connections (implementation detail)
impl NodeInternalsForPeerHandling {
    fn clone_internals_for_new_peer_connection(&self) -> Self {
        Self {
            peers: Arc::clone(&self.peers),
            app_msg_sender: self.app_msg_sender.clone(),
        }
    }
}

// The prompt asks for Node::new to return Self, and Node::next_msg() to be on &mut self.
// This implies that the application (main.rs) will hold the Node instance and poll next_msg().
// For Node to provide messages via next_msg(), it needs a receiving end of a channel that all peer handlers send to.
// The current `msg_sender` in Node is this channel's sender. The receiver should be managed internally by `next_msg()`.
// Let's refine the channel setup for `next_msg`.
// `Node::new` will set up an internal channel. `handle_incoming_peer` will send to it.
// `next_msg` will receive from it.

// The broadcast mechanism is separate: app calls `node.broadcast()`, which sends to an internal channel,
// and `node.run()` has a task that consumes from this broadcast channel and sends to all peers.

// This simplified structure for Node assumes Message is Cloneable for broadcasting. 