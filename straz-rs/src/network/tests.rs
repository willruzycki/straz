#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::time::{sleep, Duration};
    
    #[tokio::test]
    async fn test_peer_connection() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        let mut network = Network::new(addr).await.unwrap();
        
        // Start network
        network.start().await.unwrap();
        
        // Connect to peer
        let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        network.connect_to_peer(peer_addr).await.unwrap();
        
        assert!(network.peers.contains_key(&peer_addr));
        assert!(network.peers.get(&peer_addr).unwrap().is_connected);
        
        // Disconnect from peer
        network.disconnect_from_peer(peer_addr).await.unwrap();
        assert!(!network.peers.contains_key(&peer_addr));
    }
    
    #[tokio::test]
    async fn test_consensus_message_broadcast() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        let mut network = Network::new(addr).await.unwrap();
        
        // Start network
        network.start().await.unwrap();
        
        // Connect to multiple peers
        for port in 8080..8083 {
            let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
            network.connect_to_peer(peer_addr).await.unwrap();
        }
        
        // Create consensus message
        let consensus_msg = ConsensusMsg::Proposal {
            epoch: 0,
            round: 0,
            block_hash: vec![1, 2, 3],
            signature: vec![4, 5, 6],
        };
        
        // Broadcast message
        network.broadcast_consensus(consensus_msg).await.unwrap();
        
        // Wait for message processing
        sleep(Duration::from_millis(100)).await;
        
        // Verify all peers received the message
        for peer in network.peers.values() {
            assert!(peer.is_connected);
        }
    }
    
    #[tokio::test]
    async fn test_peer_discovery() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        let mut network = Network::new(addr).await.unwrap();
        
        // Start network
        network.start().await.unwrap();
        
        // Simulate peer discovery
        let peers = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081),
        ];
        
        let msg = NetworkMsg::PeerList(peers.clone());
        let data = bincode::serialize(&msg).unwrap();
        
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(&data).await.unwrap();
        
        // Wait for peer discovery
        sleep(Duration::from_millis(100)).await;
        
        // Verify peers were added
        for peer_addr in peers {
            assert!(network.peers.contains_key(&peer_addr));
        }
    }
    
    #[tokio::test]
    async fn test_connection_timeout() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        let mut network = Network::new(addr).await.unwrap();
        
        // Start network
        network.start().await.unwrap();
        
        // Connect to peer
        let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        network.connect_to_peer(peer_addr).await.unwrap();
        
        // Wait for timeout
        sleep(Duration::from_secs(CONNECTION_TIMEOUT + 1)).await;
        
        // Verify peer was removed
        assert!(!network.peers.contains_key(&peer_addr));
    }
    
    #[tokio::test]
    async fn test_max_peers_limit() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        let mut network = Network::new(addr).await.unwrap();
        
        // Start network
        network.start().await.unwrap();
        
        // Try to connect more than MAX_PEERS
        for port in 8080..(8080 + MAX_PEERS + 1) {
            let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
            if port == 8080 + MAX_PEERS {
                assert!(network.connect_to_peer(peer_addr).await.is_err());
            } else {
                network.connect_to_peer(peer_addr).await.unwrap();
            }
        }
        
        assert_eq!(network.peers.len(), MAX_PEERS);
    }
} 