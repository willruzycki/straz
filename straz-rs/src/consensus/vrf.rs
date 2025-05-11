use crate::Result;
use crate::crypto::KeyPair;
use sha3::{Keccak256, Digest};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct VRFOutput {
    pub proof: Vec<u8>,
    pub value: Vec<u8>,
}

pub struct VRF {
    keypair: KeyPair,
    outputs: HashMap<(u64, u64), VRFOutput>, // (epoch, round) -> output
}

impl VRF {
    pub fn new(keypair: KeyPair) -> Self {
        Self {
            keypair,
            outputs: HashMap::new(),
        }
    }
    
    pub fn generate_proof(&mut self, epoch: u64, round: u64) -> Result<VRFOutput> {
        // Create input from epoch and round
        let mut input = Vec::new();
        input.extend_from_slice(&epoch.to_be_bytes());
        input.extend_from_slice(&round.to_be_bytes());
        
        // Sign the input
        let signature = self.keypair.sign(&input)?;
        
        // Use signature as VRF proof
        let proof = signature;
        
        // Generate VRF value using Keccak256
        let mut hasher = Keccak256::new();
        hasher.update(&proof);
        let value = hasher.finalize().to_vec();
        
        let output = VRFOutput {
            proof,
            value,
        };
        
        // Store output
        self.outputs.insert((epoch, round), output.clone());
        
        Ok(output)
    }
    
    pub fn verify_proof(
        &self,
        epoch: u64,
        round: u64,
        validator_pubkey: &[u8],
        proof: &[u8],
        value: &[u8],
    ) -> Result<bool> {
        // Create input from epoch and round
        let mut input = Vec::new();
        input.extend_from_slice(&epoch.to_be_bytes());
        input.extend_from_slice(&round.to_be_bytes());
        
        // Verify signature
        let keypair = KeyPair::from_public_key(validator_pubkey)?;
        if !keypair.verify(&input, proof)? {
            return Ok(false);
        }
        
        // Verify VRF value
        let mut hasher = Keccak256::new();
        hasher.update(proof);
        let expected_value = hasher.finalize().to_vec();
        
        Ok(value == expected_value)
    }
    
    pub fn get_proposer(
        &self,
        epoch: u64,
        round: u64,
        validators: &[(Vec<u8>, u128)], // (pubkey, stake)
        total_stake: u128,
    ) -> Result<Vec<u8>> {
        // Get VRF output for this epoch/round
        let output = self.outputs.get(&(epoch, round))
            .ok_or_else(|| crate::StrazError::Consensus("VRF output not found".into()))?;
        
        // Convert VRF value to u128
        let mut value_bytes = [0u8; 16];
        value_bytes.copy_from_slice(&output.value[..16]);
        let value = u128::from_be_bytes(value_bytes);
        
        // Select proposer based on stake-weighted probability
        let mut cumulative_stake = 0u128;
        for (pubkey, stake) in validators {
            cumulative_stake += stake;
            if value % total_stake < cumulative_stake {
                return Ok(pubkey.clone());
            }
        }
        
        // Fallback to first validator (should never happen)
        Ok(validators[0].0.clone())
    }
    
    pub fn get_output(&self, epoch: u64, round: u64) -> Option<&VRFOutput> {
        self.outputs.get(&(epoch, round))
    }
} 