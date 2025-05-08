use crate::Result;
use ring::{
    rand::SystemRandom,
    signature::{self, KeyPair as RingKeyPair},
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};

pub fn generate_classical_keypair() -> Result<(Vec<u8>, Vec<u8>)> {
    let rng = SystemRandom::new();
    
    // Generate Ed25519 key pair
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);
    
    // Generate X25519 key pair
    let x25519_secret = StaticSecret::random_from_rng(&mut rand::rngs::OsRng);
    let x25519_public = X25519PublicKey::from(&x25519_secret);
    
    // Combine the keys
    let mut public_key = Vec::new();
    public_key.extend_from_slice(verifying_key.as_bytes());
    public_key.extend_from_slice(x25519_public.as_bytes());
    
    let mut private_key = Vec::new();
    private_key.extend_from_slice(signing_key.to_bytes().as_ref());
    private_key.extend_from_slice(x25519_secret.to_bytes().as_ref());
    
    Ok((public_key, private_key))
}

pub fn sign(message: &[u8], private_key: &[u8]) -> Result<Vec<u8>> {
    // Extract Ed25519 private key
    let ed25519_private = &private_key[..32];
    let signing_key = SigningKey::from_bytes(ed25519_private.try_into().unwrap());
    
    // Sign the message
    let signature = signing_key.sign(message);
    
    Ok(signature.to_bytes().to_vec())
}

pub fn verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    // Extract Ed25519 public key
    let ed25519_public = &public_key[..32];
    let verifying_key = VerifyingKey::from_bytes(ed25519_public.try_into().unwrap())?;
    
    // Verify the signature
    let signature = ed25519_dalek::Signature::from_bytes(signature.try_into().unwrap())?;
    Ok(verifying_key.verify(message, &signature).is_ok())
}

pub fn encrypt(message: &[u8], public_key: &[u8]) -> Result<Vec<u8>> {
    // Extract X25519 public key
    let x25519_public = &public_key[32..];
    let x25519_public = X25519PublicKey::from(x25519_public.try_into().unwrap());
    
    // Generate ephemeral key pair
    let ephemeral_secret = StaticSecret::random_from_rng(&mut rand::rngs::OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
    
    // Perform key exchange
    let shared_secret = ephemeral_secret.diffie_hellman(&x25519_public);
    
    // Use the shared secret to encrypt the message with AES-GCM
    let mut cipher = aes_gcm::Aes256Gcm::new_from_slice(shared_secret.as_bytes())?;
    let nonce = aes_gcm::Nonce::from_slice(&[0u8; 12]);
    
    let ciphertext = cipher.encrypt(nonce, message)?;
    
    // Combine ephemeral public key and ciphertext
    let mut result = Vec::new();
    result.extend_from_slice(ephemeral_public.as_bytes());
    result.extend_from_slice(&ciphertext);
    
    Ok(result)
}

pub fn decrypt(ciphertext: &[u8], private_key: &[u8]) -> Result<Vec<u8>> {
    // Extract X25519 private key
    let x25519_private = &private_key[32..];
    let x25519_private = StaticSecret::from(x25519_private.try_into().unwrap());
    
    // Extract ephemeral public key and actual ciphertext
    let ephemeral_public = &ciphertext[..32];
    let ciphertext = &ciphertext[32..];
    
    let ephemeral_public = X25519PublicKey::from(ephemeral_public.try_into().unwrap());
    
    // Perform key exchange
    let shared_secret = x25519_private.diffie_hellman(&ephemeral_public);
    
    // Decrypt the message
    let mut cipher = aes_gcm::Aes256Gcm::new_from_slice(shared_secret.as_bytes())?;
    let nonce = aes_gcm::Nonce::from_slice(&[0u8; 12]);
    
    let plaintext = cipher.decrypt(nonce, ciphertext)?;
    
    Ok(plaintext)
} 