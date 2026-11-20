use crate::hash::HashValue;
use crate::trustanchorid::TrustAnchorId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    P256Sha256,
    Ed25519,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CosignError(pub String);

impl std::fmt::Display for CosignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for CosignError {}

fn err(msg: impl Into<String>) -> CosignError {
    CosignError(msg.into())
}

/// Marshals a CosignedSubtree input (§5.3.1) in the TLS presentation
/// language, matching the Go reference's `cryptobyte` builder byte for byte:
///
///   "subtree/v1\n\0" || cosigner_name<1..2^8-1> || timestamp(u64, 0 here)
///     || log_origin<1..2^8-1> || start(u64) || end(u64) || subtree_hash(32)
fn marshal_cosigned_subtree(
    cosigner_id: &TrustAnchorId,
    log_id: &TrustAnchorId,
    start: u64,
    end: u64,
    subtree_hash: &HashValue,
) -> Result<Vec<u8>, CosignError> {
    let cosigner_name = cosigner_id
        .oid_name()
        .map_err(|e| err(format!("cosigner ID: {e}")))?;
    let log_origin = log_id.oid_name().map_err(|e| err(format!("log ID: {e}")))?;

    if cosigner_name.len() > u8::MAX as usize || log_origin.len() > u8::MAX as usize {
        return Err(err("OID name too long for 1-byte length prefix"));
    }

    let mut b = Vec::new();
    b.extend_from_slice(b"subtree/v1\n\x00");
    b.push(cosigner_name.len() as u8);
    b.extend_from_slice(cosigner_name.as_bytes());
    b.extend_from_slice(&0u64.to_be_bytes()); // timestamp, zero for certificate use
    b.push(log_origin.len() as u8);
    b.extend_from_slice(log_origin.as_bytes());
    b.extend_from_slice(&start.to_be_bytes());
    b.extend_from_slice(&end.to_be_bytes());
    b.extend_from_slice(subtree_hash);
    Ok(b)
}

/// Verifies a cosignature over a subtree (§5.3), independent of the Go
/// reference: this recomputes the signed input from scratch and verifies it
/// with this crate's own ECDSA/Ed25519 code.
pub fn verify_cosignature(
    cosigner_id: &TrustAnchorId,
    log_id: &TrustAnchorId,
    start: u64,
    end: u64,
    subtree_hash: &HashValue,
    alg: SignatureAlgorithm,
    public_key: &[u8],
    signature: &[u8],
) -> Result<(), CosignError> {
    let input = marshal_cosigned_subtree(cosigner_id, log_id, start, end, subtree_hash)?;

    match alg {
        SignatureAlgorithm::P256Sha256 => {
            use p256::ecdsa::signature::Verifier;
            use p256::ecdsa::{Signature, VerifyingKey};

            let vk = VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|e| err(format!("invalid P-256 public key: {e}")))?;
            let sig = Signature::from_der(signature)
                .map_err(|e| err(format!("invalid P-256 DER signature: {e}")))?;
            vk.verify(&input, &sig)
                .map_err(|_| err("ECDSA P-256 signature verification failed"))
        }
        SignatureAlgorithm::Ed25519 => {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};

            let pk_bytes: [u8; 32] = public_key
                .try_into()
                .map_err(|_| err("invalid Ed25519 public key length"))?;
            let vk = VerifyingKey::from_bytes(&pk_bytes)
                .map_err(|e| err(format!("invalid Ed25519 public key: {e}")))?;
            let sig_bytes: [u8; 64] = signature
                .try_into()
                .map_err(|_| err("invalid Ed25519 signature length"))?;
            let sig = Signature::from_bytes(&sig_bytes);
            vk.verify(&input, &sig)
                .map_err(|_| err("Ed25519 signature verification failed"))
        }
    }
}
