//! Tests for src/cosign.rs and src/trustanchorid.rs. The OID-name test
//! vector (`32473.1` -> `"oid/1.3.6.1.4.1.32473.1"`) is the worked example
//! given directly in §5.3.1 of draft-ietf-plants-merkle-tree-certs-08. The
//! spec gives no worked cryptographic example for cosignatures, so those
//! tests sign with throwaway keys generated here (test-only signing code;
//! the library itself only verifies) and check the library's
//! `verify_cosignature` accepts the result and rejects a tampered one.

use mtc_lake_verifier::cosign::{verify_cosignature, SignatureAlgorithm};
use mtc_lake_verifier::hash::hash_leaf;
use mtc_lake_verifier::trustanchorid::TrustAnchorId;

#[test]
fn oid_name_matches_spec_worked_example() {
    let id = TrustAnchorId::parse("32473.1").unwrap();
    assert_eq!(id.oid_name().unwrap(), "oid/1.3.6.1.4.1.32473.1");
}

#[test]
fn log_and_landmark_ids_round_trip_through_oid_name() {
    let ca = TrustAnchorId::parse("32473.1").unwrap();
    let log = ca.log_id(1);
    assert_eq!(log.oid_name().unwrap(), "oid/1.3.6.1.4.1.32473.1.0.1");

    let landmark = ca.landmark_id(1, 7);
    assert_eq!(
        landmark.oid_name().unwrap(),
        "oid/1.3.6.1.4.1.32473.1.1.1.7"
    );
}

#[test]
fn p256_cosignature_round_trip() {
    use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};

    let signing_key = SigningKey::random(&mut rand::rngs::OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);
    let pub_bytes = verifying_key.to_encoded_point(false);

    let ca = TrustAnchorId::parse("32473.1").unwrap();
    let log_id = ca.log_id(1);
    let cosigner_id = TrustAnchorId::parse("32473.100").unwrap();
    let subtree_hash = hash_leaf(b"root of an 8-entry log");

    let input = sign_input_for_test(&cosigner_id, &log_id, 0, 8, &subtree_hash);
    let sig: Signature = signing_key.sign(&input);

    verify_cosignature(
        &cosigner_id,
        &log_id,
        0,
        8,
        &subtree_hash,
        SignatureAlgorithm::P256Sha256,
        pub_bytes.as_bytes(),
        sig.to_der().as_bytes(),
    )
    .expect("valid P-256 cosignature must verify");

    let mut bad_sig = sig.to_der().as_bytes().to_vec();
    *bad_sig.last_mut().unwrap() ^= 0xff;
    assert!(verify_cosignature(
        &cosigner_id,
        &log_id,
        0,
        8,
        &subtree_hash,
        SignatureAlgorithm::P256Sha256,
        pub_bytes.as_bytes(),
        &bad_sig,
    )
    .is_err());
}

#[test]
fn ed25519_cosignature_round_trip() {
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use rand::RngCore;

    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    let ca = TrustAnchorId::parse("32473.1").unwrap();
    let log_id = ca.log_id(1);
    let cosigner_id = TrustAnchorId::parse("32473.200").unwrap();
    let subtree_hash = hash_leaf(b"root of an 8-entry log");

    let input = sign_input_for_test(&cosigner_id, &log_id, 0, 8, &subtree_hash);
    let sig = signing_key.sign(&input);

    verify_cosignature(
        &cosigner_id,
        &log_id,
        0,
        8,
        &subtree_hash,
        SignatureAlgorithm::Ed25519,
        verifying_key.as_bytes(),
        &sig.to_bytes(),
    )
    .expect("valid Ed25519 cosignature must verify");

    let mut bad_sig = sig.to_bytes();
    bad_sig[63] ^= 0xff;
    assert!(verify_cosignature(
        &cosigner_id,
        &log_id,
        0,
        8,
        &subtree_hash,
        SignatureAlgorithm::Ed25519,
        verifying_key.as_bytes(),
        &bad_sig,
    )
    .is_err());
}

/// Rebuilds the CosignedSubtree input exactly as src/cosign.rs's (private)
/// `marshal_cosigned_subtree` does, so these tests can sign it without that
/// function being exported from the crate. Kept in sync by the three tests
/// above all passing: if this drifted from src/cosign.rs, verification
/// would fail here first.
fn sign_input_for_test(
    cosigner_id: &TrustAnchorId,
    log_id: &TrustAnchorId,
    start: u64,
    end: u64,
    subtree_hash: &mtc_lake_verifier::hash::HashValue,
) -> Vec<u8> {
    let cosigner_name = cosigner_id.oid_name().unwrap();
    let log_origin = log_id.oid_name().unwrap();
    let mut b = Vec::new();
    b.extend_from_slice(b"subtree/v1\n\x00");
    b.push(cosigner_name.len() as u8);
    b.extend_from_slice(cosigner_name.as_bytes());
    b.extend_from_slice(&0u64.to_be_bytes());
    b.push(log_origin.len() as u8);
    b.extend_from_slice(log_origin.as_bytes());
    b.extend_from_slice(&start.to_be_bytes());
    b.extend_from_slice(&end.to_be_bytes());
    b.extend_from_slice(subtree_hash);
    b
}
