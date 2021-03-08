use crate::application::datatypes::{CredentialSchema, UnfinishedBbsCredential};
use bbs::{
    keys::DeterministicPublicKey,
    prover::Prover as BbsProver,
    signature::{BlindSignature, Signature},
    BlindSignatureContext, HashElem, ProofNonce, SignatureBlinding, SignatureMessage,
};
use std::collections::BTreeMap;
use std::error::Error;

pub struct CryptoProver {}

impl CryptoProver {
    pub fn create_blind_signature_context(
        issuer_pub_key: &DeterministicPublicKey,
        schema: &CredentialSchema,
        master_secret: &SignatureMessage,
        credential_offering_nonce: &ProofNonce,
    ) -> Result<(BlindSignatureContext, SignatureBlinding), Box<dyn Error>> {
        if schema.properties.len() == 0 {
            return Err(Box::from(
                "Cannot create blind signature context. Provided invalid schema",
            ));
        }
        let pk = issuer_pub_key
            .to_public_key(schema.properties.len() + 1) // + 1 for master secret
            .unwrap(); // can unwrap because we dealt with possible error before
        let mut messages = BTreeMap::new();
        messages.insert(0, master_secret.clone());
        let (context, blinding) =
            BbsProver::new_blind_signature_context(&pk, &messages, &credential_offering_nonce)
                .map_err(|e| format!("{}", e))?;

        return Ok((context, blinding));
    }

    pub fn finish_credential_signature(
        credential_messages: Vec<String>,
        master_secret: SignatureMessage,
        issuer_public_key: &DeterministicPublicKey,
        blind_signature: &BlindSignature,
        blinding_factor: &SignatureBlinding,
    ) -> Result<Signature, Box<dyn Error>> {
        let mut messages: Vec<SignatureMessage> = Vec::new();
        let mut i = 1;
        for message in &credential_messages {
            messages.insert(i, SignatureMessage::hash(message));
            i += 1;
        }
        messages.insert(0, master_secret);

        let verkey = issuer_public_key
            .to_public_key(credential_messages.len() + 1)
            .map_err(|e| format!("Error finishing credential: {}", e))?;

        BbsProver::complete_signature(&verkey, &messages, &blind_signature, &blinding_factor)
            .map_err(|e| Box::from(format!("Error finishing credential: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::issuer::Issuer;
    use crate::utils::test_data::vc_zkp::EXAMPLE_CREDENTIAL_SCHEMA;
    use bbs::{issuer::Issuer as CryptoIssuer, prover::Prover};
    use std::collections::HashMap;

    fn setup_tests() -> (
        DeterministicPublicKey,
        SignatureMessage,
        ProofNonce,
        CredentialSchema,
    ) {
        let (dpk, _) = CryptoIssuer::new_short_keys(None);
        let master_secret = Prover::new_link_secret();
        let issuer_nonce = CryptoIssuer::generate_signing_nonce();
        let credential_schema: CredentialSchema =
            serde_json::from_str(EXAMPLE_CREDENTIAL_SCHEMA).unwrap();
        return (dpk, master_secret, issuer_nonce, credential_schema);
    }

    #[test]
    fn can_create_blind_signature_context() {
        let (dpk, master_secret, nonce, credential_schema) = setup_tests();
        let ctx = CryptoProver::create_blind_signature_context(
            &dpk,
            &credential_schema,
            &master_secret,
            &nonce,
        );
        assert!(ctx.is_ok());
    }

    #[test]
    fn create_blind_sig_ctx_can_throw_proper_error() {
        let test_entities = setup_tests();
        let (dpk, master_secret, nonce, mut credential_schema) = setup_tests();
        credential_schema.properties = HashMap::new();
        let ctx = CryptoProver::create_blind_signature_context(
            &dpk,
            &credential_schema,
            &master_secret,
            &nonce,
        );
        match ctx {
            Ok(_) => assert!(false),
            Err(err) => assert_eq!(
                format!("{}", err),
                "Cannot create blind signature context. Provided invalid schema"
            ),
        }
    }

    #[test]
    fn can_finish_credential_signature() {
        // Create some small messages
        let messages: Vec<String> = Vec::new();
        let messages = vec![
            "message 1",
            "message 2",
            "message 3",
            "message 4",
            "message 5",
        ];

        // Issue credential

        // CryptoProver::finish_credential_signature();
    }
}
