use crate::application::datatypes::{CredentialSchema, UnfinishedBbsCredential};
use bbs::{
    keys::DeterministicPublicKey,
    prover::Prover as BbsProver,
    signature::{BlindSignature, Signature},
    BlindSignatureContext, ProofNonce, SignatureBlinding, SignatureMessage,
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
        credential: UnfinishedBbsCredential,
        issuer_public_key: &DeterministicPublicKey,
        blind_signature: &BlindSignature,
        blinding_factor: &SignatureBlinding,
    ) -> Result<Signature, Box<dyn Error>> {
        BbsProver::complete_signature(
            verkey: &PublicKey,
            messages: &[SignatureMessage],
            blind_signature: &BlindSignature,
            blinding_factor: &SignatureBlinding,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_data::vc_zkp::EXAMPLE_CREDENTIAL_SCHEMA;
    use bbs::{issuer::Issuer, prover::Prover};
    use std::collections::HashMap;

    #[test]
    fn can_create_blind_signature_context() {
        let (dpk, _) = Issuer::new_short_keys(None);
        let master_secret = Prover::new_link_secret();
        let nonce = Issuer::generate_signing_nonce();
        let credential_schema: CredentialSchema =
            serde_json::from_str(EXAMPLE_CREDENTIAL_SCHEMA).unwrap();
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
        let (dpk, _) = Issuer::new_short_keys(None);
        let master_secret = Prover::new_link_secret();
        let nonce = Issuer::generate_signing_nonce();
        let mut credential_schema: CredentialSchema =
            serde_json::from_str(EXAMPLE_CREDENTIAL_SCHEMA).unwrap();
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
        CryptoProver::finish_credential_signature();
    }
}
