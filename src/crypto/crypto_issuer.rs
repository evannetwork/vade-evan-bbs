use super::utils::canonicalize_credential_value_keys;
use bbs::{
    issuer::Issuer as BbsIssuer,
    keys::{DeterministicPublicKey, SecretKey},
    signature::BlindSignature,
    BlindSignatureContext, HashElem, ProofNonce, SignatureMessage,
};
use std::collections::BTreeMap;
use std::error::Error;

pub struct CryptoIssuer {}

impl CryptoIssuer {
    pub fn create_signature(
        blind_signature_context: &BlindSignatureContext,
        signing_nonce: &ProofNonce,
        credential_values: Vec<String>,
        issuer_public_key: &DeterministicPublicKey,
        issuer_secret_key: &SecretKey,
    ) -> Result<BlindSignature, Box<dyn Error>> {
        let mut messages = BTreeMap::new();
        let mut i = 1; // 0 is always reserved for master secret
        for value in &credential_values {
            let message = SignatureMessage::hash(value);
            messages.insert(i, message);
            i += 1;
        }

        let pub_key = issuer_public_key
            .to_public_key(credential_values.len() + 1) // +1 for secret
            .map_err(|_| "Schema for blinded signature context does not match provided values")?;

        let signature = BbsIssuer::blind_sign(
            blind_signature_context,
            &messages,
            issuer_secret_key,
            &pub_key,
            signing_nonce,
        )
        .map_err(|e| format!("Cannot create signature: {}", e))?;

        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        application::datatypes::CredentialSchema, crypto::crypto_prover::CryptoProver,
        utils::test_data::vc_zkp::EXAMPLE_CREDENTIAL_SCHEMA,
    };
    use bbs::prover::Prover as BbsProver;

    #[test]
    fn can_create_signature() -> Result<(), Box<dyn Error>> {
        let (dpk, sk) = BbsIssuer::new_short_keys(None);

        // Prover
        let schema: CredentialSchema = serde_json::from_str(&EXAMPLE_CREDENTIAL_SCHEMA)?;
        let master_secret = BbsProver::new_link_secret();
        let nonce = BbsIssuer::generate_signing_nonce();
        let (blind_signature_context, _) =
            CryptoProver::create_blind_signature_context(&dpk, &schema, &master_secret, &nonce)?;

        // Issuer
        let mut values = Vec::new();
        values.insert(0, "test_property_string: test_value".to_owned());
        let signature =
            CryptoIssuer::create_signature(&blind_signature_context, &nonce, values, &dpk, &sk);

        match signature {
            Ok(_) => assert!(true),
            Err(e) => return Err(Box::from(format!("{}", e))),
        }

        Ok(())
    }

    #[test]
    fn throws_when_providing_wrong_blinding_context() -> Result<(), Box<dyn Error>> {
        let (dpk, sk) = BbsIssuer::new_short_keys(None);

        let schema: CredentialSchema = serde_json::from_str(&EXAMPLE_CREDENTIAL_SCHEMA)?;
        let master_secret = BbsProver::new_link_secret();
        let nonce = BbsIssuer::generate_signing_nonce();
        let (blind_signature_context, _) =
            CryptoProver::create_blind_signature_context(&dpk, &schema, &master_secret, &nonce)?;

        let mut values = Vec::new();
        values.insert(0, "test_property_string: test_value".to_owned());
        values.insert(1, "property_not_included_in_schema: test_value".to_owned());
        let signature =
            CryptoIssuer::create_signature(&blind_signature_context, &nonce, values, &dpk, &sk);

        match signature {
            Ok(_) => {
                return Err(Box::from(
                    "Signature creation shouldn't succeed in this test",
                ))
            }
            Err(e) => {
                let message = format!("{}", e);
                assert_eq!(message.contains("Cannot create signature:"), true);
            }
        }
        Ok(())
    }
}
