use crate::application::datatypes::KEY_SIZE;
use bbs::{
    issuer::Issuer as BbsIssuer,
    keys::{DeterministicPublicKey, SecretKey},
    signature::BlindSignature,
    BlindSignatureContext,
    HashElem,
    ProofNonce,
    SignatureMessage,
};
use std::{
    collections::BTreeMap,
    error::Error,
};

pub struct CryptoIssuer {}

impl CryptoIssuer {
    pub fn create_signature(
        blind_signature_context: &BlindSignatureContext,
        signing_nonce: &ProofNonce,
        credential_values: Vec<String>,
        issuer_public_key: &DeterministicPublicKey,
        issuer_secret_key: &SecretKey,
    ) -> Result<BlindSignature, Box<dyn Error>> {
        if credential_values.len() > KEY_SIZE {
            return Err(Box::from(format!(
                "Error creating signature: Too many messages to sign, limit is {}",
                KEY_SIZE
            )));
        }
        let mut messages: BTreeMap<usize, SignatureMessage> = BTreeMap::new();
        let mut i = 1; // 0 is always reserved for master secret
        for value in &credential_values {
            let message = SignatureMessage::hash(value);
            messages.insert(i, message);
            i += 1;
        }

        for j in i..KEY_SIZE {
            messages.insert(j, SignatureMessage::hash(""));
        }

        let pub_key = issuer_public_key
            .to_public_key(KEY_SIZE)
            .map_err(|_| "Error creating signature: Schema for blinded signature context does not match provided values")?;

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
    use crate::crypto::crypto_prover::CryptoProver;
    use bbs::prover::Prover as BbsProver;

    #[test]
    fn can_create_signature() -> Result<(), Box<dyn Error>> {
        let (dpk, sk) = BbsIssuer::new_short_keys(None);

        // Prover
        let master_secret = BbsProver::new_link_secret();
        let nonce = BbsIssuer::generate_signing_nonce();
        let (blind_signature_context, _) =
            CryptoProver::create_blind_signature_context(&dpk, &master_secret, &nonce)?;

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
        let (dpk2, _) = BbsIssuer::new_short_keys(None);

        let master_secret = BbsProver::new_link_secret();
        let nonce = BbsIssuer::generate_signing_nonce();
        let (blind_signature_context, _) =
            CryptoProver::create_blind_signature_context(&dpk2, &master_secret, &nonce)?;

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

    #[test]
    fn throws_when_signing_too_many_messages() -> Result<(), Box<dyn Error>> {
        let (dpk, sk) = BbsIssuer::new_short_keys(None);

        // Prover
        let master_secret = BbsProver::new_link_secret();
        let nonce = BbsIssuer::generate_signing_nonce();
        let (blind_signature_context, _) =
            CryptoProver::create_blind_signature_context(&dpk, &master_secret, &nonce)?;

        // Issuer
        let mut values = Vec::new();
        for _ in 0..KEY_SIZE + 1 {
            values.insert(0, "test_property_string: test_value".to_owned());
        }
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
                let expected_err = format!(
                    "Error creating signature: Too many messages to sign, limit is {}",
                    KEY_SIZE.to_string()
                );
                assert_eq!(message.contains(&expected_err), true);
            }
        }
        Ok(())
    }
}
