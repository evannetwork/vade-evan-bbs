use crate::application::datatypes::{UnfinishedBbsCredential, KEY_SIZE};
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
        master_secret: &SignatureMessage,
        credential_offering_nonce: &ProofNonce,
    ) -> Result<(BlindSignatureContext, SignatureBlinding), Box<dyn Error>> {
        let pk = issuer_pub_key
            .to_public_key(KEY_SIZE) // + 1 for master secret
            .map_err(|e| format!("{}", e))?;
        let mut messages = BTreeMap::new();
        messages.insert(0, master_secret.clone());
        let (context, blinding) =
            BbsProver::new_blind_signature_context(&pk, &messages, &credential_offering_nonce)
                .map_err(|e| format!("{}", e))?;

        return Ok((context, blinding));
    }

    pub fn finish_credential_signature(
        credential_messages: Vec<String>,
        master_secret: &SignatureMessage,
        issuer_public_key: &DeterministicPublicKey,
        blind_signature: &BlindSignature,
        blinding_factor: &SignatureBlinding,
    ) -> Result<Signature, Box<dyn Error>> {
        let mut messages: Vec<SignatureMessage> = Vec::new();
        let mut i = 1;
        messages.insert(0, master_secret.clone());
        for message in &credential_messages {
            messages.insert(i, SignatureMessage::hash(message));
            i += 1;
        }

        for j in i..KEY_SIZE {
            messages.insert(j, SignatureMessage::hash(""));
        }

        let verkey = issuer_public_key
            .to_public_key(KEY_SIZE)
            .map_err(|e| format!("Error finishing credential: {}", e))?;

        BbsProver::complete_signature(&verkey, &messages, &blind_signature, &blinding_factor)
            .map_err(|e| Box::from(format!("Error finishing credential: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::issuer::Issuer;
    use crate::utils::test_data::bbs_coherent_context_test_data::{
        MASTER_SECRET, NQUADS, PUB_KEY, SIGNATURE_BLINDING, UNFINISHED_CREDENTIAL,
    };
    use bbs::{issuer::Issuer as CryptoIssuer, prover::Prover};
    use std::collections::HashMap;
    use std::convert::{From, TryInto};

    fn setup_tests() -> (DeterministicPublicKey, SignatureMessage, ProofNonce) {
        let (dpk, _) = CryptoIssuer::new_short_keys(None);
        let master_secret = Prover::new_link_secret();
        let issuer_nonce = CryptoIssuer::generate_signing_nonce();
        return (dpk, master_secret, issuer_nonce);
    }

    #[test]
    fn can_create_blind_signature_context() {
        let (dpk, master_secret, nonce) = setup_tests();
        let ctx = CryptoProver::create_blind_signature_context(&dpk, &master_secret, &nonce);
        assert!(ctx.is_ok());
    }

    #[test]
    fn can_finish_credential_signature() -> Result<(), Box<dyn Error>> {
        let unfinished_credential: UnfinishedBbsCredential =
            serde_json::from_str(&UNFINISHED_CREDENTIAL)?;
        let master_secret: SignatureMessage =
            SignatureMessage::from(base64::decode(&MASTER_SECRET)?.into_boxed_slice());
        let nquads: Vec<String> = NQUADS.iter().map(|q| q.to_string()).collect();
        let public_key: DeterministicPublicKey =
            DeterministicPublicKey::from(base64::decode(&PUB_KEY)?.into_boxed_slice());
        let blinding: SignatureBlinding =
            SignatureBlinding::from(base64::decode(&SIGNATURE_BLINDING)?.into_boxed_slice());

        let raw: Box<[u8]> =
            base64::decode(unfinished_credential.proof.blind_signature.clone())?.into_boxed_slice();
        let blind_signature: BlindSignature = raw.try_into()?;

        let result = CryptoProver::finish_credential_signature(
            nquads.clone(),
            &master_secret,
            &public_key,
            &blind_signature,
            &blinding,
        )?;

        Ok(())
    }
}
