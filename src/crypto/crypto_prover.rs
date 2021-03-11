use crate::application::datatypes::{
    BbsCredential, BbsSubProofRequest, UnfinishedBbsCredential, KEY_SIZE,
};
use bbs::{
    keys::DeterministicPublicKey,
    messages::{HiddenMessage, ProofMessage},
    pm_hidden, pm_revealed,
    pok_sig::PoKOfSignature,
    prover::Prover as BbsProver,
    signature::{BlindSignature, Signature},
    verifier::Verifier as BbsVerifier,
    BlindSignatureContext, HashElem, ProofNonce, SignatureBlinding, SignatureMessage,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::error::Error;
use std::iter::FromIterator;

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

    pub fn create_proof_of_knowledge(
        sub_proof_request: &BbsSubProofRequest,
        credential: &BbsCredential,
        public_key: &DeterministicPublicKey,
        master_secret: &SignatureMessage,
        nquads: Vec<String>,
    ) -> Result<PoKOfSignature, Box<dyn Error>> {
        let pk = public_key
            .to_public_key(KEY_SIZE)
            .map_err(|e| format!("Cannot create proof: Error converting public key: {}", e))?;

        let crypto_proof_request =
            BbsVerifier::new_proof_request(&sub_proof_request.revealed_attributes.as_slice(), &pk)
                .unwrap();

        let indices: HashSet<usize> =
            HashSet::from_iter(sub_proof_request.revealed_attributes.iter().cloned());

        let mut commitment_messages = Vec::new();
        commitment_messages.insert(0, pm_hidden!(master_secret.to_bytes_compressed_form()));
        for (i, nquad) in nquads.iter().enumerate() {
            let msg;
            if indices.contains(&i) {
                msg = pm_revealed!(nquad);
            } else {
                msg = pm_hidden!(nquad);
            }
            commitment_messages.insert(i, msg);
        }

        let signature =
            Signature::from(base64::decode(&credential.proof.signature)?.into_boxed_slice());

        let pok = BbsProver::commit_signature_pok(
            &crypto_proof_request,
            commitment_messages.as_slice(),
            &signature,
        )
        .map_err(|e| format!("Error creating PoK during proof creation: {}", e))?;

        Ok(pok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::issuer::Issuer;
    use crate::utils::test_data::bbs_coherent_context_test_data::{
        FINISHED_CREDENTIAL, MASTER_SECRET, NQUADS, PUB_KEY, SIGNATURE_BLINDING,
        UNFINISHED_CREDENTIAL,
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

    #[test]
    fn can_create_proof_of_knowledge() -> Result<(), Box<dyn Error>> {
        let credential: BbsCredential = serde_json::from_str(&FINISHED_CREDENTIAL)?;
        let public_key: DeterministicPublicKey =
            DeterministicPublicKey::from(base64::decode(&PUB_KEY)?.into_boxed_slice());
        let nquads: Vec<String> = NQUADS.iter().map(|q| q.to_string()).collect();
        let sub_proof_request = BbsSubProofRequest {
            revealed_attributes: vec![1],
            schema: credential.credential_schema.id.clone(),
        };
        let master_secret: SignatureMessage =
            SignatureMessage::from(base64::decode(&MASTER_SECRET)?.into_boxed_slice());

        match CryptoProver::create_proof_of_knowledge(
            &sub_proof_request,
            &credential,
            &public_key,
            &master_secret,
            nquads,
        ) {
            Ok(_) => assert!(true),
            Err(e) => assert!(false, "Unexpected error: {}", e),
        }

        Ok(())
    }
}
