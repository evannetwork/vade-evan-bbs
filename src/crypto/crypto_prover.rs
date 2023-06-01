/*
  Copyright (c) 2018-present evan GmbH.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

use crate::application::{
    datatypes::{BbsCredentialSignature, BbsSubProofRequest, UnfinishedBbsCredentialSignature},
    issuer::ADDITIONAL_HIDDEN_MESSAGES_COUNT,
    utils::{concat_required_and_reveal_statements, decode_base64},
};
use bbs::{
    keys::DeterministicPublicKey,
    messages::{HiddenMessage, ProofMessage},
    pm_hidden,
    pm_hidden_raw,
    pm_revealed,
    pok_sig::PoKOfSignature,
    prover::Prover as BbsProver,
    signature::{BlindSignature, Signature},
    verifier::Verifier as BbsVerifier,
    BlindSignatureContext,
    HashElem,
    ProofNonce,
    RandomElem,
    SignatureBlinding,
    SignatureMessage,
    SignatureProof,
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    convert::TryInto,
    error::Error,
    iter::FromIterator,
    panic,
};

pub struct CryptoProver {}

impl CryptoProver {
    pub fn create_blind_signature_context(
        issuer_pub_key: &DeterministicPublicKey,
        master_secret: &SignatureMessage,
        credential_offering_nonce: &ProofNonce,
        credential_message_count: usize,
    ) -> Result<(BlindSignatureContext, SignatureBlinding), Box<dyn Error>> {
        let pk = issuer_pub_key
            .to_public_key(credential_message_count)
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
        signature: &UnfinishedBbsCredentialSignature,
        blinding_factor: &SignatureBlinding,
    ) -> Result<Signature, Box<dyn Error>> {
        let raw: Box<[u8]> =
            decode_base64(&signature.blind_signature, "VC Blind Signature")?.into_boxed_slice();
        let blind_signature: BlindSignature = raw.try_into()?;

        if signature.credential_message_count
            != (credential_messages.len() + ADDITIONAL_HIDDEN_MESSAGES_COUNT)
        {
            return Err(Box::from(
                format!(
                    "Provided number of nquads differ from number used in signature; signature expected: {}, but would have to sign: {}",
                    &signature.credential_message_count,
                    &credential_messages.len() + ADDITIONAL_HIDDEN_MESSAGES_COUNT,
                ),
            ));
        }

        let mut messages: Vec<SignatureMessage> = Vec::new();
        let mut i = 1;
        messages.insert(0, master_secret.clone());
        for message in &credential_messages {
            messages.insert(i, SignatureMessage::hash(message));
            i += 1;
        }

        let verkey = issuer_public_key
            .to_public_key(signature.credential_message_count)
            .map_err(|e| format!("Error finishing credential: {}", e))?;

        BbsProver::complete_signature(&verkey, &messages, &blind_signature, &blinding_factor)
            .map_err(|e| Box::from(format!("Error finishing credential: {}", e)))
    }

    pub fn create_proof_of_knowledge(
        sub_proof_request: &BbsSubProofRequest,
        credential_signature: &BbsCredentialSignature,
        public_key: &DeterministicPublicKey,
        master_secret: &SignatureMessage,
        nquads: Vec<String>,
    ) -> Result<PoKOfSignature, Box<dyn Error>> {
        let pk = public_key
            .to_public_key(credential_signature.credential_message_count)
            .map_err(|e| format!("Cannot create proof: Error converting public key: {}", e))?;

        let crypto_proof_request =
            BbsVerifier::new_proof_request(&sub_proof_request.revealed_attributes.as_slice(), &pk)
                .map_err(|e| format!("could not create new proof request; {}", &e))?;
        let required_reveal_statements = &credential_signature.required_reveal_statements;
        let revealed_statements = &sub_proof_request.revealed_attributes;
        let all_revealed_statements =
            concat_required_and_reveal_statements(required_reveal_statements, revealed_statements)?;

        let indices: HashSet<&usize> = HashSet::from_iter(all_revealed_statements.iter());

        let mut commitment_messages = Vec::new();
        let link_secret_blinding = ProofNonce::random();
        commitment_messages.insert(
            0,
            pm_hidden_raw!(master_secret.clone(), link_secret_blinding),
        );

        let mut i = 1;
        for nquad in nquads.iter() {
            let msg;
            if indices.contains(&i) {
                msg = pm_revealed!(nquad);
            } else {
                msg = pm_hidden!(nquad);
            }
            commitment_messages.insert(i, msg);
            i += 1;
        }

        let signature_bytes =
            decode_base64(&credential_signature.signature, "VC Signature")?.into_boxed_slice();
        let signature = panic::catch_unwind(|| Signature::from(signature_bytes))
            .map_err(|_| "Error parsing signature")?;

        let pok = BbsProver::commit_signature_pok(
            &crypto_proof_request,
            commitment_messages.as_slice(),
            &signature,
        )
        .map_err(|e| format!("Error creating PoK during proof creation: {}", e))?;

        Ok(pok)
    }

    pub fn generate_proofs(
        pok_to_schema_map: HashMap<String, PoKOfSignature>,
        nonce: ProofNonce,
    ) -> Result<HashMap<String, SignatureProof>, Box<dyn Error>> {
        let err = "Error creating proof: ";

        let challenge = BbsProver::create_challenge_hash(
            pok_to_schema_map
                .values()
                .cloned()
                .collect::<Vec<PoKOfSignature>>()
                .as_slice(),
            None,
            &nonce,
        )
        .map_err(|e| format!("{} {}", err, e))?;

        let mut proofs = HashMap::new();
        for (schema, pok) in pok_to_schema_map {
            let proof = BbsProver::generate_signature_pok(pok.clone(), &challenge)
                .map_err(|e| format!("{} {}", err, e))?;
            proofs.insert(schema, proof);
        }

        return Ok(proofs);
    }
}

#[cfg(test)]
mod tests {
    extern crate utilities;
    use super::*;
    use crate::application::{
        datatypes::{BbsCredential, UnfinishedBbsCredential},
        utils::{convert_to_credential_nquads, get_dpk_from_string},
    };
    use bbs::{issuer::Issuer as CryptoIssuer, prover::Prover};
    use std::convert::From;
    use utilities::test_data::bbs_coherent_context_test_data::{
        FINISHED_CREDENTIAL,
        MASTER_SECRET,
        PUB_KEY,
        SIGNATURE_BLINDING,
        UNFINISHED_CREDENTIAL,
    };

    fn setup_tests() -> (DeterministicPublicKey, SignatureMessage, ProofNonce) {
        let (dpk, _) = CryptoIssuer::new_short_keys(None);
        let master_secret = Prover::new_link_secret();
        let issuer_nonce = CryptoIssuer::generate_signing_nonce();
        return (dpk, master_secret, issuer_nonce);
    }

    #[test]
    fn can_create_blind_signature_context() {
        let (dpk, master_secret, nonce) = setup_tests();
        let ctx = CryptoProver::create_blind_signature_context(
            &dpk,
            &master_secret,
            &nonce,
            100, /*random value*/
        );
        assert!(ctx.is_ok());
    }

    #[tokio::test]
    async fn can_finish_credential_signature() -> Result<(), Box<dyn Error>> {
        let unfinished_credential: UnfinishedBbsCredential =
            serde_json::from_str(&UNFINISHED_CREDENTIAL)?;
        let master_secret: SignatureMessage = SignatureMessage::from(
            decode_base64(&MASTER_SECRET, "Master Secret")?.into_boxed_slice(),
        );
        let nquads: Vec<String> = convert_to_credential_nquads(&unfinished_credential).await?;
        let public_key: DeterministicPublicKey = get_dpk_from_string(&PUB_KEY)?;
        let blinding: SignatureBlinding = SignatureBlinding::from(
            decode_base64(&SIGNATURE_BLINDING, "Signature Blinding")?.into_boxed_slice(),
        );

        CryptoProver::finish_credential_signature(
            nquads.clone(),
            &master_secret,
            &public_key,
            &unfinished_credential.proof,
            &blinding,
        )?;

        Ok(())
    }

    #[tokio::test]
    async fn can_create_proof_of_knowledge() -> Result<(), Box<dyn Error>> {
        let credential: BbsCredential = serde_json::from_str(&FINISHED_CREDENTIAL)?;
        let public_key: DeterministicPublicKey = get_dpk_from_string(&PUB_KEY)?;
        let nquads: Vec<String> = convert_to_credential_nquads(&credential).await?;
        let sub_proof_request = BbsSubProofRequest {
            revealed_attributes: vec![1],
            schema: credential.credential_schema.id.clone(),
        };
        let master_secret: SignatureMessage = SignatureMessage::from(
            decode_base64(&MASTER_SECRET, "Master Secret")?.into_boxed_slice(),
        );

        match CryptoProver::create_proof_of_knowledge(
            &sub_proof_request,
            &credential.proof,
            &public_key,
            &master_secret,
            nquads,
        ) {
            Ok(_) => assert!(true),
            Err(e) => assert!(false, "Unexpected error: {}", e),
        }

        Ok(())
    }

    #[tokio::test]
    async fn can_generate_proofs() -> Result<(), Box<dyn Error>> {
        let credential: BbsCredential = serde_json::from_str(&FINISHED_CREDENTIAL)?;
        let public_key: DeterministicPublicKey = get_dpk_from_string(&PUB_KEY)?;
        let nquads: Vec<String> = convert_to_credential_nquads(&credential).await?;
        let sub_proof_request = BbsSubProofRequest {
            revealed_attributes: vec![1],
            schema: credential.credential_schema.id.clone(),
        };
        let master_secret: SignatureMessage = SignatureMessage::from(
            decode_base64(&MASTER_SECRET, "Master Secret")?.into_boxed_slice(),
        );

        let pok = CryptoProver::create_proof_of_knowledge(
            &sub_proof_request,
            &credential.proof,
            &public_key,
            &master_secret,
            nquads,
        )?;
        let nonce = BbsVerifier::generate_proof_nonce();

        let mut poks = HashMap::new();
        poks.insert(credential.credential_schema.id.clone(), pok);

        CryptoProver::generate_proofs(poks, nonce)?;

        Ok(())
    }
}
