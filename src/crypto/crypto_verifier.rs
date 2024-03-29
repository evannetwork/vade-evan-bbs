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
    datatypes::{BbsProofRequest, CredentialStatus, ProofPresentation, RevocationListCredential},
    utils::{decode_base64, decode_base64_config, get_nonce_from_string},
};
use bbs::{
    keys::DeterministicPublicKey,
    verifier::Verifier as BbsVerifier,
    ProofChallenge,
    SignatureProof,
};
use flate2::read::GzDecoder;
use std::{collections::HashMap, error::Error, io::prelude::*, panic};

pub struct CryptoVerifier {}

impl CryptoVerifier {
    /// Checks if a given credential is revoked in the given revocation list
    ///
    /// # Arguments
    /// * `credential` - BbsCredential which has to be checked
    /// * `revocation_list` - Revocation list the credential belongs to
    ///
    /// # Returns
    /// * `bool` - bool value if the credential is revoked or not

    pub fn is_revoked(
        credential_status: &CredentialStatus,
        revocation_list: &RevocationListCredential,
    ) -> Result<bool, Box<dyn Error>> {
        let encoded_list = decode_base64_config(
            revocation_list.credential_subject.encoded_list.to_string(),
            base64::URL_SAFE,
            "Encoded Revocation List",
        )?;
        let mut decoder = GzDecoder::new(&encoded_list[..]);
        let mut decoded_list = Vec::new();
        decoder.read_to_end(&mut decoded_list)?;

        let revocation_list_index_number = credential_status
            .revocation_list_index
            .parse::<usize>()
            .map_err(|e| format!("Error parsing revocation_list_id: {}", e))?;

        let byte_index_float: f32 = (revocation_list_index_number / 8) as f32;
        let byte_index: usize = byte_index_float.floor() as usize;
        let revoked = decoded_list[byte_index] & (1 << (revocation_list_index_number % 8)) != 0;
        Ok(revoked)
    }

    pub fn create_challenge(
        presentation: &ProofPresentation,
        proof_request: &BbsProofRequest,
        keys_to_schema_map: &HashMap<String, DeterministicPublicKey>,
    ) -> Result<ProofChallenge, Box<dyn Error>> {
        let mut proofs = Vec::new();
        let mut proof_requests = Vec::new();
        let mut revealed_messages_per_schema = HashMap::new();

        for sub_request in &proof_request.sub_proof_requests {
            revealed_messages_per_schema.insert(
                sub_request.schema.clone(),
                sub_request.revealed_attributes.clone(),
            );
        }

        for cred in &presentation.verifiable_credential {
            let proof_bytes = decode_base64(&cred.proof.proof, "VP Proof")?.into_boxed_slice();
            let signature =
                panic::catch_unwind(|| SignatureProof::from(proof_bytes)).map_err(|_| {
                    format!("Error parsing signature proof for credential {}", &cred.id)
                })?;
            proofs.insert(proofs.len(), signature);

            let revealed_messages = revealed_messages_per_schema
                .get(&cred.credential_schema.id)
                .ok_or(format!(
                    "Missing revealed messages for schema {}",
                    cred.credential_schema.id
                ))?;
            let message_count: usize = cred.proof.credential_message_count;
            let key = keys_to_schema_map
                .get(&cred.credential_schema.id)
                .ok_or(format!(
                    "Missing key for schema {}",
                    cred.credential_schema.id
                ))?
                .to_public_key(message_count)
                .map_err(|e| format!("Error converting key for proof verification: {}", e))?;

            proof_requests.insert(
                proof_requests.len(),
                BbsVerifier::new_proof_request(&revealed_messages, &key).map_err(|e| {
                    format!(
                        "Could not create proof request for proof verification: {}",
                        e
                    )
                })?,
            );
        }

        let nonce = get_nonce_from_string(&proof_request.nonce)?;
        let challenge =
            BbsVerifier::create_challenge_hash(&proofs, proof_requests.as_slice(), &nonce, None)
                .map_err(|e| {
                    format!(
                        "Could not create challenge hash for proof verification: {}",
                        e
                    )
                })?;

        return Ok(challenge);
    }
}

#[cfg(test)]

mod tests {
    extern crate utilities;

    use super::*;
    use crate::application::datatypes::BbsCredential;
    use utilities::test_data::bbs_coherent_context_test_data::{
        FINISHED_CREDENTIAL,
        REVOCATION_LIST_CREDENTIAL,
        REVOCATION_LIST_CREDENTIAL_REVOKED_ID_1,
    };

    #[test]
    fn can_check_not_revoked_credential() -> Result<(), Box<dyn Error>> {
        let credential: BbsCredential = serde_json::from_str(&FINISHED_CREDENTIAL)?;
        let revocation_list: RevocationListCredential =
            serde_json::from_str(&REVOCATION_LIST_CREDENTIAL)?;

        match CryptoVerifier::is_revoked(
            &credential
                .credential_status
                .ok_or_else(|| "Error in Parsing credential_status")?,
            &revocation_list,
        ) {
            Ok(revoked) => assert_eq!(false, revoked),
            Err(e) => assert!(false, "Unexpected error: {}", e),
        };
        Ok(())
    }

    #[test]
    fn can_check_revoked_credential() -> Result<(), Box<dyn Error>> {
        let credential: BbsCredential = serde_json::from_str(&FINISHED_CREDENTIAL)?;
        let revocation_list: RevocationListCredential =
            serde_json::from_str(&REVOCATION_LIST_CREDENTIAL_REVOKED_ID_1)?;

        match CryptoVerifier::is_revoked(
            &credential
                .credential_status
                .ok_or_else(|| "Error in Parsing credential_status")?,
            &revocation_list,
        ) {
            Ok(revoked) => assert_eq!(true, revoked),
            Err(e) => assert!(false, "Unexpected error: {}", e),
        };
        Ok(())
    }
}
