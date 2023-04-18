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

use crate::{
    application::{
        datatypes::{
            BbsProofRequest,
            BbsProofVerification,
            BbsSubProofRequest,
            ProofPresentation,
            BBS_PROOF_TYPE,
        },
        utils::{decode_base64, get_now_as_iso_string},
    },
    crypto::{crypto_utils::check_assertion_proof, crypto_verifier::CryptoVerifier},
    BbsPresentation,
};
use bbs::{
    keys::DeterministicPublicKey,
    prelude::PublicKey,
    verifier::Verifier as BbsVerifier,
    HashElem,
    ProofChallenge,
    SignatureMessage,
    SignatureProof,
};
use std::{collections::HashMap, error::Error, panic};

fn verify_presentation(
    proof: &SignatureProof,
    key: &PublicKey,
    challenge: &ProofChallenge,
    cred: &BbsPresentation,
) -> Result<(), Box<dyn Error>> {
    let verified_proof = proof
        .proof
        .verify(&key, &proof.revealed_messages, &challenge)
        .map_err(|e| format!("Error during proof verification: {}", e))?;

    if !verified_proof.is_valid() {
        return Err(Box::from(format!(
            "Invalid proof for credential {}, with error message: {}",
            &cred.id, verified_proof
        )));
    }

    Ok(())
}

fn verify_revealed_messages(
    nquads: &Vec<String>,
    proof: &SignatureProof,
) -> Result<(), Box<dyn Error>> {
    let revealed = proof.revealed_messages.keys().len();
    let required = nquads.len();
    if revealed < required {
        return Err(Box::from(format!(
            "Required more statements to be revealed than are actually revealed. Required: {}, Revealed: {}",
            required, revealed
        )));
    }

    let mut i = 0;
    for revealed in &proof.revealed_messages {
        if *revealed.1 != SignatureMessage::hash(nquads[i].clone()) {
            return Err(Box::from(format!(
                "Revealed message invalid for expected nquad: \"{}\"",
                nquads[i],
            )));
        }
        i += 1;
    }

    Ok(())
}

pub struct Verifier {}

impl Verifier {
    /// Create proof request to send to a prover
    ///
    /// # Attributes
    /// * `verifier_did` - DID of the verifier issuing the proof request
    /// * `schemas` - `Vec` of schemas to require credentials for
    /// * `reveal_attributes` - Mapping of schema IDs to the respective required attributes to be revealed
    ///
    /// # Returns
    /// `BbsProofRequest` - Proof request
    pub fn create_proof_request(
        verifier_did: Option<String>,
        schemas: Vec<String>,
        reveal_attributes: HashMap<String, Vec<usize>>,
    ) -> Result<BbsProofRequest, Box<dyn Error>> {
        let nonce = BbsVerifier::generate_proof_nonce();
        let mut sub_proof_requests: Vec<BbsSubProofRequest> = Vec::new();
        for schema in schemas {
            let attributes = reveal_attributes
                .get(&schema)
                .ok_or(format!("Did not provide values for schema {}", &schema))?;
            sub_proof_requests.insert(
                0,
                BbsSubProofRequest {
                    schema: schema.clone(),
                    revealed_attributes: attributes.clone(),
                },
            )
        }

        return Ok(BbsProofRequest {
            nonce: base64::encode(nonce.to_bytes_compressed_form()),
            created_at: get_now_as_iso_string(),
            verifier: verifier_did,
            r#type: BBS_PROOF_TYPE.to_string(),
            sub_proof_requests: sub_proof_requests,
        });
    }

    /// Verify a proof received from a prover
    ///
    /// # Attributes
    /// * `presentation` - Received presentation
    /// * `proof_request` - The associated proof request that the presentation is an answer to
    /// * `keys_to_schema_map` - Public keys of the issuer(s) mapped by the respective credential schema DID
    /// * `signer_address` - Address of the `AssertionProof` signer (usually the prover)
    ///
    /// # Returns
    /// * `ProofVerification` - States whether the verification was successful or not
    pub fn verify_proof(
        presentation: &ProofPresentation,
        proof_request: &BbsProofRequest,
        keys_to_schema_map: &HashMap<String, DeterministicPublicKey>,
        signer_address: &str,
        nquads_to_schema_map: &HashMap<String, Vec<String>>,
    ) -> Result<BbsProofVerification, Box<dyn Error>> {
        if presentation.verifiable_credential.len() == 0 {
            return Err(Box::from("Invalid presentation: No credentials provided"));
        }

        check_assertion_proof(&serde_json::to_string(&presentation)?, signer_address)?;

        let challenge =
            CryptoVerifier::create_challenge(&presentation, &proof_request, &keys_to_schema_map)?;

        for cred in &presentation.verifiable_credential {
            let message_count: usize = cred.proof.credential_message_count;
            let key = keys_to_schema_map
                .get(&cred.credential_schema.id)
                .ok_or(format!(
                    "Missing public key for schema {}",
                    &cred.credential_schema.id
                ))?
                .to_public_key(message_count)
                .map_err(|e| {
                    format!(
                        "Error converting deterministic public key while verifying proof: {}",
                        e
                    )
                })?;

            let proof_bytes = decode_base64(&cred.proof.proof, "VP Proof")?.into_boxed_slice();
            let proof = panic::catch_unwind(|| SignatureProof::from(proof_bytes))
                .map_err(|_| "Error parsing signature")?;

            match verify_presentation(&proof, &key, &challenge, &cred) {
                Err(e) => {
                    return Ok(BbsProofVerification {
                        presented_proof: presentation.id.to_string(),
                        status: "rejected".to_string(),
                        reason: Some(e.to_string()),
                    })
                }
                Ok(()) => (),
            }

            match verify_revealed_messages(
                nquads_to_schema_map
                    .get(&cred.credential_schema.id)
                    .ok_or(format!(
                        "Missing nquads for schema {}",
                        &cred.credential_schema.id
                    ))?,
                &proof,
            ) {
                Err(e) => {
                    return Ok(BbsProofVerification {
                        presented_proof: presentation.id.to_string(),
                        status: "rejected".to_string(),
                        reason: Some(e.to_string()),
                    })
                }
                Ok(()) => (),
            }
        }

        Ok(BbsProofVerification {
            presented_proof: presentation.id.to_string(),
            status: "verified".to_string(),
            reason: None,
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate utilities;
    use super::*;
    use crate::{
        application::{
            datatypes::{CredentialSchema, RevocationListCredential, UnfinishedProofPresentation},
            utils::get_dpk_from_string,
        },
        crypto::crypto_utils::create_assertion_proof,
    };
    use serde_json::Value;
    use utilities::test_data::{
        accounts::local::{SIGNER_1_ADDRESS, SIGNER_1_DID, SIGNER_1_PRIVATE_KEY, VERIFIER_DID},
        bbs_coherent_context_test_data::{
            NQUADS,
            PROOF_PRESENTATION,
            PROOF_PRESENTATION_INVALID_SIGNATURE_AND_WITHOUT_JWS,
            PROOF_REQUEST,
            PROOF_REQUEST_SCHEMA_FIVE_PROPERTIES,
            PROOF_REQUEST_SCHEMA_FIVE_PROPERTIES_WITHOUT_VERIFIER,
            PUB_KEY,
            REVOCATION_LIST_CREDENTIAL,
            SCHEMA,
        },
    };
    use vade_signer::{LocalSigner, Signer};

    #[test]
    fn can_create_proof_request_for_one_schema() -> Result<(), Box<dyn Error>> {
        let schema: CredentialSchema = serde_json::from_str(&SCHEMA)?;
        let schemas: Vec<String> = vec![schema.id.clone()];
        let mut reveal_attributes = HashMap::new();
        reveal_attributes.insert(schema.clone().id, vec![1]);

        match Verifier::create_proof_request(
            Some(VERIFIER_DID.to_string()),
            schemas.clone(),
            reveal_attributes.clone(),
        ) {
            Ok(proof_request) => {
                assert_eq!(proof_request.verifier, Some(VERIFIER_DID.to_string()));
                assert_eq!(proof_request.sub_proof_requests.len(), 1);
                assert_eq!(
                    proof_request.sub_proof_requests[0].revealed_attributes,
                    vec![1]
                );
                assert_eq!(proof_request.sub_proof_requests[0].schema, schema.id);
                // Nonce properly encoded
                assert!(decode_base64(&proof_request.nonce, "Proof request nonce").is_ok());
            }
            Err(e) => assert!(false, "Test unexpectedly failed with error: {}", e),
        }

        Ok(())
    }

    #[test]
    fn can_create_proof_request_without_verifier() -> Result<(), Box<dyn Error>> {
        let schema: CredentialSchema = serde_json::from_str(&SCHEMA)?;
        let schemas: Vec<String> = vec![schema.id.clone()];
        let mut reveal_attributes = HashMap::new();
        reveal_attributes.insert(schema.clone().id, vec![1]);

        match Verifier::create_proof_request(None, schemas.clone(), reveal_attributes.clone()) {
            Ok(proof_request) => {
                assert_eq!(proof_request.verifier, None);
                assert_eq!(proof_request.sub_proof_requests.len(), 1);
                assert_eq!(
                    proof_request.sub_proof_requests[0].revealed_attributes,
                    vec![1]
                );
                assert_eq!(proof_request.sub_proof_requests[0].schema, schema.id);
                // Nonce properly encoded
                assert!(decode_base64(&proof_request.nonce, "Proof request nonce").is_ok());
            }
            Err(e) => assert!(false, "Test unexpectedly failed with error: {}", e),
        }

        Ok(())
    }

    #[test]
    fn can_create_proof_request_for_two_schemas() -> Result<(), Box<dyn Error>> {
        let schema: CredentialSchema = serde_json::from_str(&SCHEMA)?;
        let mut another_schema: CredentialSchema = schema.clone();
        another_schema.id = "other_did".to_owned();
        let schemas: Vec<String> = vec![schema.id.clone(), another_schema.id.clone()];
        let mut reveal_attributes = HashMap::new();
        reveal_attributes.insert(schema.clone().id, vec![1]);
        reveal_attributes.insert(another_schema.clone().id, vec![1]);

        match Verifier::create_proof_request(
            Some(VERIFIER_DID.to_string()),
            schemas.clone(),
            reveal_attributes.clone(),
        ) {
            Ok(proof_request) => {
                assert_eq!(proof_request.verifier, Some(VERIFIER_DID.to_string()));
                assert_eq!(proof_request.sub_proof_requests.len(), 2);
                assert_eq!(
                    proof_request.sub_proof_requests[0].revealed_attributes,
                    vec![1]
                );
                assert_eq!(
                    proof_request.sub_proof_requests[1].revealed_attributes,
                    vec![1]
                );
                assert_eq!(
                    proof_request.sub_proof_requests[0].schema,
                    another_schema.id
                );
                assert_eq!(proof_request.sub_proof_requests[1].schema, schema.id);
                // Nonce properly encoded
                assert!(decode_base64(&proof_request.nonce, "Proof request nonce").is_ok());
            }
            Err(e) => assert!(false, "Test unexpectedly failed with error: {}", e),
        }

        Ok(())
    }

    #[test]
    fn can_verify_proof() -> Result<(), Box<dyn Error>> {
        let signer_address = SIGNER_1_ADDRESS;
        let presentation: ProofPresentation = serde_json::from_str(&PROOF_PRESENTATION)?;
        let proof_request: BbsProofRequest =
            serde_json::from_str(&PROOF_REQUEST_SCHEMA_FIVE_PROPERTIES)?;
        let key: DeterministicPublicKey = get_dpk_from_string(&PUB_KEY)?;

        let mut keys_to_schema_map = HashMap::new();
        keys_to_schema_map.insert(
            presentation.verifiable_credential[0]
                .credential_schema
                .id
                .clone(),
            key,
        );

        let mut nquads_to_schema_map = HashMap::new();
        nquads_to_schema_map.insert(
            presentation.verifiable_credential[0]
                .credential_schema
                .id
                .clone(),
            vec![NQUADS[0].to_string()],
        );

        Verifier::verify_proof(
            &presentation,
            &proof_request,
            &keys_to_schema_map,
            signer_address,
            &nquads_to_schema_map,
        )?;

        Ok(())
    }

    #[test]
    fn can_verify_proof_without_verifier() -> Result<(), Box<dyn Error>> {
        let signer_address = SIGNER_1_ADDRESS;
        let presentation: ProofPresentation = serde_json::from_str(&PROOF_PRESENTATION)?;
        let proof_request: BbsProofRequest =
            serde_json::from_str(&PROOF_REQUEST_SCHEMA_FIVE_PROPERTIES_WITHOUT_VERIFIER)?;
        let key: DeterministicPublicKey = get_dpk_from_string(&PUB_KEY)?;

        let mut keys_to_schema_map = HashMap::new();
        keys_to_schema_map.insert(
            presentation.verifiable_credential[0]
                .credential_schema
                .id
                .clone(),
            key,
        );

        let mut nquads_to_schema_map = HashMap::new();
        nquads_to_schema_map.insert(
            presentation.verifiable_credential[0]
                .credential_schema
                .id
                .clone(),
            vec![NQUADS[0].to_string()],
        );

        Verifier::verify_proof(
            &presentation,
            &proof_request,
            &keys_to_schema_map,
            signer_address,
            &nquads_to_schema_map,
        )?;

        Ok(())
    }

    #[tokio::test]
    async fn throws_on_invalid_bbs_proof() -> Result<(), Box<dyn Error>> {
        let proofless_presentation: UnfinishedProofPresentation =
            serde_json::from_str(PROOF_PRESENTATION_INVALID_SIGNATURE_AND_WITHOUT_JWS)?;
        let holder_address = SIGNER_1_ADDRESS;
        let signer: Box<dyn Signer> = Box::new(LocalSigner::new());
        let assertion_proof = create_assertion_proof(
            &serde_json::to_value(&proofless_presentation)?,
            &format!("{}#key-1", SIGNER_1_DID),
            SIGNER_1_DID,
            SIGNER_1_PRIVATE_KEY,
            &signer,
        )
        .await?;
        let presentation = ProofPresentation::new(proofless_presentation, assertion_proof);
        let proof_request: BbsProofRequest =
            serde_json::from_str(&PROOF_REQUEST_SCHEMA_FIVE_PROPERTIES)?;
        let key: DeterministicPublicKey = get_dpk_from_string(&PUB_KEY)?;

        let mut keys_to_schema_map = HashMap::new();
        keys_to_schema_map.insert(
            presentation.verifiable_credential[0]
                .credential_schema
                .id
                .clone(),
            key,
        );

        let mut nqsm: HashMap<String, Vec<String>> = HashMap::new();
        nqsm.insert(
            proof_request.sub_proof_requests[0].schema.clone(),
            vec![NQUADS[0].to_string()],
        );

        match Verifier::verify_proof(
            &presentation,
            &proof_request,
            &keys_to_schema_map,
            holder_address,
            &nqsm,
        ) {
            Ok(_) => assert!(false, "This test should have failed"),
            Err(e) => assert_eq!(
                format!(
                    "Error parsing signature proof for credential {}",
                    presentation.verifiable_credential[0].id.clone()
                ),
                format!("{}", e)
            ),
        }

        Ok(())
    }

    #[test]
    fn throws_on_invalid_assertion_proof() -> Result<(), Box<dyn Error>> {
        let holder_address = SIGNER_1_ADDRESS;
        // Our assertion got corrupted mysteriously
        let mut presentation: ProofPresentation = serde_json::from_str(&PROOF_PRESENTATION)?;
        let other_proof =
            serde_json::from_str::<RevocationListCredential>(REVOCATION_LIST_CREDENTIAL)?
                .proof
                .jws;
        presentation.proof.jws = other_proof;

        let proof_request: BbsProofRequest =
            serde_json::from_str(&PROOF_REQUEST_SCHEMA_FIVE_PROPERTIES)?;
        let key: DeterministicPublicKey = get_dpk_from_string(&PUB_KEY)?;

        let mut keys_to_schema_map = HashMap::new();
        keys_to_schema_map.insert(
            presentation.verifiable_credential[0]
                .credential_schema
                .id
                .clone(),
            key,
        );

        let mut nqsm: HashMap<String, Vec<String>> = HashMap::new();
        nqsm.insert(
            proof_request.sub_proof_requests[0].schema.clone(),
            vec![NQUADS[0].to_string()],
        );

        match Verifier::verify_proof(
            &presentation,
            &proof_request,
            &keys_to_schema_map,
            holder_address,
            &nqsm,
        ) {
            Ok(_) => assert!(false, "This test should have failed"),
            Err(e) => assert_eq!(
                "recovered VC document and given VC document do not match",
                format!("{}", e)
            ),
        }

        Ok(())
    }

    #[test]
    fn throws_on_invalid_presentation_structure() -> Result<(), Box<dyn Error>> {
        let holder_address = SIGNER_1_ADDRESS;
        // Our bbs proof got corrupted mysteriously
        let mut presentation_doc: Value = serde_json::from_str(&PROOF_PRESENTATION)?;
        presentation_doc["verifiableCredential"] = Value::Array(Vec::new());

        let presentation: ProofPresentation = serde_json::from_value(presentation_doc)?;
        let proof_request: BbsProofRequest =
            serde_json::from_str(&PROOF_REQUEST_SCHEMA_FIVE_PROPERTIES)?;

        let keys_to_schema_map = HashMap::new();

        let mut nqsm: HashMap<String, Vec<String>> = HashMap::new();
        nqsm.insert(
            proof_request.sub_proof_requests[0].schema.clone(),
            vec![NQUADS[0].to_string()],
        );

        match Verifier::verify_proof(
            &presentation,
            &proof_request,
            &keys_to_schema_map,
            holder_address,
            &nqsm,
        ) {
            Ok(_) => assert!(false, "This test should have failed"),
            Err(e) => assert_eq!(
                "Invalid presentation: No credentials provided",
                format!("{}", e)
            ),
        }

        Ok(())
    }

    #[test]
    fn deems_proof_invalid_on_unexpected_values() -> Result<(), Box<dyn Error>> {
        let holder_address = SIGNER_1_ADDRESS;
        // Our assertion got corrupted mysteriously
        let presentation: ProofPresentation = serde_json::from_str(&PROOF_PRESENTATION)?;

        let proof_request: BbsProofRequest = serde_json::from_str(&PROOF_REQUEST)?;
        let key: DeterministicPublicKey = get_dpk_from_string(&PUB_KEY)?;

        let mut keys_to_schema_map = HashMap::new();
        keys_to_schema_map.insert(
            presentation.verifiable_credential[0]
                .credential_schema
                .id
                .clone(),
            key,
        );

        let mut nqsm: HashMap<String, Vec<String>> = HashMap::new();
        nqsm.insert(
            proof_request.sub_proof_requests[0].schema.clone(),
            vec!["We expect this value".to_string()], // Proof reveals NQUADS[0] but we expect different value
        );

        match Verifier::verify_proof(
            &presentation,
            &proof_request,
            &keys_to_schema_map,
            holder_address,
            &nqsm,
        ) {
            Ok(result) => {
                assert_eq!(result.status, "rejected");
                assert!(result
                    .reason
                    .ok_or("Missing reason for proof rejection")?
                    .contains("Revealed message invalid for expected nquad: "));
            }
            Err(e) => assert!(
                false,
                "This test shouldn't have failed but it failed with Reason: {}",
                e
            ),
        }

        Ok(())
    }
}
