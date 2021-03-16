use crate::application::{
    datatypes::{
        BbsProofRequest,
        BbsSubProofRequest,
        CredentialSchema,
        ProofPresentation,
        KEY_SIZE,
    },
    utils::get_now_as_iso_string,
};
use bbs::verifier::Verifier as BbsVerifier;
use bbs::{keys::DeterministicPublicKey, ProofNonce, SignatureProof};
use std::collections::HashMap;
use std::error::Error;

pub struct Verifier {}

impl Verifier {
    pub fn create_proof_request(
        verifier_did: String,
        schemas: Vec<CredentialSchema>,
        reveal_attributes: HashMap<String, Vec<usize>>,
    ) -> Result<BbsProofRequest, Box<dyn Error>> {
        let nonce = BbsVerifier::generate_proof_nonce();
        let mut sub_proof_requests: Vec<BbsSubProofRequest> = Vec::new();
        for schema in schemas {
            let attributes = reveal_attributes
                .get(&schema.id)
                .ok_or(format!("Did not provide values for schema {}", &schema.id))?;
            sub_proof_requests.insert(
                0,
                BbsSubProofRequest {
                    schema: schema.id.clone(),
                    revealed_attributes: attributes.clone(),
                },
            )
        }

        return Ok(BbsProofRequest {
            nonce: base64::encode(nonce.to_bytes_compressed_form()),
            created_at: get_now_as_iso_string(),
            verifier: verifier_did,
            sub_proof_requests: sub_proof_requests,
        });
    }

    pub fn verify_proof(
        presentation: ProofPresentation,
        proof_request: BbsProofRequest,
        keys_to_schema_map: HashMap<String, DeterministicPublicKey>,
    ) -> Result<(), Box<dyn Error>> {
        let mut proofs = Vec::new();
        let mut proof_requests = Vec::new();
        let mut revealed_messages_per_schema = HashMap::new();

        for sub_request in proof_request.sub_proof_requests {
            revealed_messages_per_schema
                .insert(sub_request.schema, sub_request.revealed_attributes);
        }

        for cred in presentation.verifiable_credential {
            let signature =
                SignatureProof::from(base64::decode(cred.proof.proof)?.into_boxed_slice());
            proofs.insert(proofs.len(), signature);

            let revealed_messages = revealed_messages_per_schema
                .get(&cred.credential_schema.id)
                .ok_or(format!(
                    "Missing revealed messages for schema {}",
                    cred.credential_schema.id
                ))?;
            let key = keys_to_schema_map
                .get(&cred.credential_schema.id)
                .ok_or(format!(
                    "Missing key for schema {}",
                    cred.credential_schema.id
                ))?
                .to_public_key(KEY_SIZE)
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

        let nonce = ProofNonce::from(base64::decode(proof_request.nonce)?.into_boxed_slice());
        let challenge =
            BbsVerifier::create_challenge_hash(&proofs, proof_requests.as_slice(), &nonce, None);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_data::{
        accounts::local::VERIFIER_DID,
        vc_zkp::EXAMPLE_CREDENTIAL_SCHEMA,
        vc_zkp::EXAMPLE_CREDENTIAL_SCHEMA_FIVE_PROPERTIES,
    };
    #[test]
    fn can_create_proof_request_for_one_schema() -> Result<(), Box<dyn Error>> {
        let schema: CredentialSchema =
            serde_json::from_str(&EXAMPLE_CREDENTIAL_SCHEMA_FIVE_PROPERTIES)?;
        let schemas: Vec<CredentialSchema> = vec![schema.clone()];
        let mut reveal_attributes = HashMap::new();
        reveal_attributes.insert(schema.clone().id, vec![1]);

        match Verifier::create_proof_request(
            VERIFIER_DID.to_string(),
            schemas.clone(),
            reveal_attributes.clone(),
        ) {
            Ok(proof_request) => {
                assert_eq!(proof_request.verifier, VERIFIER_DID);
                assert_eq!(proof_request.sub_proof_requests.len(), 1);
                assert_eq!(
                    proof_request.sub_proof_requests[0].revealed_attributes,
                    vec![1]
                );
                assert_eq!(proof_request.sub_proof_requests[0].schema, schema.id);
                // Nonce properly encoded
                assert!(base64::decode(&proof_request.nonce).is_ok());
            }
            Err(e) => assert!(false, "Test unexpectedly failed with error: {}", e),
        }

        Ok(())
    }

    #[test]
    fn can_create_proof_request_for_two_schemas() -> Result<(), Box<dyn Error>> {
        let schema: CredentialSchema = serde_json::from_str(&EXAMPLE_CREDENTIAL_SCHEMA)?;
        let mut another_schema: CredentialSchema = schema.clone();
        another_schema.id = "other_did".to_owned();
        let schemas: Vec<CredentialSchema> = vec![schema.clone(), another_schema.clone()];
        let mut reveal_attributes = HashMap::new();
        reveal_attributes.insert(schema.clone().id, vec![1]);
        reveal_attributes.insert(another_schema.clone().id, vec![1]);

        match Verifier::create_proof_request(
            VERIFIER_DID.to_string(),
            schemas.clone(),
            reveal_attributes.clone(),
        ) {
            Ok(proof_request) => {
                assert_eq!(proof_request.verifier, VERIFIER_DID);
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
                assert!(base64::decode(proof_request.nonce).is_ok());
            }
            Err(e) => assert!(false, "Test unexpectedly failed with error: {}", e),
        }

        Ok(())
    }

    #[test]
    fn can_verify_proof() -> Result<(), Box<dyn Error>> {
        // Verifier::verifiy_proof();

        panic!("Not implemented");
    }
}
