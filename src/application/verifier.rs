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
use crate::crypto::{crypto_utils::check_assertion_proof, crypto_verifier::CryptoVerifier};

use bbs::verifier::Verifier as BbsVerifier;
use bbs::{keys::DeterministicPublicKey, SignatureProof};
use std::collections::HashMap;
use std::error::Error;
use std::panic;

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

    /// Verify a proof received from a prover
    ///
    /// # Attributes
    /// * `presentation` - Received presentation
    /// * `proof_request` - The associated proof request that the presentation is an answer to
    /// * `keys_to_schema_map` - Public keys of the issuer(s) mapped by the respective credential schema DID
    /// * `signer_address` - Address of the `AssertionProof` signer (usually the prover)
    ///
    /// # Returns
    /// `()` - Finishes if proof is valid, throws an `Error` otherwise
    pub fn verify_proof(
        presentation: &ProofPresentation,
        proof_request: &BbsProofRequest,
        keys_to_schema_map: &HashMap<String, DeterministicPublicKey>,
        signer_address: &str,
    ) -> Result<(), Box<dyn Error>> {
        if presentation.verifiable_credential.len() == 0 {
            return Err(Box::from("Invalid presentation: No credentials provided"));
        }

        check_assertion_proof(&serde_json::to_string(&presentation)?, signer_address)?;

        let challenge =
            CryptoVerifier::create_challenge(&presentation, &proof_request, &keys_to_schema_map)?;

        for cred in &presentation.verifiable_credential {
            let key = keys_to_schema_map
                .get(&cred.credential_schema.id)
                .ok_or(format!(
                    "Missing public key for schema {}",
                    &cred.credential_schema.id
                ))?
                .to_public_key(KEY_SIZE)
                .map_err(|e| {
                    format!(
                        "Error converting deterministic public key while verifying proof: {}",
                        e
                    )
                })?;

            let proof_bytes = base64::decode(&cred.proof.proof)?.into_boxed_slice();
            let proof = panic::catch_unwind(|| SignatureProof::from(proof_bytes))
                .map_err(|_| "Error parsing signature")?;

            let valid = proof
                .proof
                .verify(&key, &proof.revealed_messages, &challenge)
                .map_err(|e| format!("Error during proof verification: {}", e))?
                .is_valid();

            if !valid {
                return Err(Box::from(format!(
                    "Invalid proof for credential {}",
                    &cred.id
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::datatypes::{RevocationListCredential, UnfinishedProofPresentation};
    use crate::application::utils::get_dpk_from_string;
    use crate::crypto::crypto_utils::create_assertion_proof;
    use crate::signing::{LocalSigner, Signer};
    use crate::utils::test_data::{
        accounts::local::{SIGNER_1_ADDRESS, SIGNER_1_DID, SIGNER_1_PRIVATE_KEY, VERIFIER_DID},
        bbs_coherent_context_test_data::{
            PROOF_PRESENTATION,
            PROOF_PRESENTATION_INVALID_SIGNATURE_AND_WITHOUT_JWS,
            PROOF_REQUEST_SCHEMA_FIVE_PROPERTIES,
            PUB_KEY,
            REVOCATION_LIST_CREDENTIAL,
        },
        vc_zkp::EXAMPLE_CREDENTIAL_SCHEMA,
        vc_zkp::EXAMPLE_CREDENTIAL_SCHEMA_FIVE_PROPERTIES,
    };
    use serde_json::Value;

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
        let holder_address = SIGNER_1_ADDRESS;
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

        Verifier::verify_proof(
            &presentation,
            &proof_request,
            &keys_to_schema_map,
            holder_address,
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
        // assert!(false, serde_json::to_string(&presentation)?);
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

        match Verifier::verify_proof(
            &presentation,
            &proof_request,
            &keys_to_schema_map,
            holder_address,
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

        match Verifier::verify_proof(
            &presentation,
            &proof_request,
            &keys_to_schema_map,
            holder_address,
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

        match Verifier::verify_proof(
            &presentation,
            &proof_request,
            &keys_to_schema_map,
            holder_address,
        ) {
            Ok(_) => assert!(false, "This test should have failed"),
            Err(e) => assert_eq!(
                "Invalid presentation: No credentials provided",
                format!("{}", e)
            ),
        }
        Ok(())
    }
}
