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

use super::datatypes::{
    BbsCredential,
    BbsCredentialOffer,
    BbsCredentialRequest,
    BbsPresentation,
    BbsProofRequest,
    CredentialProposal,
    CredentialSchema,
    CredentialSubject,
    ProofPresentation,
    UnfinishedBbsCredential,
    UnfinishedProofPresentation,
    CREDENTIAL_PROPOSAL_TYPE,
    CREDENTIAL_REQUEST_TYPE,
    DEFAULT_CREDENTIAL_CONTEXTS,
};
use crate::{
    application::utils::{generate_uuid, get_nonce_from_string, get_now_as_iso_string},
    crypto::{crypto_prover::CryptoProver, crypto_utils::create_assertion_proof},
};
use bbs::{
    keys::DeterministicPublicKey,
    pok_sig::PoKOfSignature,
    signature::BlindSignature,
    SignatureBlinding,
    SignatureMessage,
    ToVariableLengthBytes,
};
use std::{
    collections::HashMap,
    convert::{From, TryInto},
    error::Error,
};
use vade_evan_substrate::signing::Signer;

pub struct Prover {}

impl Prover {
    /// Create a new credential proposal to send to a potential issuer.
    ///
    /// # Arguments
    /// * `issuer_did` - DID of the issuer the proposal is for
    /// * `subject_did` - DID of the proposal creator and potential subject of the credential
    /// * `schema_did` - DID of the schema to propose the credential for
    ///
    /// # Returns
    /// * `CredentialProposal` - The message to be sent to an issuer
    pub fn propose_credential(
        issuer_did: &str,
        subject_did: &str,
        schema_did: &str,
    ) -> CredentialProposal {
        CredentialProposal {
            issuer: issuer_did.to_owned(),
            subject: subject_did.to_owned(),
            schema: schema_did.to_owned(),
            r#type: CREDENTIAL_PROPOSAL_TYPE.to_string(),
        }
    }

    /// Request a new credential based on a received credential offering.
    ///
    /// # Arguments
    /// * `credential_offering` - The received credential offering sent by the potential issuer
    /// * `credential_schema` - The requested credential schema
    /// * `master_secret` - The master secret to be incorporated as a blinded value to be signed by the issuer
    /// * `credential_values` - A mapping of property names to their stringified cleartext values
    /// * `issuer_pub_key` - Public key of the issuer
    /// * `credential_message_count` - Number of messages to be signed in this credential by the issuer (all required schema properties + the optional ones the prover wants to provide values for)
    ///
    /// # Returns
    /// * `BbsCredentialRequest` - The request to be sent to the issuer
    /// * `SignatureBlinding` - Blinding that is needed for finishing the issued credential
    pub fn request_credential(
        credential_offering: &BbsCredentialOffer,
        credential_schema: &CredentialSchema,
        master_secret: &SignatureMessage,
        credential_values: HashMap<String, String>,
        issuer_pub_key: &DeterministicPublicKey,
    ) -> Result<(BbsCredentialRequest, SignatureBlinding), Box<dyn Error>> {
        if credential_values.len() == 0 {
            return Err(Box::from(
                "Cannot create blind signature context. Provided no credential values",
            ));
        }

        for required in &credential_schema.required {
            if credential_values.get(required).is_none() {
                let error = format!(
                    "Cannot request credential: Missing required schema property: {}",
                    required
                );
                return Err(Box::from(error));
            }
        }

        let nonce = get_nonce_from_string(&credential_offering.nonce)?;
        let (blind_signature_context, blinding) = CryptoProver::create_blind_signature_context(
            &issuer_pub_key,
            &master_secret,
            &nonce,
            credential_offering.credential_message_count,
        )
        .map_err(|e| {
            format!(
                "Cannot request credential: Could not create signature blinding: {}",
                e
            )
        })?;

        Ok((
            BbsCredentialRequest {
                schema: credential_schema.id.clone(),
                subject: credential_offering.subject.clone(),
                r#type: CREDENTIAL_REQUEST_TYPE.to_string(),
                credential_values: credential_values,
                blind_signature_context: base64::encode(
                    blind_signature_context.to_bytes_compressed_form(),
                ),
            },
            blinding,
        ))
    }

    /// Incorporate values into the signature that have previously been provided as blinded values to the issuer
    ///
    /// # Arguments
    /// * `unfinished_credential` - The credential received from the issuer
    /// * `master_secret` - The master secret to be incorporated as a blinded value to be signed by the issuer
    /// * `nquads` - The credential, minus the proof part, transformed to nquads
    /// * `issuer_public_key` - Public key of the issuer
    /// * `blinding` - Blinding previously created by the prover during credential request creation
    ///
    /// # Returns
    /// * `BbsCredential` - The final credential that can be used to derive proofs
    pub fn finish_credential(
        unfinished_credential: &UnfinishedBbsCredential,
        master_secret: &SignatureMessage,
        nquads: &Vec<String>,
        issuer_public_key: &DeterministicPublicKey,
        blinding: &SignatureBlinding,
    ) -> Result<BbsCredential, Box<dyn Error>> {
        let raw: Box<[u8]> =
            base64::decode(unfinished_credential.proof.blind_signature.clone())?.into_boxed_slice();
        let blind_signature: BlindSignature = raw.try_into()?;
        let final_signature = CryptoProver::finish_credential_signature(
            nquads.clone(),
            master_secret,
            issuer_public_key,
            &blind_signature,
            blinding,
        )?;

        let credential = BbsCredential::new(
            unfinished_credential.clone(),
            base64::encode(final_signature.to_bytes_compressed_form()),
        );
        Ok(credential)
    }

    /// Derive a proof from a `BbsCredential` revealing the requested properties
    ///
    /// # Arguments
    /// * `proof_request` - A verifier's proof request
    /// * `credential_schema_map` - Mapping of requested credential schemas (DIDs) to the relevant credentials
    /// * `revealed_properties_schema_map` - Mapping of requested credential schemas (DIDs) to the required indices to be revealed
    /// * `public_key_schema_map` - Mapping of requested credential schemas (DIDs) to the public keys associated to the respective signature
    /// * `nquads_schema_map` - Mapping of requested credential schemas (DIDs) to the nquads of the respective `BbsCredential`
    /// * `master_secret` - The master secret of the prover
    /// * `prover_did` - DID of the prover
    /// * `prober_public_key_did` - DID of the prover's public key to use to check the presentation's assertion proof
    /// * `prover_proving_key` - Secret key of the prover to use to create an `AssertionProof` over the presentation
    /// * `signer` . Signer to use to create the `AssertionProof` jws
    ///
    /// # Returns
    /// * `ProofPresentation` - The requested proof presentation
    pub async fn present_proof(
        proof_request: &BbsProofRequest,
        credential_schema_map: &HashMap<String, BbsCredential>,
        revealed_properties_schema_map: &HashMap<String, CredentialSubject>,
        public_key_schema_map: &HashMap<String, DeterministicPublicKey>,
        nquads_schema_map: &HashMap<String, Vec<String>>,
        master_secret: &SignatureMessage,
        prover_did: &str,
        prover_public_key_did: &str,
        prover_proving_key: &str,
        signer: &Box<dyn Signer>,
    ) -> Result<ProofPresentation, Box<dyn Error>> {
        let mut poks: HashMap<String, PoKOfSignature> = HashMap::new();
        for sub_proof_request in &proof_request.sub_proof_requests {
            let credential: BbsCredential = credential_schema_map
                .get(&sub_proof_request.schema)
                .ok_or(format!(
                    "Cannot create proof because credential is missing for schema {}",
                    &sub_proof_request.schema
                ))?
                .clone();
            let dpk = public_key_schema_map
                .get(&sub_proof_request.schema)
                .ok_or(format!(
                    "Cannot create proof because public key is missing for schema {}",
                    &sub_proof_request.schema
                ))?;
            let nquads = nquads_schema_map
                .get(&sub_proof_request.schema)
                .ok_or(format!(
                    "Cannot create proof because nquads are missing for schema {}",
                    &sub_proof_request.schema
                ))?
                .clone();

            let proof_of_knowledge = CryptoProver::create_proof_of_knowledge(
                sub_proof_request,
                &credential.proof.signature,
                &dpk,
                &master_secret,
                nquads,
            )?;

            poks.insert(sub_proof_request.schema.clone(), proof_of_knowledge);
        }
        let nonce = get_nonce_from_string(&proof_request.nonce)?;
        let proofs = CryptoProver::generate_proofs(poks, nonce)?;

        let mut presentation_credentials: Vec<BbsPresentation> = Vec::new();
        for (schema, proof) in proofs {
            let data_to_proof: BbsCredential = credential_schema_map
                .get(&schema)
                .ok_or(format!("Missing credential for schema {}", &schema))?
                .clone();
            let revealed_subject = revealed_properties_schema_map
                .get(&schema)
                .ok_or(format!(
                    "Missing revealed properties for schema {}",
                    &schema
                ))?
                .clone();
            let issuance_date = get_now_as_iso_string();
            let proof_cred =
                BbsPresentation::new(data_to_proof, issuance_date, proof, revealed_subject, nonce);

            presentation_credentials.insert(presentation_credentials.len(), proof_cred);
        }

        let signatureless_presentation = UnfinishedProofPresentation {
            context: DEFAULT_CREDENTIAL_CONTEXTS
                .iter()
                .map(|c| String::from(c.to_owned()))
                .collect::<Vec<_>>(),
            id: generate_uuid(),
            r#type: vec!["VerifiablePresentation".to_string()],
            verifiable_credential: presentation_credentials.clone(),
        };

        let document_to_sign = serde_json::to_value(&signatureless_presentation)?;
        let proof = create_assertion_proof(
            &document_to_sign,
            &prover_public_key_did,
            &prover_did,
            &prover_proving_key,
            signer,
        )
        .await?;

        Ok(ProofPresentation::new(signatureless_presentation, proof))
    }
}

#[cfg(test)]
mod tests {
    extern crate utilities;
    use super::*;
    use crate::{
        application::utils::{get_dpk_from_string, get_signature_message_from_string},
        crypto::crypto_utils::check_assertion_proof,
    };
    use bbs::{
        issuer::Issuer as BbsIssuer,
        keys::SecretKey,
        prover::Prover as BbsProver,
        SignatureBlinding,
    };
    use utilities::test_data::{
        accounts::local::{
            HOLDER_DID,
            ISSUER_DID,
            SIGNER_1_ADDRESS,
            SIGNER_1_PRIVATE_KEY,
            VERIFIER_DID,
        },
        bbs_coherent_context_test_data::{
            FINISHED_CREDENTIAL,
            MASTER_SECRET,
            NQUADS,
            PROOF_REQUEST_SCHEMA_FIVE_PROPERTIES,
            PUB_KEY,
            SIGNATURE_BLINDING,
            UNFINISHED_CREDENTIAL,
        },
        vc_zkp::{EXAMPLE_CREDENTIAL_OFFERING, EXAMPLE_CREDENTIAL_SCHEMA},
    };
    use vade_evan_substrate::signing::{LocalSigner, Signer};

    fn setup_test() -> Result<
        (
            DeterministicPublicKey,
            SecretKey,
            BbsCredentialOffer,
            CredentialSchema,
            SignatureMessage,
            HashMap<String, String>,
        ),
        Box<dyn Error>,
    > {
        let (dpk, sk) = BbsIssuer::new_short_keys(None);
        let offering: BbsCredentialOffer = serde_json::from_str(EXAMPLE_CREDENTIAL_OFFERING)?;
        let schema: CredentialSchema = serde_json::from_str(EXAMPLE_CREDENTIAL_SCHEMA)?;
        let secret = BbsProver::new_link_secret();
        let mut credential_values = HashMap::new();
        credential_values.insert("test_property_string".to_owned(), "value".to_owned());

        return Ok((dpk, sk, offering, schema, secret, credential_values));
    }

    fn get_creat_proof_data() -> Result<
        (
            BbsProofRequest,
            HashMap<String, BbsCredential>,
            HashMap<String, CredentialSubject>,
            HashMap<String, DeterministicPublicKey>,
            HashMap<String, Vec<String>>,
        ),
        Box<dyn Error>,
    > {
        let credential: BbsCredential = serde_json::from_str(&FINISHED_CREDENTIAL)?;
        let proof_request: BbsProofRequest =
            serde_json::from_str(&PROOF_REQUEST_SCHEMA_FIVE_PROPERTIES)?;
        let schema_id = &proof_request.sub_proof_requests[0].schema;

        let mut credential_map = HashMap::new();
        credential_map.insert(schema_id.clone(), credential.clone());

        // Just reveal properties 1 and 2
        let mut revealed_data = credential.credential_subject.data.clone();
        revealed_data.remove("test_property_string2");
        revealed_data.remove("test_property_string3");
        revealed_data.remove("test_property_string4");

        let revealed = CredentialSubject {
            id: HOLDER_DID.to_string(),
            data: revealed_data,
        };
        let mut revealed_properties_map = HashMap::new();
        revealed_properties_map.insert(schema_id.clone(), revealed);

        let nquads: Vec<String> = NQUADS
            .iter()
            .map(|q| q.to_string())
            .collect::<Vec<String>>();
        let mut nquads_schema_map = HashMap::new();
        nquads_schema_map.insert(schema_id.clone(), nquads);

        let public_key: DeterministicPublicKey = get_dpk_from_string(&PUB_KEY)?;
        let mut public_key_schema_map = HashMap::new();
        public_key_schema_map.insert(schema_id.clone(), public_key);

        Ok((
            proof_request,
            credential_map,
            revealed_properties_map,
            public_key_schema_map,
            nquads_schema_map,
        ))
    }

    fn assert_proof(
        proof: ProofPresentation,
        proof_request: BbsProofRequest,
        revealed_properties_map: HashMap<String, CredentialSubject>,
    ) -> Result<(), Box<dyn Error>> {
        // Assert proof frame
        assert_eq!(
            proof.context.clone().as_slice(),
            DEFAULT_CREDENTIAL_CONTEXTS
        );
        assert_eq!(proof.r#type.clone(), vec!["VerifiablePresentation"]);
        check_assertion_proof(&serde_json::to_string(&proof)?, SIGNER_1_ADDRESS)?;
        assert_eq!(proof.verifiable_credential.len(), 1);

        // Assert proof credential
        let proof_cred = &proof.verifiable_credential[0];
        let schema_id = &proof_request.sub_proof_requests[0].schema;
        let new_credential_subject = revealed_properties_map
            .get(schema_id)
            .ok_or("Error!")?
            .clone();
        assert_eq!(proof_cred.credential_subject.id, new_credential_subject.id);
        // Only reveals the provided subject data, not the credential's original subject data
        assert_eq!(
            proof_cred.credential_subject.data,
            new_credential_subject.data
        );
        assert_eq!(proof_cred.credential_schema.id, schema_id.to_string());
        assert_eq!(proof_cred.issuer, ISSUER_DID);

        // proof object of proof credential is okay
        assert_eq!(
            proof_cred.proof.r#type,
            "BbsBlsSignatureProof2020".to_owned()
        );
        assert_eq!(proof_cred.proof.nonce, proof_request.nonce);

        Ok(())
    }

    #[test]
    fn can_propose_credential() {
        let proposal = Prover::propose_credential(&ISSUER_DID, &HOLDER_DID, "schemadid");
        assert_eq!(&proposal.subject, &HOLDER_DID);
        assert_eq!(&proposal.issuer, &ISSUER_DID);
        assert_eq!(&proposal.schema, "schemadid");
        assert_eq!(&proposal.r#type, CREDENTIAL_PROPOSAL_TYPE);
    }

    #[test]
    fn can_request_credential() -> Result<(), Box<dyn Error>> {
        let (dpk, _, offering, schema, secret, credential_values) = setup_test()?;
        let (credential_request, _) =
            Prover::request_credential(&offering, &schema, &secret, credential_values, &dpk)
                .map_err(|e| format!("{}", e))?;
        assert_eq!(credential_request.schema, schema.id);
        assert_eq!(credential_request.subject, offering.subject);
        assert_eq!(credential_request.r#type, CREDENTIAL_REQUEST_TYPE);
        Ok(())
    }

    #[test]
    fn throws_when_omitting_required_credential_value() -> Result<(), Box<dyn Error>> {
        let (dpk, _, offering, schema, secret, mut credential_values) = setup_test()?;
        let message_len = &credential_values.len() + 1; /* +1 for master secret */
        credential_values.remove("test_property_string");
        match Prover::request_credential(&offering, &schema, &secret, credential_values, &dpk) {
            Ok(_) => assert!(false),
            Err(e) => assert_eq!(
                format!("{}", e),
                "Cannot create blind signature context. Provided no credential values"
            ),
        }
        Ok(())
    }

    #[test]
    fn can_finish_credential() -> Result<(), Box<dyn Error>> {
        let unfinished_credential: UnfinishedBbsCredential =
            serde_json::from_str(&UNFINISHED_CREDENTIAL)?;
        let master_secret: SignatureMessage = get_signature_message_from_string(&MASTER_SECRET)?;
        let nquads: Vec<String> = NQUADS.iter().map(|q| q.to_string()).collect();
        let public_key: DeterministicPublicKey = get_dpk_from_string(&PUB_KEY)?;
        let blinding: SignatureBlinding =
            SignatureBlinding::from(base64::decode(&SIGNATURE_BLINDING)?.into_boxed_slice());

        match Prover::finish_credential(
            &unfinished_credential,
            &master_secret,
            &nquads,
            &public_key,
            &blinding,
        ) {
            Ok(cred) => {
                // There is now a property 'signature' and it is base64 encoded
                assert!(base64::decode(&cred.proof.signature).is_ok());
            }
            Err(e) => {
                assert!(false, "Unexpected error when finishing credential: {}", e);
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn can_create_proof_presentation() -> Result<(), Box<dyn Error>> {
        let (
            proof_request,
            credential_map,
            revealed_properties_map,
            public_key_schema_map,
            nquads_schema_map,
        ) = get_creat_proof_data()?;

        let master_secret: SignatureMessage =
            SignatureMessage::from(base64::decode(&MASTER_SECRET)?.into_boxed_slice());
        let holder_secret_key = SIGNER_1_PRIVATE_KEY;

        let signer: Box<dyn Signer> = Box::new(LocalSigner::new());

        let proof = Prover::present_proof(
            &proof_request,
            &credential_map,
            &revealed_properties_map,
            &public_key_schema_map,
            &nquads_schema_map,
            &master_secret,
            &VERIFIER_DID,
            &format!("{}#key-1", VERIFIER_DID),
            holder_secret_key,
            &signer,
        )
        .await?;

        assert_proof(proof.clone(), proof_request, revealed_properties_map)?;

        Ok(())
    }
}
