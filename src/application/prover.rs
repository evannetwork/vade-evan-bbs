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

use super::{
    datatypes::{
        BbsCredential,
        BbsCredentialRequest,
        BbsPresentation,
        BbsProofRequest,
        CredentialProposal,
        CredentialSchema,
        CredentialSubject,
        ProofPresentation,
        UnfinishedBbsCredential,
        UnfinishedProofPresentation,
        DEFAULT_CREDENTIAL_CONTEXTS,
    },
    utils::{
        check_for_required_reveal_index0,
        concat_required_and_reveal_statements,
        get_nonce_from_string,
    },
};
use crate::{
    application::utils::generate_uuid,
    crypto::{crypto_prover::CryptoProver, crypto_utils::create_assertion_proof},
    BbsCredentialOffer,
};
use bbs::{
    keys::DeterministicPublicKey,
    pok_sig::PoKOfSignature,
    prover::Prover as BbsProver,
    SignatureBlinding,
    SignatureMessage,
    ToVariableLengthBytes,
};

use std::{collections::HashMap, convert::From, error::Error};
use vade_signer::Signer;

pub struct Prover {}

impl Prover {
    /// Create a new credential proposal to send to a potential issuer.
    ///
    /// # Arguments
    /// * `issuer_did` - DID of the issuer the proposal is for
    /// * `schema_did` - DID of the schema to propose the credential for
    ///
    /// # Returns
    /// * `CredentialProposal` - The message to be sent to an issuer
    pub fn propose_credential(issuer_did: &str, schema_did: &str) -> CredentialProposal {
        CredentialProposal {
            issuer: issuer_did.to_owned(),
            schema: schema_did.to_owned(),
        }
    }

    /// Request a new credential based on a received credential offering.
    ///
    /// # Arguments
    /// * `ld_proof_vc_detail` - details about credential to be requested
    /// * `nonce` -  nonce from offer
    /// * `credential_schema` - The requested credential schema
    /// * `master_secret` - The master secret to be incorporated as a blinded value to be signed by the issuer
    /// * `issuer_pub_key` - Public key of the issuer
    ///
    /// # Returns
    /// * `BbsCredentialRequest` - The request to be sent to the issuer
    /// * `SignatureBlinding` - Blinding that is needed for finishing the issued credential
    pub fn request_credential(
        credential_offer: &BbsCredentialOffer,
        credential_schema: &CredentialSchema,
        master_secret: &SignatureMessage,
        issuer_pub_key: &DeterministicPublicKey,
    ) -> Result<(BbsCredentialRequest, SignatureBlinding), Box<dyn Error>> {
        if credential_offer
            .ld_proof_vc_detail
            .credential
            .credential_subject
            .data
            .len()
            == 0
        {
            return Err(Box::from(
                "Cannot create blind signature context. Provided no credential values",
            ));
        }

        for required in &credential_schema.required {
            if credential_offer
                .ld_proof_vc_detail
                .credential
                .credential_subject
                .data
                .get(required)
                .is_none()
            {
                let error = format!(
                    "Cannot request credential: Missing required schema property: {}",
                    required
                );
                return Err(Box::from(error));
            }
        }

        let nonce = get_nonce_from_string(&credential_offer.nonce)?;
        let (blind_signature_context, blinding) = CryptoProver::create_blind_signature_context(
            &issuer_pub_key,
            &master_secret,
            &nonce,
            credential_offer.ld_proof_vc_detail.get_message_count()?,
        )
        .map_err(|e| {
            format!(
                "Cannot request credential: Could not create signature blinding: {}",
                e
            )
        })?;

        Ok((
            BbsCredentialRequest {
                credential_offer: credential_offer.to_owned(),
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
        check_for_required_reveal_index0(&unfinished_credential.proof.required_reveal_statements)?;
        let final_signature = CryptoProver::finish_credential_signature(
            nquads.clone(),
            master_secret,
            issuer_public_key,
            &unfinished_credential.proof,
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
        let mut proof_request = proof_request.to_owned();
        for sub_proof_request in &mut proof_request.sub_proof_requests {
            let credential: BbsCredential = credential_schema_map
                .get(&sub_proof_request.schema)
                .ok_or(format!(
                    "Cannot create proof because credential is missing for schema {}",
                    &sub_proof_request.schema
                ))?
                .clone();

            let required_reveal_statements = &credential.proof.required_reveal_statements;
            check_for_required_reveal_index0(&required_reveal_statements)?;
            let revealed_statements = &sub_proof_request.revealed_attributes;
            let all_revealed_statements = concat_required_and_reveal_statements(
                required_reveal_statements,
                revealed_statements,
            )?;
            sub_proof_request.revealed_attributes = all_revealed_statements;

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
                &credential.proof,
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
            let proof_cred = BbsPresentation::new(data_to_proof, proof, revealed_subject, nonce);

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

    /// Creates a new master secret
    ///
    /// # Returns
    /// * `String` - Base64-encoded bytes representation of the master secret
    pub fn create_master_secret() -> String {
        return base64::encode(BbsProver::new_link_secret().to_bytes_compressed_form());
    }
}

#[cfg(test)]
mod tests {
    extern crate utilities;
    use super::*;
    use crate::{
        application::{
            datatypes::BbsCredentialOffer,
            utils::{
                convert_to_nquads,
                decode_base64,
                get_dpk_from_string,
                get_now_as_iso_string,
                get_signature_message_from_string,
            },
        },
        crypto::crypto_utils::check_assertion_proof,
        CredentialDraftOptions,
        LdProofVcDetail,
        LdProofVcDetailOptions,
        LdProofVcDetailOptionsCredentialStatus,
        LdProofVcDetailOptionsCredentialStatusType,
        LdProofVcDetailOptionsType,
        UnsignedBbsCredential,
    };
    use bbs::{
        issuer::Issuer as BbsIssuer,
        keys::SecretKey,
        prover::Prover as BbsProver,
        SignatureBlinding,
    };
    use utilities::test_data::{
        accounts::local::{ISSUER_DID, SIGNER_1_ADDRESS, SIGNER_1_PRIVATE_KEY, VERIFIER_DID},
        bbs_coherent_context_test_data::{
            FINISHED_CREDENTIAL,
            MASTER_SECRET,
            PROOF_REQUEST_SCHEMA_FIVE_PROPERTIES,
            PUB_KEY,
            SCHEMA,
            SIGNATURE_BLINDING,
            UNFINISHED_CREDENTIAL,
        },
    };
    use vade_signer::{LocalSigner, Signer};

    fn setup_test() -> Result<
        (
            DeterministicPublicKey,
            SecretKey,
            BbsCredentialOffer,
            CredentialSchema,
            SignatureMessage,
        ),
        Box<dyn Error>,
    > {
        let (dpk, sk) = BbsIssuer::new_short_keys(None);
        let schema: CredentialSchema = serde_json::from_str(SCHEMA)?;
        let mut credential_draft = schema.to_draft_credential(CredentialDraftOptions {
            issuer_did: ISSUER_DID.to_string(),
            id: None,
            issuance_date: None,
            valid_until: None,
        });
        credential_draft
            .credential_subject
            .data
            .insert("test_property_string".to_owned(), "value".to_owned());
        let offering: BbsCredentialOffer = BbsCredentialOffer {
            ld_proof_vc_detail: LdProofVcDetail {
                credential: credential_draft,
                options: LdProofVcDetailOptions {
                    created: get_now_as_iso_string(),
                    proof_type: LdProofVcDetailOptionsType::Ed25519Signature2018,
                    credential_status: LdProofVcDetailOptionsCredentialStatus {
                        r#type:
                            LdProofVcDetailOptionsCredentialStatusType::RevocationList2021Status,
                    },
                    required_reveal_statements: vec![1]
                },
        },
        nonce: "WzM0LDIxNSwyNDEsODgsMTg2LDExMiwyOSwxNTksNjUsMjE1LDI0MiwxNjQsMTksOCwyMDEsNzgsNTUsMTA4LDE1NCwxMTksMTg0LDIyNCwyMjUsNDAsNDgsMTgwLDY5LDE3OCwxNDgsNSw1OSwxMTFd".to_string(), };
        let secret = BbsProver::new_link_secret();

        return Ok((dpk, sk, offering, schema, secret));
    }

    async fn get_create_proof_data() -> Result<
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
            id: None,
            data: revealed_data,
        };
        let mut revealed_properties_map = HashMap::new();
        revealed_properties_map.insert(schema_id.clone(), revealed);

        let mut nquads_schema_map: HashMap<String, Vec<String>> = HashMap::new();
        let unfinished_without_proof: UnsignedBbsCredential =
            serde_json::from_str(&serde_json::to_string(&credential)?)?;
        let nquads = convert_to_nquads(&serde_json::to_string(&unfinished_without_proof)?).await?;
        nquads_schema_map.insert(schema_id.to_owned(), nquads);

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
        let proposal = Prover::propose_credential(&ISSUER_DID, "schema-did");
        assert_eq!(&proposal.issuer, &ISSUER_DID);
        assert_eq!(&proposal.schema, "schema-did");
    }

    #[test]
    fn can_request_credential() -> Result<(), Box<dyn Error>> {
        let (dpk, _, offering, schema, secret) = setup_test()?;
        let (credential_request, _) = Prover::request_credential(&offering, &schema, &secret, &dpk)
            .map_err(|e| format!("{}", e))?;
        assert_eq!(
            credential_request
                .credential_offer
                .ld_proof_vc_detail
                .credential
                .credential_schema
                .id,
            schema.id
        );
        Ok(())
    }

    #[test]
    fn throws_when_omitting_required_credential_value() -> Result<(), Box<dyn Error>> {
        let (dpk, _, mut offering, schema, secret) = setup_test()?;
        offering
            .ld_proof_vc_detail
            .credential
            .credential_subject
            .data
            .remove("test_property_string");
        match Prover::request_credential(&offering, &schema, &secret, &dpk) {
            Ok(_) => assert!(false),
            Err(e) => assert_eq!(
                format!("{}", e),
                "Cannot request credential: Missing required schema property: test_property_string"
            ),
        }
        Ok(())
    }

    #[tokio::test]
    async fn can_finish_credential() -> Result<(), Box<dyn Error>> {
        let unfinished_credential: UnfinishedBbsCredential =
            serde_json::from_str(&UNFINISHED_CREDENTIAL)?;
        let master_secret: SignatureMessage = get_signature_message_from_string(&MASTER_SECRET)?;
        let unfinished_without_proof: UnsignedBbsCredential =
            serde_json::from_str(&serde_json::to_string(&unfinished_credential)?)?;
        let nquads = convert_to_nquads(&serde_json::to_string(&unfinished_without_proof)?).await?;
        let public_key: DeterministicPublicKey = get_dpk_from_string(&PUB_KEY)?;
        let blinding: SignatureBlinding = SignatureBlinding::from(
            decode_base64(&SIGNATURE_BLINDING, "Signature Blinding")?.into_boxed_slice(),
        );

        match Prover::finish_credential(
            &unfinished_credential,
            &master_secret,
            &nquads,
            &public_key,
            &blinding,
        ) {
            Ok(cred) => {
                // There is now a property 'signature' and it is base64 encoded
                assert!(decode_base64(&cred.proof.signature, "Proof Signature").is_ok());
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
        ) = get_create_proof_data().await?;

        let master_secret: SignatureMessage = SignatureMessage::from(
            decode_base64(&MASTER_SECRET, "Master Secret")?.into_boxed_slice(),
        );
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
