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

use super::datatypes::SchemaProperty;
use crate::{
    application::{
        datatypes::{
            BbsCredentialOffer,
            BbsCredentialRequest,
            BbsUnfinishedCredentialSignature,
            CredentialProposal,
            CredentialSchema,
            CredentialSchemaReference,
            CredentialStatus,
            CredentialSubject,
            RevocationListCredential,
            RevocationListCredentialSubject,
            UnfinishedBbsCredential,
            UnproofedRevocationListCredential,
            CREDENTIAL_OFFER_TYPE,
            CREDENTIAL_PROOF_PURPOSE,
            CREDENTIAL_SCHEMA_TYPE,
            CREDENTIAL_SIGNATURE_TYPE,
            DEFAULT_CREDENTIAL_CONTEXTS,
            DEFAULT_REVOCATION_CONTEXTS,
        },
        utils::{generate_uuid, get_now_as_iso_string},
    },
    crypto::{crypto_issuer::CryptoIssuer, crypto_utils::create_assertion_proof},
};
use bbs::{
    issuer::Issuer as BbsIssuer,
    keys::{DeterministicPublicKey, SecretKey},
    BlindSignatureContext,
    ProofNonce,
};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use std::{collections::HashMap, convert::TryInto, error::Error, io::prelude::*};
use vade_evan_substrate::signing::Signer;

pub struct Issuer {}

const MAX_REVOCATION_ENTRIES: usize = 131072;

// Master secret is always incorporated, without being mentioned in the credential schema
pub const ADDITIONAL_HIDDEN_MESSAGES_COUNT: usize = 1;

impl Issuer {
    /// Creates a new credential schema specifying properties credentials issued under this schema need to incorporate.
    /// The schema needs to be stored in a publicly available and temper-proof way.
    ///
    /// # Arguments
    /// * `assigned_did` - DID to be used to resolve this credential definition
    /// * `issuer_did` - DID of the issuer
    /// * `schema_name` - Name of the schema
    /// * `description` - Description for the schema. Can be left blank
    /// * `properties` - The properties of the schema as Key-Object pairs#
    /// * `required_properties` - The keys of properties that need to be provided when issuing a credential under this schema.
    /// * `allow_additional_properties` - Specifies whether a credential under this schema is considered valid if it specifies more properties than the schema specifies.
    /// * `issuer_public_key_did` - DID of the public key to check the assertion proof of the definition document
    /// * `issuer_proving_key` - Private key used to create the assertion proof
    /// * `signer` - `Signer` to sign with
    ///
    /// # Returns
    /// * `CredentialSchema` - The schema object to be saved in a publicly available and temper-proof way
    pub async fn create_credential_schema(
        assigned_did: &str,
        issuer_did: &str,
        schema_name: &str,
        description: &str,
        properties: HashMap<String, SchemaProperty>,
        required_properties: Vec<String>,
        allow_additional_properties: bool,
        issuer_public_key_did: &str,
        issuer_proving_key: &str,
        signer: &Box<dyn Signer>,
    ) -> Result<CredentialSchema, Box<dyn Error>> {
        let created_at = get_now_as_iso_string();

        let mut schema = CredentialSchema {
            id: assigned_did.to_owned(),
            r#type: "EvanVCSchema".to_string(),
            name: schema_name.to_owned(),
            author: issuer_did.to_owned(),
            created_at,
            description: description.to_owned(),
            properties,
            required: required_properties,
            additional_properties: allow_additional_properties,
            proof: None,
        };

        let document_to_sign = serde_json::to_value(&schema)?;

        let proof = create_assertion_proof(
            &document_to_sign,
            &issuer_public_key_did,
            &issuer_did,
            &issuer_proving_key,
            &signer,
        )
        .await?;

        schema.proof = Some(proof);

        Ok(schema)
    }

    /// Creates a new credential offer, as a response to a `CredentialProposal` sent by a prover.
    ///
    /// # Arguments
    /// * `credential_proposal` - The proposal to respond to
    /// * `issuer_did` - DID of the issuer that is supposed to issue the offer
    ///
    /// # Returns
    /// * `BbsCredentialOffer` - The message to be sent to the prover.
    pub fn offer_credential(
        credential_proposal: &CredentialProposal,
        issuer_did: &str,
        nquad_count: usize,
    ) -> Result<BbsCredentialOffer, Box<dyn Error>> {
        let nonce = base64::encode(BbsIssuer::generate_signing_nonce().to_bytes_compressed_form());
        if credential_proposal.issuer != issuer_did {
            return Err(Box::from(
                "Cannot offer credential: Proposal is not targeted at this issuer",
            ));
        }

        Ok(BbsCredentialOffer {
            issuer: issuer_did.to_owned(),
            subject: credential_proposal.subject.to_owned(),
            r#type: CREDENTIAL_OFFER_TYPE.to_string(),
            schema: credential_proposal.schema.to_owned(),
            credential_message_count: nquad_count + ADDITIONAL_HIDDEN_MESSAGES_COUNT,
            nonce,
        })
    }

    /// Issues a new unfinished credential, that still needs post-processing by the credential subject.
    ///
    /// # Arguments
    /// * `issuer_did` - DID of the issuer
    /// * `subject_did` - DID of the subject
    /// * `credential_offer` - Credential offer object sent by the issuer
    /// * `credential_request` - Credential request object sent by the subject
    /// * `issuer_public_key_id` - DID of the public key associated with the created signature
    /// * `issuer_public_key` - Public key associated with the created signature
    /// * `issuer_secret_key` - Secret key to create the signature with
    /// * `credential_schema` - Credential schema to be used as specified by the credential request
    /// * `required_indices` - Indices of the nquads representing the properties that need to be revealed when creating proofs
    /// * `nquads` - The properties that need to be signed as nquads. Usually should include the whole document, not only the credential_subject part.
    /// * `revocation_list_did` - DID of the associated revocation list
    /// * `revocation_list_id` - ID of the revoation list to assign to this credential
    ///
    /// # Returns
    /// * `UnfinishedBbsCredential` - Credential including signature that needs to be post-processed by the subject
    pub fn issue_credential(
        issuer_did: &str,
        subject_did: &str,
        credential_offer: &BbsCredentialOffer,
        credential_request: &BbsCredentialRequest,
        issuer_public_key_id: &str,
        issuer_public_key: &DeterministicPublicKey,
        issuer_secret_key: &SecretKey,
        credential_schema: CredentialSchema,
        required_indices: Vec<u32>,
        nquads: Vec<String>,
        revocation_list_did: &str,
        revocation_list_id: usize,
    ) -> Result<UnfinishedBbsCredential, Box<dyn Error>> {
        if revocation_list_id > MAX_REVOCATION_ENTRIES {
            let error = format!(
                "Cannot issue credential: revocation_list_id {} is larger than list limit of {}",
                revocation_list_id, MAX_REVOCATION_ENTRIES
            );
            return Err(Box::from(error));
        }

        let credential_subject = CredentialSubject {
            id: subject_did.to_owned(),
            data: credential_request.credential_values.clone(),
        };

        let schema_reference = CredentialSchemaReference {
            id: credential_schema.id,
            r#type: CREDENTIAL_SCHEMA_TYPE.to_string(),
        };

        let blind_signature_context: BlindSignatureContext =
            base64::decode(&credential_request.blind_signature_context)?
                .into_boxed_slice()
                .try_into()?;

        let nonce = ProofNonce::from(base64::decode(&credential_offer.nonce)?.into_boxed_slice());
        let blind_signature = CryptoIssuer::create_signature(
            &blind_signature_context,
            &nonce,
            nquads.clone(),
            issuer_public_key,
            issuer_secret_key,
        )
        .map_err(|e| format!("Error creating bbs+ signature: {}", e))?;

        let vc_signature = BbsUnfinishedCredentialSignature {
            r#type: CREDENTIAL_SIGNATURE_TYPE.to_string(),
            created: get_now_as_iso_string(),
            proof_purpose: CREDENTIAL_PROOF_PURPOSE.to_owned(),
            verification_method: issuer_public_key_id.to_owned(),
            required_reveal_statements: required_indices,
            credential_message_count: nquads.len() + ADDITIONAL_HIDDEN_MESSAGES_COUNT,
            blind_signature: base64::encode(blind_signature.to_bytes_compressed_form()),
        };

        let credential_id = generate_uuid();
        let credential = UnfinishedBbsCredential {
            context: DEFAULT_CREDENTIAL_CONTEXTS
                .iter()
                .map(|c| String::from(c.to_owned()))
                .collect::<Vec<_>>(),
            id: credential_id,
            r#type: vec!["VerifiableCredential".to_string()],
            issuer: issuer_did.to_owned(),
            credential_subject,
            credential_schema: schema_reference,
            credential_status: CredentialStatus {
                id: format!("{}#{}", revocation_list_did, revocation_list_id),
                r#type: "RevocationList2021Status".to_string(),
                revocation_list_index: revocation_list_id,
                revocation_list_credential: revocation_list_did.to_string(),
            },
            proof: vc_signature,
        };
        Ok(credential)
    }

    /// Creates a new revocation list. This list is used to store the revocation stat of a given credential id.
    /// It needs to be publicly published and updated after every revocation. The definition is signed by the issuer.
    ///
    /// # Arguments
    /// * `assigned_did` - DID that will point to the revocation list
    /// * `issuer_did` - DID of the issuer
    /// * `issuer_public_key_did` - DID of the public key that will be associated with the created signature
    /// * `issuer_proving_key` - Private key of the issuer used for signing the definition
    /// * `signer` - `Signer` to sign with
    ///
    /// # Returns
    /// * `RevocationListCredential` - The initial revocation list credential.
    pub async fn create_revocation_list(
        assigned_did: &str,
        issuer_did: &str,
        issuer_public_key_did: &str,
        issuer_proving_key: &str,
        signer: &Box<dyn Signer>,
    ) -> Result<RevocationListCredential, Box<dyn Error>> {
        let available_bytes = [0u8; MAX_REVOCATION_ENTRIES / 8];
        let mut gzip_encoder = GzEncoder::new(Vec::new(), Compression::default());
        gzip_encoder.write_all(&available_bytes)?;
        let compressed_bytes = gzip_encoder.finish();
        let unfinished_revocation_list = UnproofedRevocationListCredential {
            context: DEFAULT_REVOCATION_CONTEXTS
                .iter()
                .map(|c| String::from(c.to_owned()))
                .collect::<Vec<_>>(),
            id: assigned_did.to_owned(),
            r#type: vec![
                "VerifiableCredential".to_string(),
                "StatusList2021Credential".to_string(),
            ],
            issuer: issuer_public_key_did.to_owned(),
            issued: get_now_as_iso_string(),
            credential_subject: RevocationListCredentialSubject {
                id: format!("{}#{}", assigned_did, "list"),
                r#type: "RevocationList2021".to_string(),
                encoded_list: base64::encode_config(&compressed_bytes?, base64::URL_SAFE),
            },
        };

        let document_to_sign = serde_json::to_value(&unfinished_revocation_list)?;
        let proof = create_assertion_proof(
            &document_to_sign,
            &issuer_public_key_did,
            &issuer_did,
            &issuer_proving_key,
            &signer,
        )
        .await?;

        let revocation_list = RevocationListCredential::new(unfinished_revocation_list, proof);

        Ok(revocation_list)
    }

    /// Revokes a credential by flipping the specific index in the given revocation list.
    /// See <https://w3c-ccg.github.io/vc-status-rl-2020/#revocationlist2020credential> for reference
    /// # Arguments
    /// * `issuer` - DID of the issuer
    /// * `revocation_list` - Revocation list the credential belongs to
    /// * `revocation_id` - Revocation ID of the credential
    /// * `issuer_public_key_did` - DID of the public key that will be associated with the created signature
    /// * `issuer_proving_key` - Private key of the issuer used for signing the definition
    /// * `signer` - `Signer` to sign with
    ///
    /// # Returns
    /// * `RevocationListCredential` - The updated revocation list that needs to be stored in the original revocation list's place.
    pub async fn revoke_credential(
        issuer: &str,
        mut revocation_list: RevocationListCredential,
        revocation_id: usize,
        issuer_public_key_did: &str,
        issuer_proving_key: &str,
        signer: &Box<dyn Signer>,
    ) -> Result<RevocationListCredential, Box<dyn Error>> {
        if revocation_id > MAX_REVOCATION_ENTRIES {
            let error = format!(
                "Cannot revoke credential: revocation_id {} is larger than list limit of {}",
                revocation_id, MAX_REVOCATION_ENTRIES
            );
            return Err(Box::from(error));
        }

        let encoded_list = base64::decode_config(
            revocation_list.credential_subject.encoded_list.to_string(),
            base64::URL_SAFE,
        )?;
        let mut decoder = GzDecoder::new(&encoded_list[..]);
        let mut decoded_list = Vec::new();
        decoder.read_to_end(&mut decoded_list)?;

        let byte_index_float: f32 = (revocation_id / 8) as f32;
        let bit: u8 = 1 << (revocation_id % 8);
        let byte_index: usize = byte_index_float.floor() as usize;
        decoded_list[byte_index] |= bit;

        let mut gzip_encoder = GzEncoder::new(Vec::new(), Compression::default());
        gzip_encoder.write_all(&decoded_list)?;
        let compressed_bytes = gzip_encoder.finish()?;

        revocation_list.credential_subject.encoded_list =
            base64::encode_config(&compressed_bytes, base64::URL_SAFE);
        revocation_list.issued = get_now_as_iso_string();

        let document_to_sign = serde_json::to_value(&revocation_list)?;
        let proof = create_assertion_proof(
            &document_to_sign,
            &issuer_public_key_did,
            &issuer,
            &issuer_proving_key,
            &signer,
        )
        .await?;

        revocation_list.proof = proof;

        Ok(revocation_list)
    }
}

#[cfg(test)]
mod tests {
    extern crate utilities;
    use super::*;
    use crate::application::{
        datatypes::{BbsCredentialOffer, BbsCredentialRequest},
        prover::Prover,
    };
    use bbs::{issuer::Issuer as BbsIssuer, prover::Prover as BbsProver};
    use std::collections::HashMap;
    use utilities::test_data::{
        accounts::local::{HOLDER_DID, ISSUER_DID, ISSUER_PRIVATE_KEY, ISSUER_PUBLIC_KEY_DID},
        bbs_coherent_context_test_data::{
            EXAMPLE_REVOCATION_LIST_DID,
            PUB_KEY,
            REVOCATION_LIST_CREDENTIAL,
            SECRET_KEY,
        },
        vc_zkp::{EXAMPLE_CREDENTIAL_PROPOSAL, EXAMPLE_CREDENTIAL_SCHEMA},
    };
    use vade_evan_substrate::signing::{LocalSigner, Signer};

    fn request_credential(
        pub_key: &DeterministicPublicKey,
        offer: &BbsCredentialOffer,
    ) -> Result<(BbsCredentialRequest, CredentialSchema, Vec<String>), Box<dyn Error>> {
        let schema: CredentialSchema = serde_json::from_str(EXAMPLE_CREDENTIAL_SCHEMA)?;
        let secret = BbsProver::new_link_secret();
        let mut credential_values = HashMap::new();
        credential_values.insert("test_property_string".to_owned(), "value".to_owned());
        for i in 1..(offer.credential_message_count - 1) {
            // Create messages until we have message_count - 1 messages (one is reserved for master secret)
            credential_values.insert(format!("test_property_string{}", i), "value".to_owned());
        }

        // Nquad-ize. Flatten the json-ld document graph.
        // This will be done by TnT for now as we currently could not find a suitable rust library
        let mut nquads = Vec::new();
        let mut keys: Vec<String> = credential_values.keys().map(|k| k.to_string()).collect();
        keys.sort();
        for key in &keys {
            let val = credential_values.get(key).ok_or("AAA".to_owned())?;
            let string = format!("{}: {}", key, val);
            nquads.insert(nquads.len(), string);
        }

        let (credential_request, _) =
            Prover::request_credential(offer, &schema, &secret, credential_values, pub_key)
                .map_err(|e| format!("{}", e))?;

        return Ok((credential_request, schema, nquads));
    }

    fn is_base_64(input: String) -> bool {
        match base64::decode(input) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    fn assert_credential(
        credential_request: BbsCredentialRequest,
        cred: UnfinishedBbsCredential,
        pub_key_id: &str,
        schema_id: &str,
    ) {
        assert_eq!(&cred.issuer, ISSUER_DID);
        assert_eq!(&cred.credential_subject.id, HOLDER_DID);
        assert_eq!(&cred.credential_schema.id, schema_id);
        // proof
        assert_eq!(&cred.proof.required_reveal_statements, &[1].to_vec());
        assert_eq!(&cred.proof.r#type, CREDENTIAL_SIGNATURE_TYPE);
        assert_eq!(&cred.proof.proof_purpose, CREDENTIAL_PROOF_PURPOSE);
        assert_eq!(&cred.proof.verification_method, pub_key_id);
        assert!(
            is_base_64(cred.proof.blind_signature.to_owned()),
            "Signature seems not to be base64 encoded"
        );
        // Credential subject
        // Are the values correctly copied into the credentials?
        assert!(&cred
            .credential_subject
            .data
            .keys()
            .all(|key| credential_request.credential_values.contains_key(key)
                && credential_request.credential_values.get(key)
                    == cred.credential_subject.data.get(key)));
    }

    #[test]
    fn can_offer_credential() -> Result<(), Box<dyn Error>> {
        let proposal: CredentialProposal = serde_json::from_str(&EXAMPLE_CREDENTIAL_PROPOSAL)?;
        let offer = Issuer::offer_credential(&proposal, &ISSUER_DID, 1)?;

        assert_eq!(&offer.issuer, &ISSUER_DID);
        assert_eq!(&offer.schema, &proposal.schema);
        assert_eq!(&offer.subject, &proposal.subject);
        assert_eq!(&offer.r#type, &CREDENTIAL_OFFER_TYPE);

        Ok(())
    }

    #[test]
    fn credential_offer_fails_on_wrong_issuer() -> Result<(), Box<dyn Error>> {
        let proposal: CredentialProposal = serde_json::from_str(&EXAMPLE_CREDENTIAL_PROPOSAL)?;
        let offer = Issuer::offer_credential(&proposal, "random_issuer", 1);

        match offer {
            Ok(_) => assert!(false),
            Err(e) => assert_eq!(
                format!("{}", e),
                "Cannot offer credential: Proposal is not targeted at this issuer"
            ),
        };

        Ok(())
    }

    #[test]
    fn can_issue_credential_one_property() -> Result<(), Box<dyn Error>> {
        let message_count = 1;
        let (dpk, sk) = BbsIssuer::new_short_keys(None);
        let proposal: CredentialProposal = serde_json::from_str(&EXAMPLE_CREDENTIAL_PROPOSAL)?;
        let offer = Issuer::offer_credential(&proposal, &ISSUER_DID, message_count)?;
        let key_id = format!("{}#key-1", ISSUER_DID);
        let (credential_request, schema, nquads) = request_credential(&dpk, &offer)?;

        match Issuer::issue_credential(
            &ISSUER_DID,
            &HOLDER_DID,
            &offer,
            &credential_request,
            &key_id,
            &dpk,
            &sk,
            schema.clone(),
            [1].to_vec(),
            nquads,
            EXAMPLE_REVOCATION_LIST_DID,
            0,
        ) {
            Ok(cred) => {
                assert_credential(
                    credential_request.clone(),
                    cred.clone(),
                    &key_id,
                    &schema.id,
                );
            }
            Err(e) => assert!(false, "Received error when issuing credential: {}", e),
        }
        Ok(())
    }

    #[test]
    fn can_issue_credential_five_properties() -> Result<(), Box<dyn Error>> {
        let message_count = 5;

        let nonce_bytes = base64::decode(&PUB_KEY)?.into_boxed_slice();
        let dpk = DeterministicPublicKey::from(nonce_bytes);
        let nonce_bytes = base64::decode(&SECRET_KEY)?.into_boxed_slice();
        let sk = SecretKey::from(nonce_bytes);
        let proposal: CredentialProposal = serde_json::from_str(&EXAMPLE_CREDENTIAL_PROPOSAL)?;
        let offer = Issuer::offer_credential(&proposal, &ISSUER_DID, message_count)?;
        let key_id = format!("{}#key-1", ISSUER_DID);
        let (credential_request, schema, nquads) = request_credential(&dpk, &offer)?;

        match Issuer::issue_credential(
            &ISSUER_DID,
            &HOLDER_DID,
            &offer,
            &credential_request,
            &key_id,
            &dpk,
            &sk,
            schema.clone(),
            [1].to_vec(),
            nquads,
            EXAMPLE_REVOCATION_LIST_DID,
            0,
        ) {
            Ok(cred) => {
                assert_credential(
                    credential_request.clone(),
                    cred.clone(),
                    &key_id,
                    &schema.id,
                );
            }
            Err(e) => assert!(false, "Received error when issuing credential: {}", e),
        }
        Ok(())
    }

    #[test]
    fn cannot_issue_credential_larger_revocation_id() -> Result<(), Box<dyn Error>> {
        let message_count = 5;
        let (dpk, sk) = BbsIssuer::new_short_keys(None);
        let proposal: CredentialProposal = serde_json::from_str(&EXAMPLE_CREDENTIAL_PROPOSAL)?;
        let offer = Issuer::offer_credential(&proposal, &ISSUER_DID, message_count)?;
        let key_id = format!("{}#key-1", ISSUER_DID);
        let (credential_request, schema, nquads) = request_credential(&dpk, &offer)?;

        let result = Issuer::issue_credential(
            &ISSUER_DID,
            &HOLDER_DID,
            &offer,
            &credential_request,
            &key_id,
            &dpk,
            &sk,
            schema.clone(),
            [1].to_vec(),
            nquads,
            EXAMPLE_REVOCATION_LIST_DID,
            MAX_REVOCATION_ENTRIES + 1,
        )
        .map_err(|e| format!("{}", e))
        .err();
        assert_eq!(
            result,
            Some(format!(
                "Cannot issue credential: revocation_list_id {} is larger than list limit of {}",
                MAX_REVOCATION_ENTRIES + 1,
                MAX_REVOCATION_ENTRIES
            ))
        );
        Ok(())
    }

    #[tokio::test]
    async fn revocation_can_create_revocation_registry() -> Result<(), Box<dyn Error>> {
        let signer: Box<dyn Signer> = Box::new(LocalSigner::new());

        Issuer::create_revocation_list(
            EXAMPLE_REVOCATION_LIST_DID,
            ISSUER_DID,
            ISSUER_PUBLIC_KEY_DID,
            ISSUER_PRIVATE_KEY,
            &signer,
        )
        .await?;

        Ok(())
    }

    #[tokio::test]
    async fn revocation_throws_error_when_max_count_reached() -> Result<(), Box<dyn Error>> {
        let signer: Box<dyn Signer> = Box::new(LocalSigner::new());

        let revocation_list: RevocationListCredential =
            serde_json::from_str(&REVOCATION_LIST_CREDENTIAL)?;

        let result = Issuer::revoke_credential(
            ISSUER_DID,
            revocation_list.clone(),
            MAX_REVOCATION_ENTRIES + 1,
            ISSUER_PUBLIC_KEY_DID,
            ISSUER_PRIVATE_KEY,
            &signer,
        )
        .await
        .map_err(|e| format!("{}", e))
        .err();

        assert_eq!(
            result,
            Some(format!(
                "Cannot revoke credential: revocation_id {} is larger than list limit of {}",
                MAX_REVOCATION_ENTRIES + 1,
                MAX_REVOCATION_ENTRIES
            ))
        );
        Ok(())
    }

    #[tokio::test]
    async fn revocation_can_set_revoked_status() -> Result<(), Box<dyn Error>> {
        let signer: Box<dyn Signer> = Box::new(LocalSigner::new());

        let revocation_list: RevocationListCredential =
            serde_json::from_str(&REVOCATION_LIST_CREDENTIAL)?;

        let updated_revocation_list = Issuer::revoke_credential(
            ISSUER_DID,
            revocation_list.clone(),
            1,
            ISSUER_PUBLIC_KEY_DID,
            ISSUER_PRIVATE_KEY,
            &signer,
        )
        .await?;

        assert_ne!(
            &revocation_list.credential_subject.encoded_list,
            &updated_revocation_list.credential_subject.encoded_list
        );

        Ok(())
    }
}
