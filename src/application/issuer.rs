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

use super::{datatypes::SchemaProperty, utils::convert_to_nquads};
use crate::{
    application::{
        datatypes::{
            BbsCredentialOffer,
            BbsCredentialRequest,
            CredentialSchema,
            CredentialSchemaReference,
            CredentialStatus,
            CredentialSubject,
            RevocationListCredential,
            RevocationListCredentialSubject,
            UnfinishedBbsCredential,
            UnfinishedBbsCredentialSignature,
            UnproofedRevocationListCredential,
            UnsignedBbsCredential,
            CREDENTIAL_PROOF_PURPOSE,
            CREDENTIAL_SCHEMA_TYPE,
            CREDENTIAL_SIGNATURE_TYPE,
            DEFAULT_CREDENTIAL_CONTEXTS,
            DEFAULT_REVOCATION_CONTEXTS,
        },
        utils::{
            check_for_requird_reveal_index0,
            decode_base64,
            decode_base64_config,
            generate_uuid,
            get_now_as_iso_string,
        },
    },
    crypto::{crypto_issuer::CryptoIssuer, crypto_utils::create_assertion_proof},
    DraftBbsCredential,
    LdProofVcDetail,
    LdProofVcDetailOptions,
    LdProofVcDetailOptionsCredentialStatus,
    LdProofVcDetailOptionsCredentialStatusType,
    LdProofVcDetailOptionsType,
};
use bbs::{
    issuer::Issuer as BbsIssuer,
    keys::{DeterministicPublicKey, SecretKey},
    BlindSignatureContext,
    ProofNonce,
};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use std::{collections::HashMap, convert::TryInto, error::Error, io::prelude::*};
use vade_signer::Signer;

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

    /// Creates a new credential offer.
    ///
    /// # Arguments
    /// * `credential` - draft credential to be offered
    /// * `required_reveal_statements` - required indices to be revealed
    /// * `credential_status_type` - type of credential status
    ///
    /// # Returns
    /// * `BbsCredentialOffer` - The message to be sent to the prover.
    pub fn offer_credential(
        credential: &DraftBbsCredential,
        required_reveal_statements: &Vec<u32>,
        credential_status_type: &LdProofVcDetailOptionsCredentialStatusType,
    ) -> Result<BbsCredentialOffer, Box<dyn Error>> {
        let nonce = base64::encode(BbsIssuer::generate_signing_nonce().to_bytes_compressed_form());

        check_for_requird_reveal_index0(required_reveal_statements)?;

        Ok(BbsCredentialOffer {
            ld_proof_vc_detail: LdProofVcDetail {
                credential: credential.clone(),
                options: LdProofVcDetailOptions {
                    created: get_now_as_iso_string(),
                    proof_type: LdProofVcDetailOptionsType::Ed25519Signature2018,
                    credential_status: LdProofVcDetailOptionsCredentialStatus {
                        r#type: credential_status_type.to_owned(),
                    },
                    required_reveal_statements: required_reveal_statements.to_owned(),
                },
            },
            nonce,
        })
    }

    pub async fn sign_nquads(
        credential_request: &BbsCredentialRequest,
        credential_status: Option<CredentialStatus>,
        issuer_public_key_id: &str,
        issuer_public_key: &DeterministicPublicKey,
        issuer_secret_key: &SecretKey,
    ) -> Result<UnfinishedBbsCredential, Box<dyn Error>> {
        let unsigned_credential: UnsignedBbsCredential = credential_request
            .credential_offer
            .ld_proof_vc_detail
            .credential
            .to_unsigned_credential(credential_status);
        let nquads = convert_to_nquads(&serde_json::to_string(&unsigned_credential)?).await?;

        let blind_signature_context: BlindSignatureContext = decode_base64(
            &credential_request.blind_signature_context,
            "Blind Signature Context",
        )?
        .into_boxed_slice()
        .try_into()?;

        let nonce = ProofNonce::from(
            decode_base64(
                &credential_request.credential_offer.nonce,
                "Credential Offer Nonce",
            )?
            .into_boxed_slice(),
        );
        let blind_signature = CryptoIssuer::create_signature(
            &blind_signature_context,
            &nonce,
            nquads.clone(),
            issuer_public_key,
            issuer_secret_key,
        )
        .map_err(|e| format!("Error creating bbs+ signature: {}", e))?;

        let vc_signature = UnfinishedBbsCredentialSignature {
            r#type: CREDENTIAL_SIGNATURE_TYPE.to_string(),
            created: get_now_as_iso_string(),
            proof_purpose: CREDENTIAL_PROOF_PURPOSE.to_owned(),
            verification_method: issuer_public_key_id.to_owned(),
            required_reveal_statements: credential_request
                .credential_offer
                .ld_proof_vc_detail
                .options
                .required_reveal_statements
                .to_owned(),
            credential_message_count: nquads.len() + ADDITIONAL_HIDDEN_MESSAGES_COUNT,
            blind_signature: base64::encode(blind_signature.to_bytes_compressed_form()),
        };

        let unfinished_credential = UnfinishedBbsCredential::new(unsigned_credential, vc_signature);

        Ok(unfinished_credential)
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
    /// * `revocation_list_id` - ID of the revocation list to assign to this credential
    ///
    /// # Returns
    /// * `UnfinishedBbsCredential` - Credential including signature that needs to be post-processed by the subject
    //
    // ######### Please keep this commented until we have an Rust nquad library #########
    #[allow(dead_code)]
    pub fn issue_credential(
        issuer_did: &str,
        credential_offer: &BbsCredentialOffer,
        credential_request: &BbsCredentialRequest,
        issuer_public_key_id: &str,
        issuer_public_key: &DeterministicPublicKey,
        issuer_secret_key: &SecretKey,
        credential_schema: CredentialSchema,
        required_indices: Vec<u32>,
        nquads: Vec<String>,
        revocation_list_did: Option<&str>,
        revocation_list_id: Option<&str>,
        valid_until: Option<String>,
    ) -> Result<UnfinishedBbsCredential, Box<dyn Error>> {
        check_for_requird_reveal_index0(
            &credential_offer
                .ld_proof_vc_detail
                .options
                .required_reveal_statements,
        )?;

        let mut credential_status: Option<CredentialStatus> = None;
        if revocation_list_id.is_some() || revocation_list_did.is_some() {
            let revocation_list_id =
                revocation_list_id.ok_or_else(|| "Error parsing revocation_list_id")?;
            let revocation_list_did =
                revocation_list_did.ok_or_else(|| "Error parsing revocation_list_did")?;
            let revocation_list_index_number = revocation_list_id
                .parse::<usize>()
                .map_err(|e| format!("Error parsing revocation_list_id: {}", e))?;

            if revocation_list_index_number > MAX_REVOCATION_ENTRIES {
                let error = format!(
                "Cannot issue credential: revocation_list_id {} is larger than list limit of {}",
                revocation_list_index_number, MAX_REVOCATION_ENTRIES
            );
                return Err(Box::from(error));
            }
            credential_status = Some(CredentialStatus {
                id: format!("{}#{}", revocation_list_did, revocation_list_id),
                r#type: "RevocationList2020Status".to_string(),
                revocation_list_index: revocation_list_id.to_string(),
                revocation_list_credential: revocation_list_did.to_string(),
            });
        }

        let credential_subject = CredentialSubject {
            data: credential_request
                .credential_offer
                .ld_proof_vc_detail
                .credential
                .credential_subject
                .data
                .clone(),
        };

        let schema_reference = CredentialSchemaReference {
            id: credential_schema.id,
            r#type: CREDENTIAL_SCHEMA_TYPE.to_string(),
        };

        let blind_signature_context: BlindSignatureContext = decode_base64(
            &credential_request.blind_signature_context,
            "Blind Signature Context",
        )?
        .into_boxed_slice()
        .try_into()?;

        let nonce = ProofNonce::from(
            decode_base64(&credential_offer.nonce, "Credential Offer Nonce")?.into_boxed_slice(),
        );
        let blind_signature = CryptoIssuer::create_signature(
            &blind_signature_context,
            &nonce,
            nquads.clone(),
            issuer_public_key,
            issuer_secret_key,
        )
        .map_err(|e| format!("Error creating bbs+ signature: {}", e))?;

        let vc_signature = UnfinishedBbsCredentialSignature {
            r#type: CREDENTIAL_SIGNATURE_TYPE.to_string(),
            created: get_now_as_iso_string(),
            proof_purpose: CREDENTIAL_PROOF_PURPOSE.to_owned(),
            verification_method: issuer_public_key_id.to_owned(),
            required_reveal_statements: required_indices,
            credential_message_count: nquads.len() + ADDITIONAL_HIDDEN_MESSAGES_COUNT,
            blind_signature: base64::encode(blind_signature.to_bytes_compressed_form()),
        };

        let credential_id = format!("uuid:{}", generate_uuid());
        let credential = UnfinishedBbsCredential {
            context: DEFAULT_CREDENTIAL_CONTEXTS
                .iter()
                .map(|c| String::from(c.to_owned()))
                .collect::<Vec<_>>(),
            id: credential_id,
            r#type: vec!["VerifiableCredential".to_string()],
            issuer: issuer_did.to_owned(),
            credential_subject,
            valid_until,
            issuance_date: get_now_as_iso_string(),
            credential_schema: schema_reference,
            credential_status,
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
                "RevocationList2020Credential".to_string(),
            ],
            issuer: issuer_public_key_did.to_owned(),
            issued: get_now_as_iso_string(),
            credential_subject: RevocationListCredentialSubject {
                id: format!("{}#{}", assigned_did, "list"),
                r#type: "RevocationList2020".to_string(),
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
        revocation_id: &str,
        issuer_public_key_did: &str,
        issuer_proving_key: &str,
        signer: &Box<dyn Signer>,
    ) -> Result<RevocationListCredential, Box<dyn Error>> {
        let revocation_id = revocation_id
            .parse::<usize>()
            .map_err(|e| format!("Error parsing revocation_id: {}", e))?;

        if revocation_id > MAX_REVOCATION_ENTRIES {
            let error = format!(
                "Cannot revoke credential: revocation_id {} is larger than list limit of {}",
                revocation_id, MAX_REVOCATION_ENTRIES
            );
            return Err(Box::from(error));
        }

        let encoded_list = decode_base64_config(
            &revocation_list.credential_subject.encoded_list,
            base64::URL_SAFE,
            "Encoded revocation list",
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

    /// Creates a new key pair
    ///
    /// # Returns
    /// * `(DeterministicPublicKey, SecretKey)` - Tuple of the public key and secret key
    pub fn create_new_keys() -> (DeterministicPublicKey, SecretKey) {
        return BbsIssuer::new_short_keys(None);
    }
}

#[cfg(test)]
mod tests {
    extern crate utilities;
    use super::*;
    use crate::{
        application::{
            datatypes::{BbsCredentialOffer, BbsCredentialRequest},
            prover::Prover,
            utils::convert_to_nquads,
        },
        CredentialDraftOptions,
    };
    use bbs::{issuer::Issuer as BbsIssuer, prover::Prover as BbsProver};
    use std::collections::HashMap;
    use utilities::test_data::{
        accounts::local::{ISSUER_DID, ISSUER_PRIVATE_KEY, ISSUER_PUBLIC_KEY_DID},
        bbs_coherent_context_test_data::{
            EXAMPLE_REVOCATION_LIST_DID,
            PUB_KEY,
            REVOCATION_LIST_CREDENTIAL,
            SCHEMA,
            SECRET_KEY,
        },
    };
    use vade_signer::{LocalSigner, Signer};

    async fn request_credential(
        pub_key: &DeterministicPublicKey,
        offer: &mut BbsCredentialOffer,
        credential_value_count: usize,
    ) -> Result<(BbsCredentialRequest, CredentialSchema), Box<dyn Error>> {
        let schema: CredentialSchema = serde_json::from_str(SCHEMA)?;
        let secret = BbsProver::new_link_secret();
        let mut credential_values = HashMap::new();
        credential_values.insert("test_property_string".to_owned(), "value".to_owned());
        for i in 1..(credential_value_count) {
            // Create messages until we have message_count - 1 messages (one is reserved for master secret)
            credential_values.insert(format!("test_property_string{}", i), "value".to_owned());
        }
        offer.ld_proof_vc_detail.credential.credential_subject.data = credential_values;

        let (credential_request, _) = Prover::request_credential(&offer, &schema, &secret, pub_key)
            .map_err(|e| format!("{}", e))?;

        return Ok((credential_request, schema));
    }

    fn is_base_64(input: &str) -> bool {
        match decode_base64(input, "Test input") {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    fn assert_credential_proof(
        cred: UnfinishedBbsCredential,
        pub_key_id: &str,
        required_reveal_statements: Vec<u32>,
    ) {
        assert_eq!(
            &cred.proof.required_reveal_statements,
            &required_reveal_statements
        );
        assert_eq!(&cred.proof.r#type, CREDENTIAL_SIGNATURE_TYPE);
        assert_eq!(&cred.proof.proof_purpose, CREDENTIAL_PROOF_PURPOSE);
        assert_eq!(&cred.proof.verification_method, pub_key_id);
        assert!(
            is_base_64(&cred.proof.blind_signature),
            "Signature seems not to be base64 encoded"
        );
    }

    fn assert_credential(
        credential_request: BbsCredentialRequest,
        cred: UnfinishedBbsCredential,
        pub_key_id: &str,
        schema_id: &str,
        valid_until: Option<String>,
    ) {
        assert_eq!(&cred.issuer, ISSUER_DID);
        assert_eq!(&cred.credential_schema.id, schema_id);
        // proof
        assert_eq!(&cred.proof.required_reveal_statements, &[1].to_vec());
        assert_eq!(&cred.proof.r#type, CREDENTIAL_SIGNATURE_TYPE);
        assert_eq!(&cred.proof.proof_purpose, CREDENTIAL_PROOF_PURPOSE);
        assert_eq!(&cred.proof.verification_method, pub_key_id);
        assert!(
            is_base_64(&cred.proof.blind_signature),
            "Signature seems not to be base64 encoded"
        );
        // Credential subject
        // Are the values correctly copied into the credentials?
        assert!(&cred
            .credential_subject
            .data
            .keys()
            .all(|key| credential_request
                .credential_offer
                .ld_proof_vc_detail
                .credential
                .credential_subject
                .data
                .contains_key(key)
                && credential_request
                    .credential_offer
                    .ld_proof_vc_detail
                    .credential
                    .credential_subject
                    .data
                    .get(key)
                    == cred.credential_subject.data.get(key)));
        if valid_until.is_some() {
            assert_eq!(cred.valid_until, valid_until);
        }
    }

    #[test]
    fn can_offer_credential() -> Result<(), Box<dyn Error>> {
        let schema: CredentialSchema = serde_json::from_str(&SCHEMA)?;
        let mut draft: DraftBbsCredential = schema.to_draft_credential(CredentialDraftOptions {
            issuer_did: ISSUER_DID.to_string(),
            id: None,
            issuance_date: None,
            valid_until: None,
        });

        draft.issuer = ISSUER_DID.to_string();
        draft.credential_subject.data.clear(); // don't pre-fill schema values with empty strings in test
                                               // values must be inserted into draft to get a predictable outcome
        draft
            .credential_subject
            .data
            .insert("test_property_string".to_string(), "foo".to_string());
        draft
            .credential_subject
            .data
            .insert("test_property_string2".to_string(), "bar".to_string());

        let offer = Issuer::offer_credential(
            &draft,
            &vec![1],
            &LdProofVcDetailOptionsCredentialStatusType::RevocationList2021Status,
        )?;

        assert_eq!(&offer.ld_proof_vc_detail.credential.issuer, &ISSUER_DID);
        Ok(())
    }

    #[tokio::test]
    async fn can_issue_credential_one_property() -> Result<(), Box<dyn Error>> {
        let (dpk, sk) = BbsIssuer::new_short_keys(None);
        let schema: CredentialSchema = serde_json::from_str(SCHEMA)?;
        let draft = schema.to_draft_credential(CredentialDraftOptions {
            issuer_did: ISSUER_DID.to_string(),
            id: None,
            issuance_date: None,
            valid_until: Some(get_now_as_iso_string()),
        });
        let mut offer = Issuer::offer_credential(
            &draft,
            &vec![1],
            &LdProofVcDetailOptionsCredentialStatusType::RevocationList2021Status,
        )?;
        let key_id = format!("{}#key-1", ISSUER_DID);
        let (credential_request, _) = request_credential(&dpk, &mut offer, 1).await?;

        let status = CredentialStatus {
            id: format!("{}#0", EXAMPLE_REVOCATION_LIST_DID),
            r#type: "RevocationList2020Status".to_string(),
            revocation_list_index: "0".to_string(),
            revocation_list_credential: EXAMPLE_REVOCATION_LIST_DID.to_string(),
        };

        let result =
            Issuer::sign_nquads(&credential_request, Some(status), &key_id, &dpk, &sk).await;
        match result {
            Ok(cred) => {
                assert_credential(
                    credential_request.clone(),
                    cred.clone(),
                    &key_id,
                    &schema.id,
                    draft.valid_until.clone(),
                );
            }
            Err(e) => assert!(false, "Received error when issuing credential: {}", e),
        };

        Ok(())
    }

    #[tokio::test]
    async fn can_issue_credential_five_properties() -> Result<(), Box<dyn Error>> {
        let nonce_bytes = decode_base64(&PUB_KEY, "Public Key")?.into_boxed_slice();
        let dpk = DeterministicPublicKey::from(nonce_bytes);
        let nonce_bytes = decode_base64(&SECRET_KEY, "Secret Key")?.into_boxed_slice();
        let sk = SecretKey::from(nonce_bytes);
        let schema: CredentialSchema = serde_json::from_str(SCHEMA)?;
        let draft = schema.to_draft_credential(CredentialDraftOptions {
            issuer_did: ISSUER_DID.to_string(),
            id: None,
            issuance_date: None,
            valid_until: None,
        });
        let mut offer = Issuer::offer_credential(
            &draft,
            &vec![1],
            &LdProofVcDetailOptionsCredentialStatusType::RevocationList2021Status,
        )?;
        let key_id = format!("{}#key-1", ISSUER_DID);
        let (credential_request, _) = request_credential(&dpk, &mut offer, 5).await?;

        let status = CredentialStatus {
            id: format!("{}#0", EXAMPLE_REVOCATION_LIST_DID),
            r#type: "RevocationList2020Status".to_string(),
            revocation_list_index: "0".to_string(),
            revocation_list_credential: EXAMPLE_REVOCATION_LIST_DID.to_string(),
        };

        let result =
            Issuer::sign_nquads(&credential_request, Some(status), &key_id, &dpk, &sk).await;

        match result {
            Ok(cred) => {
                assert_credential(
                    credential_request.clone(),
                    cred.clone(),
                    &key_id,
                    &schema.id,
                    None,
                );
            }
            Err(e) => assert!(false, "Received error when issuing credential: {}", e),
        };

        Ok(())
    }

    #[tokio::test]
    async fn can_sign_nquads_five_properties() -> Result<(), Box<dyn Error>> {
        let nonce_bytes = decode_base64(&PUB_KEY, "Public Key")?.into_boxed_slice();
        let dpk = DeterministicPublicKey::from(nonce_bytes);
        let nonce_bytes = decode_base64(&SECRET_KEY, "Secret Key")?.into_boxed_slice();
        let sk = SecretKey::from(nonce_bytes);
        let schema: CredentialSchema = serde_json::from_str(SCHEMA)?;
        let draft = schema.to_draft_credential(CredentialDraftOptions {
            issuer_did: ISSUER_DID.to_string(),
            id: None,
            issuance_date: None,
            valid_until: None,
        });
        let mut offer = Issuer::offer_credential(
            &draft,
            &vec![1],
            &LdProofVcDetailOptionsCredentialStatusType::RevocationList2021Status,
        )?;
        let key_id = format!("{}#key-1", ISSUER_DID);
        let (credential_request, _) = request_credential(&dpk, &mut offer, 5).await?;

        let status = CredentialStatus {
            id: format!("{}#0", EXAMPLE_REVOCATION_LIST_DID),
            r#type: "RevocationList2020Status".to_string(),
            revocation_list_index: "0".to_string(),
            revocation_list_credential: EXAMPLE_REVOCATION_LIST_DID.to_string(),
        };

        match Issuer::sign_nquads(&credential_request, Some(status), &key_id, &dpk, &sk).await {
            Ok(cred) => assert_credential_proof(cred, &key_id, [1].to_vec()),
            Err(e) => assert!(false, "Received error when issuing credential: {}", e),
        }

        Ok(())
    }

    #[tokio::test]
    async fn cannot_issue_credential_larger_revocation_id() -> Result<(), Box<dyn Error>> {
        let (dpk, sk) = BbsIssuer::new_short_keys(None);
        let schema: CredentialSchema = serde_json::from_str(SCHEMA)?;
        let draft = schema.to_draft_credential(CredentialDraftOptions {
            issuer_did: ISSUER_DID.to_string(),
            id: None,
            issuance_date: None,
            valid_until: None,
        });
        let mut offer = Issuer::offer_credential(
            &draft,
            &vec![1],
            &LdProofVcDetailOptionsCredentialStatusType::RevocationList2021Status,
        )?;
        let key_id = format!("{}#key-1", ISSUER_DID);
        let (credential_request, _) = request_credential(&dpk, &mut offer, 5).await?;

        let over_max = &(MAX_REVOCATION_ENTRIES + 1).to_string();
        let status = CredentialStatus {
            id: format!("{}#{}", EXAMPLE_REVOCATION_LIST_DID, &over_max),
            r#type: "RevocationList2020Status".to_string(),
            revocation_list_index: over_max.to_owned(),
            revocation_list_credential: EXAMPLE_REVOCATION_LIST_DID.to_string(),
        };
        let unsigned = &offer
            .ld_proof_vc_detail
            .credential
            .to_unsigned_credential(Some(status));
        let nquads = convert_to_nquads(&serde_json::to_string(&unsigned)?).await?;

        let result = Issuer::issue_credential(
            &ISSUER_DID,
            &offer,
            &credential_request,
            &key_id,
            &dpk,
            &sk,
            schema.clone(),
            [1].to_vec(),
            nquads,
            Some(EXAMPLE_REVOCATION_LIST_DID),
            Some(&(MAX_REVOCATION_ENTRIES + 1).to_string()),
            None,
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
            &(MAX_REVOCATION_ENTRIES + 1).to_string(),
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
            "1",
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
