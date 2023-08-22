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

use bbs::{ProofNonce, SignatureProof, ToVariableLengthBytes};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, convert::TryFrom, error::Error, fmt::Display};
use uuid::Uuid;

use super::{issuer::ADDITIONAL_HIDDEN_MESSAGES_COUNT, utils::get_now_as_iso_string};

pub const CORE_MESSAGE_COUNT: usize = 7; // w/o status and values
pub const CREDENTIAL_SIGNATURE_TYPE: &str = "BbsBlsSignature2020";
pub const PROOF_SIGNATURE_TYPE: &str = "BbsBlsSignatureProof2020";
pub const CREDENTIAL_SCHEMA_TYPE: &str = "EvanZKPSchema";
pub const CREDENTIAL_PROOF_PURPOSE: &str = "assertionMethod";
pub const DEFAULT_CREDENTIAL_CONTEXTS: [&'static str; 3] = [
    "https://www.w3.org/2018/credentials/v1",
    "https://schema.org/",
    "https://w3id.org/vc-revocation-list-2020/v1",
];
pub const DEFAULT_REVOCATION_CONTEXTS: [&'static str; 2] = [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/vc-revocation-list-2020/v1",
];

pub const BBS_PROOF_TYPE: &str = "BBS";

/// Message following a `BbsCredentialOffer`, sent by a potential credential prover.
/// Provides the values that need to be signed by the issuer in both encoded/cleartext, and blinded format.
/// Incorporates the nonce value sent in `BbsCredentialOffer`.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BbsCredentialRequest {
    pub credential_offer: BbsCredentialOffer,
    pub blind_signature_context: String,
}

/// Message sent by a prover stating which attributes of which schema he is intending to reveal.
///
/// All fields (except `createdAt`) will be included in a `BbsProofRequest` created from this proposal.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BbsProofProposal {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier: Option<String>,
    pub created_at: String,
    pub nonce: String,
    pub r#type: String,
    pub sub_proof_requests: Vec<BbsSubProofRequest>,
}

impl From<BbsProofRequest> for BbsProofProposal {
    fn from(request: BbsProofRequest) -> Self {
        Self {
            verifier: request.verifier,
            created_at: request.created_at,
            nonce: request.nonce,
            r#type: request.r#type,
            sub_proof_requests: request.sub_proof_requests,
        }
    }
}

/// Message sent by a verifier stating which attributes of which schema the prover is supposed to reveal.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BbsProofRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier: Option<String>,
    pub created_at: String,
    pub nonce: String,
    pub r#type: String,
    pub sub_proof_requests: Vec<BbsSubProofRequest>,
}

impl From<BbsProofProposal> for BbsProofRequest {
    fn from(proposal: BbsProofProposal) -> Self {
        Self {
            verifier: proposal.verifier,
            created_at: proposal.created_at,
            nonce: proposal.nonce,
            r#type: proposal.r#type,
            sub_proof_requests: proposal.sub_proof_requests,
        }
    }
}

/// Part of a proof request that requests attributes of a specific schema
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BbsSubProofRequest {
    pub schema: String,
    pub revealed_attributes: Vec<usize>,
}

/// Specifies the properties of a credential, as well as metadata.
/// Needs to be stored publicly available and temper-proof.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchema {
    pub id: String,
    pub r#type: String,
    pub name: String,
    pub author: String,
    pub created_at: String,
    pub description: String,
    pub properties: HashMap<String, SchemaProperty>,
    pub required: Vec<String>,
    pub additional_properties: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<AssertionProof>,
}

pub struct CredentialDraftOptions {
    pub issuer_did: String,
    pub id: Option<PrefixedUuid>,
    pub issuance_date: Option<String>,
    pub valid_until: Option<String>,
}

impl CredentialSchema {
    pub fn from_str(schema_document: &str) -> Result<CredentialSchema, Box<dyn Error>> {
        Ok(serde_json::from_str::<CredentialSchema>(schema_document)?)
    }

    pub fn to_draft_credential(&self, options: CredentialDraftOptions) -> DraftBbsCredential {
        DraftBbsCredential {
            context: vec![
                "https://www.w3.org/2018/credentials/v1".to_string(),
                "https://schema.org/".to_string(),
                "https://w3id.org/vc-revocation-list-2020/v1".to_string(),
            ],
            id: options.id.unwrap_or_else(|| PrefixedUuid::new(Uuid::new_v4().to_string())),
            r#type: vec!["VerifiableCredential".to_string()],
            issuer: options.issuer_did,
            valid_until: options.valid_until,
            issuance_date: options
                .issuance_date
                .unwrap_or_else(|| get_now_as_iso_string()),
            credential_subject: CredentialSubject {
                id: None,
                data: self // fill ALL subject data fields with empty string (mandatory and optional ones)
                    .properties
                    .clone()
                    .into_iter()
                    .map(|(name, _schema_property)| (name, String::new()))
                    .collect(),
            },
            credential_schema: CredentialSchemaReference {
                id: self.id.to_owned(),
                r#type: self.r#type.to_owned(),
            },
        }
    }
}

/// Metadata about a property of a credential schema
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SchemaProperty {
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<String>>,
}

/// AssertionProof, typically used to ensure authenticity and integrity of a verifiable credential
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AssertionProof {
    pub r#type: String,
    pub created: String,
    pub proof_purpose: String,
    pub verification_method: String,
    pub jws: String,
}

/// Message sent by an issuer.
/// Defines how the credential to be issued will look like.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BbsCredentialOffer {
    pub ld_proof_vc_detail: LdProofVcDetail,
    pub nonce: String,
}

/// Message to initiate credential issuance, sent by (potential) prover.
/// Specifies the schema to be used for the credential.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CredentialProposal {
    pub issuer: String,
    pub schema: String,
}

/// A verifiable credential issued by an issuer upon receiving a `CredentialRequest`.
/// Specifies the signed values, the `CredentialSchema`, and the `CredentialSignature`
/// including revocation info.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BbsCredential {
    #[serde(rename(serialize = "@context", deserialize = "@context"))]
    pub context: Vec<String>,
    pub id: PrefixedUuid,
    pub r#type: Vec<String>,
    pub issuer: String,
    pub issuance_date: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    pub credential_subject: CredentialSubject,
    pub credential_schema: CredentialSchemaReference,
    pub credential_status: Option<CredentialStatus>,
    pub proof: BbsCredentialSignature,
}

impl BbsCredential {
    pub fn new(cred: UnfinishedBbsCredential, signature: String) -> BbsCredential {
        BbsCredential {
            context: cred.context,
            id: cred.id,
            r#type: cred.r#type,
            issuer: cred.issuer,
            issuance_date: cred.issuance_date,
            valid_until: cred.valid_until,
            credential_subject: CredentialSubject {
                id: None,
                data: cred.credential_subject.data,
            },
            credential_schema: CredentialSchemaReference {
                id: cred.credential_schema.id,
                r#type: cred.credential_schema.r#type,
            },
            credential_status: cred.credential_status,
            proof: BbsCredentialSignature {
                created: cred.proof.created,
                proof_purpose: cred.proof.proof_purpose,
                required_reveal_statements: cred.proof.required_reveal_statements,
                signature: signature,
                credential_message_count: cred.proof.credential_message_count,
                r#type: cred.proof.r#type,
                verification_method: cred.proof.verification_method,
            },
        }
    }
}

/// A verifiable credential with a blind signature that still needs to be processed by the holder
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UnsignedBbsCredential {
    #[serde(rename(serialize = "@context", deserialize = "@context"))]
    pub context: Vec<String>,
    pub id: PrefixedUuid,
    pub r#type: Vec<String>,
    pub issuer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    pub issuance_date: String,
    pub credential_subject: CredentialSubject,
    pub credential_schema: CredentialSchemaReference,
    pub credential_status: Option<CredentialStatus>,
}

impl UnsignedBbsCredential {
    pub fn from_proof_presentation(value: &BbsPresentation) -> Result<Self, Box<dyn Error>> {
        Ok(serde_json::from_str(&serde_json::to_string(&value)?)?)
    }

    pub fn from_bbs_credential(value: &BbsCredential) -> Result<Self, Box<dyn Error>> {
        Ok(serde_json::from_str(&serde_json::to_string(&value)?)?)
    }
}

/// A verifiable credential containing a blind signature that still needs to be processed by the holder/receiver.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UnfinishedBbsCredential {
    #[serde(rename(serialize = "@context", deserialize = "@context"))]
    pub context: Vec<String>,
    pub id: PrefixedUuid,
    pub r#type: Vec<String>,
    pub issuer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    pub issuance_date: String,
    pub credential_subject: CredentialSubject,
    pub credential_schema: CredentialSchemaReference,
    pub credential_status: Option<CredentialStatus>,
    pub proof: UnfinishedBbsCredentialSignature,
}

impl UnfinishedBbsCredential {
    pub fn new(
        unsigned_vc: UnsignedBbsCredential,
        signature: UnfinishedBbsCredentialSignature,
    ) -> UnfinishedBbsCredential {
        UnfinishedBbsCredential {
            context: unsigned_vc.context,
            id: unsigned_vc.id,
            r#type: unsigned_vc.r#type,
            issuer: unsigned_vc.issuer,
            valid_until: unsigned_vc.valid_until,
            issuance_date: unsigned_vc.issuance_date,
            credential_schema: unsigned_vc.credential_schema,
            credential_subject: unsigned_vc.credential_subject,
            credential_status: unsigned_vc.credential_status,
            proof: signature,
        }
    }
}

/// Payload/data part of a verifiable credential.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub data: HashMap<String, String>,
}

/// 'credentialStatus' property of a verifiable credential containing revocation information.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatus {
    pub id: String,
    pub r#type: String,
    pub revocation_list_index: String,
    pub revocation_list_credential: String,
}

/// Payload part of a revocation list credential.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RevocationListCredentialSubject {
    pub id: String,
    pub r#type: String,
    pub encoded_list: String,
}

/// Reference to a credential schema.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemaReference {
    pub id: String,
    pub r#type: String,
}

/// The signature ('proof' part) of a BBS+ verifiable credential.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BbsCredentialSignature {
    pub r#type: String,
    pub created: String,
    pub proof_purpose: String,
    pub verification_method: String,
    pub credential_message_count: usize,
    #[serde(default = "empty_array")]
    pub required_reveal_statements: Vec<u32>,
    pub signature: String,
}

/// A blinded signature created by an issuer that needs to be finished
/// by the holder/receiver of this signature.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UnfinishedBbsCredentialSignature {
    pub r#type: String,
    pub created: String,
    pub proof_purpose: String,
    pub verification_method: String,
    pub credential_message_count: usize,
    #[serde(default = "empty_array")]
    pub required_reveal_statements: Vec<u32>,
    pub blind_signature: String,
}

/// A collection of all proofs requested in a `ProofRequest`. Sent to a verifier as the response to
/// a `ProofRequest`.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProofPresentation {
    #[serde(rename(serialize = "@context", deserialize = "@context"))]
    pub context: Vec<String>,
    pub id: String,
    pub r#type: Vec<String>,
    pub verifiable_credential: Vec<BbsPresentation>,
    pub proof: Option<AssertionProof>,
}

impl ProofPresentation {
    pub fn new(
        unsigned_proof_presentation: UnfinishedProofPresentation,
        proof: Option<AssertionProof>,
    ) -> ProofPresentation {
        return ProofPresentation {
            context: unsigned_proof_presentation.context,
            id: unsigned_proof_presentation.id,
            r#type: unsigned_proof_presentation.r#type,
            verifiable_credential: unsigned_proof_presentation.verifiable_credential,
            proof: proof,
        };
    }
}

/// Proof presentation without a proof (just for internal use)
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnfinishedProofPresentation {
    #[serde(rename(serialize = "@context", deserialize = "@context"))]
    pub context: Vec<String>,
    pub id: String,
    pub r#type: Vec<String>,
    pub verifiable_credential: Vec<BbsPresentation>,
}

/// A verifiable credential exposing requested properties of a `BbsCredential` by providing a Bbs signature proof
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BbsPresentation {
    #[serde(rename(serialize = "@context", deserialize = "@context"))]
    pub context: Vec<String>,
    pub id: PrefixedUuid,
    pub r#type: Vec<String>,
    pub issuer: String,
    pub issuance_date: String,
    pub credential_subject: CredentialSubject,
    pub credential_schema: CredentialSchemaReference,
    pub credential_status: Option<CredentialStatus>,
    pub proof: BbsPresentationProof,
}

impl BbsPresentation {
    pub fn new(
        cred: BbsCredential,
        proof: SignatureProof,
        revealed_properties: CredentialSubject,
        nonce: ProofNonce,
    ) -> BbsPresentation {
        BbsPresentation {
            context: cred.context,
            id: cred.id,
            issuance_date: cred.issuance_date,
            r#type: cred.r#type,
            issuer: cred.issuer,
            credential_subject: revealed_properties,
            credential_schema: CredentialSchemaReference {
                id: cred.credential_schema.id,
                r#type: cred.credential_schema.r#type,
            },
            credential_status: cred.credential_status,
            proof: BbsPresentationProof {
                created: cred.proof.created,
                proof_purpose: cred.proof.proof_purpose,
                required_reveal_statements: cred.proof.required_reveal_statements,
                proof: base64::encode(proof.to_bytes_compressed_form()),
                credential_message_count: cred.proof.credential_message_count,
                r#type: PROOF_SIGNATURE_TYPE.to_owned(),
                verification_method: cred.proof.verification_method,
                nonce: base64::encode(nonce.to_bytes_compressed_form()),
            },
        }
    }
}

/// A proof object of a `BbsPresentation`
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BbsPresentationProof {
    pub r#type: String,
    pub created: String,
    pub proof_purpose: String,
    pub credential_message_count: usize,
    pub verification_method: String,
    #[serde(default = "empty_array")]
    pub required_reveal_statements: Vec<u32>,
    pub nonce: String,
    pub proof: String,
}

/// Result of a call to the verifyProof endpoint. Gives the status of a verification (i.e. whether it
/// was successful or not) and a reason, if rejected.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BbsProofVerification {
    pub presented_proof: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `RevocationListCredential` without a proof (for internal use only).
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UnproofedRevocationListCredential {
    #[serde(rename(serialize = "@context", deserialize = "@context"))]
    pub context: Vec<String>,
    pub id: String,
    pub r#type: Vec<String>,
    pub issuer: String,
    pub issued: String,
    pub credential_subject: RevocationListCredentialSubject,
}

/// A revocation list credential associating verifiable credential revocation IDs to their revocation status as a bit list. See
/// <https://w3c-ccg.github.io/vc-status-rl-2020/#revocationlist2020credential>
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RevocationListCredential {
    #[serde(rename(serialize = "@context", deserialize = "@context"))]
    pub context: Vec<String>,
    pub id: String,
    pub r#type: Vec<String>,
    pub issuer: String,
    pub issued: String,
    pub credential_subject: RevocationListCredentialSubject,
    pub proof: AssertionProof,
}

impl RevocationListCredential {
    pub fn new(
        list: UnproofedRevocationListCredential,
        proof: AssertionProof,
    ) -> RevocationListCredential {
        RevocationListCredential {
            context: list.context,
            id: list.id,
            r#type: list.r#type,
            issuer: list.issuer,
            issued: list.issued,
            credential_subject: list.credential_subject,
            proof,
        }
    }
}

/// Helper class to ensure that credential id uuid's are prefixed with `"uuid:"`.
#[derive(Clone, Deserialize, Serialize)]
#[serde(try_from = "String")]
pub struct PrefixedUuid(String);

impl PrefixedUuid {
    /// Creates a new `PrefixedUuid` by either taking given uuid as is or prefixing it with `"uuid:"` if required.
    ///
    /// # Arguments
    ///
    /// * `uuid` - uuid string to use as value
    pub fn new(uuid: String) -> Self {
        if uuid.starts_with("uuid:") {
            Self(uuid)
        } else {
            Self(format!("uuid:{}", &uuid))
        }
    }

    /// Tries to create a new `PrefixedUuid` instance, will fail if missing the `"uuid:"` prefix. Used for parsing uuids.
    ///
    /// # Arguments
    ///
    /// * `uuid` - uuid string to use as value
    pub fn try_new(uuid: String) -> Result<Self, String> {
        if uuid.starts_with("uuid:") {
            Ok(Self(uuid))
        } else {
            Err(format!(
                r#"uuid must start with prefix "uuid:" but got: "{}""#,
                uuid
            ))
        }
    }

    pub fn into_inner(self) -> String {
        self.0
    }

    pub fn inner(&self) -> &String {
        &self.0
    }
}

impl TryFrom<String> for PrefixedUuid {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        PrefixedUuid::try_new(value)
    }
}

impl Display for PrefixedUuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DraftBbsCredential {
    #[serde(rename(serialize = "@context", deserialize = "@context"))]
    pub context: Vec<String>,
    pub id: PrefixedUuid,
    pub r#type: Vec<String>,
    pub issuer: String,
    pub issuance_date: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    pub credential_subject: CredentialSubject,
    pub credential_schema: CredentialSchemaReference,
}

impl DraftBbsCredential {
    pub fn to_unsigned_credential(
        &self,
        status: Option<CredentialStatus>,
    ) -> UnsignedBbsCredential {
        UnsignedBbsCredential {
            context: self.context.clone(),
            id: self.id.clone(),
            r#type: self.r#type.clone(),
            issuer: self.issuer.to_owned(),
            valid_until: self.valid_until.to_owned(),
            issuance_date: self.issuance_date.clone(),
            credential_subject: self.credential_subject.clone(),
            credential_schema: self.credential_schema.clone(),
            credential_status: status.clone(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum LdProofVcDetailOptionsType {
    Ed25519Signature2018,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum LdProofVcDetailOptionsCredentialStatusType {
    RevocationList2021Status,
    None,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LdProofVcDetailOptionsCredentialStatus {
    pub r#type: LdProofVcDetailOptionsCredentialStatusType,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct LdProofVcDetailOptions {
    pub created: String,
    pub proof_type: LdProofVcDetailOptionsType,
    pub credential_status: LdProofVcDetailOptionsCredentialStatus,
    #[serde(default = "empty_array")]
    pub required_reveal_statements: Vec<u32>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LdProofVcDetail {
    pub credential: DraftBbsCredential,
    pub options: LdProofVcDetailOptions,
}

fn empty_array() -> Vec<u32> {
    [].into()
}

impl LdProofVcDetail {
    pub fn get_message_count(&self) -> Result<usize, Box<dyn Error>> {
        let mut message_count = CORE_MESSAGE_COUNT
            + ADDITIONAL_HIDDEN_MESSAGES_COUNT
            + &self.credential.credential_subject.data.len();

        if self.credential.valid_until.is_some() {
            message_count += 1;
        }

        message_count += match &self.options.credential_status.r#type {
            LdProofVcDetailOptionsCredentialStatusType::RevocationList2021Status => 4, // 1 link to sub-section, 3 lines with payload, 0 extra line for id (used in key)
            LdProofVcDetailOptionsCredentialStatusType::None => 0,
        };

        Ok(message_count)
    }
}

#[cfg(test)]
mod tests {
    extern crate utilities;

    use serde_json::Value;
    use utilities::test_data::bbs_coherent_context_test_data::{
        FINISHED_CREDENTIAL,
        PROOF_PRESENTATION,
        UNFINISHED_CREDENTIAL,
        UNSIGNED_CREDENTIAL,
    };

    use crate::{BbsCredential, ProofPresentation, UnfinishedBbsCredential, UnsignedBbsCredential};

    #[test]
    fn can_parse_a_credential_with_a_valid_uuid() -> Result<(), Box<dyn std::error::Error>> {
        let result: Result<BbsCredential, serde_json::Error> =
            serde_json::from_str(&FINISHED_CREDENTIAL);

        assert!(&result.is_ok());

        Ok(())
    }

    #[test]
    fn cannot_parse_a_credential_with_an_invalid_uuid() -> Result<(), Box<dyn std::error::Error>> {
        let mut credential: Value = serde_json::from_str(&FINISHED_CREDENTIAL)?;
        credential["id"] = Value::String("733ae398-ca4e-45e8-a420-a602b1ab9131".to_string());
        let serialized_with_invalid_id = serde_json::to_string(&credential)?;

        let result: Result<BbsCredential, serde_json::Error> =
            serde_json::from_str(&serialized_with_invalid_id);

        assert!(&result.is_err());
        let error_message = format!("{}", &result.err().unwrap());
        assert!(error_message.starts_with(r#"uuid must start with prefix "uuid:""#));

        Ok(())
    }

    #[test]
    fn can_parse_an_unsigned_credential_with_a_valid_uuid() -> Result<(), Box<dyn std::error::Error>> {
        let result: Result<UnsignedBbsCredential, serde_json::Error> =
            serde_json::from_str(&UNSIGNED_CREDENTIAL);

        assert!(&result.is_ok());

        Ok(())
    }

    #[test]
    fn cannot_parse_an_unsigned_credential_with_an_invalid_uuid() -> Result<(), Box<dyn std::error::Error>> {
        let mut credential: Value = serde_json::from_str(&UNSIGNED_CREDENTIAL)?;
        credential["id"] = Value::String("733ae398-ca4e-45e8-a420-a602b1ab9131".to_string());
        let serialized_with_invalid_id = serde_json::to_string(&credential)?;

        let result: Result<UnsignedBbsCredential, serde_json::Error> =
            serde_json::from_str(&serialized_with_invalid_id);

        assert!(&result.is_err());
        let error_message = format!("{}", &result.err().unwrap());
        assert!(error_message.starts_with(r#"uuid must start with prefix "uuid:""#));

        Ok(())
    }

    #[test]
    fn can_parse_an_unfinished_credential_with_a_valid_uuid() -> Result<(), Box<dyn std::error::Error>> {
        let result: Result<UnfinishedBbsCredential, serde_json::Error> =
            serde_json::from_str(&UNFINISHED_CREDENTIAL);

        assert!(&result.is_ok());

        Ok(())
    }

    #[test]
    fn cannot_parse_an_unfinished_credential_with_an_invalid_uuid() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut credential: Value = serde_json::from_str(&UNFINISHED_CREDENTIAL)?;
        credential["id"] = Value::String("733ae398-ca4e-45e8-a420-a602b1ab9131".to_string());
        let serialized_with_invalid_id = serde_json::to_string(&credential)?;

        let result: Result<UnfinishedBbsCredential, serde_json::Error> =
            serde_json::from_str(&serialized_with_invalid_id);

        assert!(&result.is_err());
        let error_message = format!("{}", &result.err().unwrap());
        assert!(error_message.starts_with(r#"uuid must start with prefix "uuid:""#));

        Ok(())
    }

    #[test]
    fn can_parse_a_proof_presentation_with_a_valid_uuid() -> Result<(), Box<dyn std::error::Error>> {
        let result: Result<ProofPresentation, serde_json::Error> =
            serde_json::from_str(&PROOF_PRESENTATION);

        assert!(&result.is_ok());

        Ok(())
    }

    #[test]
    fn cannot_parse_a_proof_presentation_with_an_invalid_uuid() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut proof_presentation: Value = serde_json::from_str(&PROOF_PRESENTATION)?;
        proof_presentation["verifiableCredential"]
            .as_array_mut()
            .ok_or_else(|| "could not get verifiableCredential array".to_string())?[0]
            .as_object_mut()
            .ok_or_else(|| "could not get the first verifiableCredential object".to_string())?
            ["id"] =
            Value::String("733ae398-ca4e-45e8-a420-a602b1ab9131".to_string());
        let serialized_with_invalid_id = serde_json::to_string(&proof_presentation)?;

        let result: Result<ProofPresentation, serde_json::Error> =
            serde_json::from_str(&serialized_with_invalid_id);

        assert!(&result.is_err());
        let error_message = format!("{}", &result.err().unwrap());
        assert!(error_message.starts_with(r#"uuid must start with prefix "uuid:""#));

        Ok(())
    }
}
