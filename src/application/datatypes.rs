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
use std::collections::HashMap;

pub const CREDENTIAL_REQUEST_TYPE: &str = "EvanBbsCredentialRequest";
pub const CREDENTIAL_PROPOSAL_TYPE: &str = "EvanCredentialProposal";
pub const CREDENTIAL_OFFER_TYPE: &str = "EvanBbsCredentialOffering";
pub const CREDENTIAL_SIGNATURE_TYPE: &str = "BbsBlsSignature2020";
pub const PROOF_SIGNATURE_TYPE: &str = "BbsBlsSignatureProof2020";
pub const CREDENTIAL_SCHEMA_TYPE: &str = "EvanZKPSchema";
pub const CREDENTIAL_PROOF_PURPOSE: &str = "assertionMethod";
pub const DEFAULT_CREDENTIAL_CONTEXTS: [&'static str; 3] = [
    "https://www.w3.org/2018/credentials/v1",
    "https:://schema.org",
    "https://w3id.org/vc-status-list-2021/v1",
];
pub const DEFAULT_REVOCATION_CONTEXTS: [&'static str; 2] = [
    "https://www.w3.org/2018/credentials/v1",
    "https://w3id.org/vc-status-list-2021/v1",
];
pub const KEY_SIZE: usize = 500;

/// Message following a `BbsCredentialOffer`, sent by a potential credential prover.
/// Provides the values that need to be signed by the issuer in both encoded/cleartext, and blinded format.
/// Incorporates the nonce value sent in `BbsCredentialOffer`.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BbsCredentialRequest {
    pub subject: String,
    pub schema: String,
    pub r#type: String,
    pub blind_signature_context: String,
    pub credential_values: HashMap<String, String>,
}

/// Message sent by a verifier stating which attributes of which schema the prover is supposed to reveal.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BbsProofRequest {
    pub verifier: String,
    pub created_at: String,
    pub nonce: String,
    pub sub_proof_requests: Vec<BbsSubProofRequest>,
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

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SchemaProperty {
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<String>>,
}

/// AssertionProof, typically used to ensure authenticity and integrity of a VC document
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AssertionProof {
    pub r#type: String,
    pub created: String,
    pub proof_purpose: String,
    pub verification_method: String,
    pub jws: String,
}

/// Message following a `CredentialProposal`, sent by an issuer.
/// Specifies the DIDs of both the `CredentialSchema` and `CredentialDefinition`
/// to be used for issuance.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BbsCredentialOffer {
    pub issuer: String,
    pub subject: String,
    pub r#type: String,
    pub schema: String,
    pub nonce: String,
}

/// Message to initiate credential issuance, sent by (potential) prover.
/// Specifies the schema to be used for the credential.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CredentialProposal {
    pub issuer: String,
    pub subject: String,
    pub r#type: String,
    pub schema: String,
}

/// A verifiable credential issued by an issuer upon receiving a `CredentialRequest`.
/// Specifies the signed values, the DID of the prover/subject, the `CredentialSchema`, and the `CredentialSignature`
/// including revocation info.
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BbsCredential {
    #[serde(rename(serialize = "@context", deserialize = "@context"))]
    pub context: Vec<String>,
    pub id: String,
    pub r#type: Vec<String>,
    pub issuer: String,
    pub credential_subject: CredentialSubject,
    pub credential_schema: CredentialSchemaReference,
    pub credential_status: CredentialStatus,
    pub proof: BbsCredentialSignature,
}

impl BbsCredential {
    pub fn new(cred: UnfinishedBbsCredential, signature: String) -> BbsCredential {
        BbsCredential {
            context: cred.context,
            id: cred.id,
            r#type: cred.r#type,
            issuer: cred.issuer,
            credential_subject: CredentialSubject {
                id: cred.credential_subject.id,
                data: cred.credential_subject.data,
            },
            credential_schema: CredentialSchemaReference {
                id: cred.credential_schema.id,
                r#type: cred.credential_schema.r#type,
            },
            credential_status: CredentialStatus {
                id: cred.credential_status.id,
                r#type: cred.credential_status.r#type,
                revocation_list_index: cred.credential_status.revocation_list_index,
                revocation_list_credential: cred.credential_status.revocation_list_credential,
            },
            proof: BbsCredentialSignature {
                created: cred.proof.created,
                proof_purpose: cred.proof.proof_purpose,
                required_reveal_statements: cred.proof.required_reveal_statements,
                signature: signature,
                r#type: cred.proof.r#type,
                verification_method: cred.proof.verification_method,
            },
        }
    }
}

/// A verifiable credential with a blind signature that still needs to be processed by the holder
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UnfinishedBbsCredential {
    #[serde(rename(serialize = "@context", deserialize = "@context"))]
    pub context: Vec<String>,
    pub id: String,
    pub r#type: Vec<String>,
    pub issuer: String,
    pub credential_subject: CredentialSubject,
    pub credential_schema: CredentialSchemaReference,
    pub credential_status: CredentialStatus,
    pub proof: BbsUnfinishedCredentialSignature,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubject {
    pub id: String,
    pub data: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatus {
    pub id: String,
    pub r#type: String,
    pub revocation_list_index: String,
    pub revocation_list_credential: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RevocationListCredentialSubject {
    pub id: String,
    pub r#type: String,
    pub encoded_list: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemaReference {
    pub id: String,
    pub r#type: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BbsCredentialSignature {
    pub r#type: String,
    pub created: String,
    pub proof_purpose: String,
    pub verification_method: String,
    pub required_reveal_statements: Vec<u32>,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BbsUnfinishedCredentialSignature {
    pub r#type: String,
    pub created: String,
    pub proof_purpose: String,
    pub verification_method: String,
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
    pub proof: AssertionProof,
}

impl ProofPresentation {
    pub fn new(
        unsigned_proof_presentation: UnfinishedProofPresentation,
        proof: AssertionProof,
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
    pub id: String,
    pub r#type: Vec<String>,
    pub issuer: String,
    pub issuance_date: String,
    pub credential_subject: CredentialSubject,
    pub credential_schema: CredentialSchemaReference,
    pub credential_status: CredentialStatus,
    pub proof: BbsPresentationProof,
}

impl BbsPresentation {
    pub fn new(
        cred: BbsCredential,
        issuance_date: String,
        proof: SignatureProof,
        revealed_properties: CredentialSubject,
        nonce: ProofNonce,
    ) -> BbsPresentation {
        BbsPresentation {
            context: cred.context,
            id: cred.id,
            issuance_date: issuance_date,
            r#type: cred.r#type,
            issuer: cred.issuer,
            credential_subject: revealed_properties,
            credential_schema: CredentialSchemaReference {
                id: cred.credential_schema.id,
                r#type: cred.credential_schema.r#type,
            },
            credential_status: CredentialStatus {
                id: cred.credential_status.id,
                r#type: cred.credential_status.r#type,
                revocation_list_index: cred.credential_status.revocation_list_index,
                revocation_list_credential: cred.credential_status.revocation_list_credential,
            },
            proof: BbsPresentationProof {
                created: cred.proof.created,
                proof_purpose: cred.proof.proof_purpose,
                proof: base64::encode(proof.to_bytes_compressed_form()),
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
    pub verification_method: String,
    pub nonce: String,
    pub proof: String,
}

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

/// A revocation list credential associating VC revocation IDs to their revocation status as a bit list. See
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
