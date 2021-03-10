use bbs::BlindSignatureContext;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const CREDENTIAL_REQUEST_TYPE: &str = "EvanBbsCredentialRequest";
pub const CREDENTIAL_PROPOSAL_TYPE: &str = "EvanCredentialProposal";
pub const CREDENTIAL_OFFER_TYPE: &str = "EvanBbsCredentialOffering";
pub const CREDENTIAL_SIGNATURE_TYPE: &str = "BbsBlsSignature2020";
pub const CREDENTIAL_SCHEMA_TYPE: &str = "EvanZKPSchema";
pub const CREDENTIAL_PROOF_PURPOSE: &str = "assertionMethod";
pub const DEFAULT_CREDENTIAL_CONTEXTS: [&'static str; 2] = [
    "https://www.w3.org/2018/credentials/v1",
    "https:://schema.org",
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
    pub blind_signature_context: BlindSignatureContext,
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

// A verifiable credential with a blind signature that still needs to be processed by the holder
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
    pub proof: BbsUnfinishedCredentialSignature,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSubject {
    pub id: String,
    pub data: HashMap<String, String>,
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
