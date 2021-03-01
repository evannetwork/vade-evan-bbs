use bbs::{BlindSignatureContext, ProofNonce};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Message following a `CredentialOffer`, sent by a potential credential prover.
/// Provides the values that need to be signed by the issuer in both encoded/cleartext, and blinded format.
/// Incorporates the nonce value sent in `CredentialOffer`.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BbsCredentialRequest {
    pub subject: String,
    pub schema: String,
    pub credential_definition: String,
    pub r#type: String,
    pub blind_signature_context: BlindSignatureContext,
    pub credential_values: HashMap<String, String>,
}

/// Specifies the properties of a credential, as well as metadata.
/// Needs to be stored publicly available and temper-proof.
#[derive(Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaProperty {
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
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
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialOffer {
    pub issuer: String,
    pub subject: String,
    pub r#type: String,
    pub schema: String,
    pub credential_definition: String,
    pub nonce: ProofNonce,
}
