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

use crate::application::{
    datatypes::{
        BbsCredential, BbsCredentialOffer, BbsCredentialRequest, BbsProofRequest,
        CredentialProposal, CredentialSchema, RevocationListCredential,
    },
    issuer::Issuer,
    prover::Prover,
    verifier::Verifier,
};
use async_trait::async_trait;
use bbs::{
    keys::{DeterministicPublicKey, SecretKey},
    SignatureMessage,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, error::Error};
use vade::{Vade, VadePlugin, VadePluginResultValue};
use vade_evan_substrate::signing::Signer;

const EVAN_METHOD: &str = "did:evan";
const EVAN_METHOD_ZKP: &str = "did:evan:zkp";
const PROOF_METHOD_CL: &str = "cl";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypeOptions {
    pub r#type: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationOptions {
    pub private_key: String,
    pub identity: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRevocationListPayload {
    pub issuer_did: String,
    pub schema_did: String,
    pub issuer_public_key_did: String,
    pub issuer_proving_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueCredentialPayload {
    pub issuer: String,
    pub issuer_public_key_id: String,
    pub issuer_public_key: DeterministicPublicKey,
    pub issuer_secret_key: SecretKey,
    pub issuance_date: Option<String>,
    pub subject: String,
    pub schema: String,
    pub credential_request: BbsCredentialRequest,
    pub credential_offer: BbsCredentialOffer,
    pub required_indices: Vec<u32>,
    pub nquads: Vec<String>,
    pub revocation_list_did: String,
    pub revocation_list_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OfferCredentialPayload {
    pub issuer: String,
    pub credential_proposal: CredentialProposal,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentProofPayload {
    pub proof_request: BbsProofRequest,
    pub credential_schema_map: HashMap<String, BbsCredential>,
    pub public_key_schema_map: HashMap<String, DeterministicPublicKey>,
    pub nquads_schema_map: HashMap<String, Vec<String>>,
    pub master_secret: SignatureMessage,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCredentialProposalPayload {
    pub issuer: String,
    pub subject: String,
    pub schema: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestCredentialPayload {
    pub credential_offering: BbsCredentialOffer,
    pub credential_schema: String,
    pub master_secret: SignatureMessage,
    pub credential_values: HashMap<String, String>,
    pub issuer_pub_key: DeterministicPublicKey,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestProofPayload {
    pub verifier_did: String,
    pub schemas: Vec<CredentialSchema>,
    pub reveal_attributes: HashMap<String, Vec<usize>>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeCredentialPayload {
    pub issuer: String,
    pub revocation_list: String,
    pub revocation_id: usize,
    pub issuer_public_key_did: String,
    pub issuer_proving_key: String,
}

macro_rules! parse {
    ($data:expr, $type_name:expr) => {{
        serde_json::from_str($data)
            .map_err(|e| format!("{} when parsing {} {}", &e, $type_name, $data))?
    }};
}

macro_rules! get_document {
    ($vade:expr, $did:expr, $type_name:expr) => {{
        debug!("fetching {} with did; {}", $type_name, $did);
        let resolve_result = $vade.did_resolve($did).await?;
        let result_str = resolve_result[0]
            .as_ref()
            .ok_or_else(|| format!("could not get {} did document", $type_name))?;
        parse!(&result_str, &$type_name)
    }};
}

macro_rules! ignore_unrelated {
    ($method:expr, $options:expr) => {{
        if $method != EVAN_METHOD {
            return Ok(VadePluginResultValue::Ignored);
        }
        let type_options: TypeOptions = parse!($options, "options");
        match type_options.r#type.as_deref() {
            Some(PROOF_METHOD_CL) => (),
            _ => return Ok(VadePluginResultValue::Ignored),
        };
    }};
}

pub struct VadeEvanBbs {
    signer: Box<dyn Signer>,
    vade: Vade,
}

impl VadeEvanBbs {
    /// Creates new instance of `VadeEvanBbs`.
    pub fn new(vade: Vade, signer: Box<dyn Signer>) -> VadeEvanBbs {
        match env_logger::try_init() {
            Ok(_) | Err(_) => (),
        };
        VadeEvanBbs { signer, vade }
    }
}

impl VadeEvanBbs {
    async fn generate_did(
        &mut self,
        private_key: &str,
        identity: &str,
    ) -> Result<String, Box<dyn Error>> {
        let options = format!(
            r###"{{
            "privateKey": "{}",
            "identity": "{}"
        }}"###,
            private_key, identity
        );
        let result = self
            .vade
            .did_create(EVAN_METHOD_ZKP, &options, &"".to_string())
            .await?;
        if result.is_empty() {
            return Err(Box::from(
                "Could not generate DID as no listeners were registered for this method",
            ));
        }

        let generated_did = result[0]
            .as_ref()
            .ok_or("could not generate DID")?
            .to_owned();

        Ok(generated_did)
    }

    async fn set_did_document(
        &mut self,
        did: &str,
        payload: &str,
        private_key: &str,
        identity: &str,
    ) -> Result<Option<String>, Box<dyn Error>> {
        let options = format!(
            r###"{{
            "privateKey": "{}",
            "identity": "{}",
            "operation": "setDidDocument"
        }}"###,
            &private_key, &identity
        );
        let result = self.vade.did_update(&did, &options, &payload).await?;

        if result.is_empty() {
            return Err(Box::from(
                "Could not set did document as no listeners were registered for this method",
            ));
        }

        Ok(Some("".to_string()))
    }
}

#[async_trait(?Send)]
impl VadePlugin for VadeEvanBbs {
    /// Creates a new revocation registry definition and stores it on-chain. The definition consists of a public
    /// and a private part. The public part holds the cryptographic material needed to create non-revocation proofs.
    /// The private part needs to reside with the registry owner and is used to revoke credentials.
    ///
    /// Note that `options.identity` needs to be whitelisted for this function.
    ///
    /// # Arguments
    ///
    /// * `method` - method to create a revocation registry definition for (e.g. "did:example")
    /// * `options` - serialized [`AuthenticationOptions`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.AuthenticationOptions.html)
    /// * `payload` - serialized [`CreateRevocationRegistryDefinitionPayload`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.CreateRevocationRegistryDefinitionPayload.html)
    ///
    /// # Returns
    /// * created revocation registry definition as a JSON object as serialized [`CreateRevocationRegistryDefinitionResult`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.CreateRevocationRegistryDefinitionResult.html)
    async fn vc_zkp_create_revocation_registry_definition(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);
        let options: AuthenticationOptions = parse!(&options, "options");
        let payload: CreateRevocationListPayload = parse!(&payload, "payload");

        let generated_did = self
            .generate_did(&options.private_key, &options.identity)
            .await?;

        let revocation_list = Issuer::create_revocation_list(
            &generated_did,
            &payload.issuer_did,
            &payload.issuer_public_key_did,
            &payload.issuer_proving_key,
            &self.signer,
        )
        .await?;

        let serialized_list = serde_json::to_string(&revocation_list)?;

        self.set_did_document(
            &generated_did,
            &serialized_list,
            &options.private_key,
            &options.identity,
        )
        .await?;

        let serialized_result = serde_json::to_string(&serialized_list)?;

        Ok(VadePluginResultValue::Success(Some(serialized_result)))
    }

    /// Issues a new credential. This requires an issued schema, credential definition, an active revocation
    /// registry and a credential request message.
    ///
    /// # Arguments
    ///
    /// * `method` - method to issue a credential for (e.g. "did:example")
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.TypeOptions.html)
    /// * `payload` - serialized [`IssueCredentialPayload`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.IssueCredentialPayload.html)
    ///
    /// # Returns
    /// * serialized [`IssueCredentialResult`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.IssueCredentialResult.html) consisting of the credential, this credential's initial revocation state and
    /// the updated revocation info, only interesting for the issuer (needs to be stored privately)
    async fn vc_zkp_issue_credential(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);
        let payload: IssueCredentialPayload = parse!(&payload, "payload");
        let schema: CredentialSchema = get_document!(&mut self.vade, &payload.schema, "schema");
        let unfinished_credential = Issuer::issue_credential(
            &payload.issuer,
            &payload.subject,
            &payload.credential_offer,
            &payload.credential_request,
            &payload.issuer_public_key_id,
            &payload.issuer_public_key,
            &payload.issuer_secret_key,
            schema,
            payload.required_indices,
            payload.nquads,
            &payload.revocation_list_did,
            &payload.revocation_list_id,
        )?;

        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &unfinished_credential,
        )?)))
    }

    /// Creates a `CredentialOffer` message. A `CredentialOffer` is sent by an issuer and is the response
    /// to a `CredentialProposal`. The `CredentialOffer` specifies which schema and definition the issuer
    /// is capable and willing to use for credential issuance.
    ///
    /// # Arguments
    ///
    /// * `method` - method to create a credential offer for (e.g. "did:example")
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.TypeOptions.html)
    /// * `payload` - serialized [`OfferCredentialPayload`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.OfferCredentialPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - The offer as a JSON object
    async fn vc_zkp_create_credential_offer(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);
        let payload: OfferCredentialPayload = parse!(&payload, "payload");
        let result: BbsCredentialOffer =
            Issuer::offer_credential(&payload.credential_proposal, &payload.issuer)?;
        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &result,
        )?)))
    }

    /// Presents a proof for one or more credentials. A proof presentation is the response to a
    /// proof request. The proof needs to incorporate all required fields from all required schemas
    /// requested in the proof request.
    ///
    /// # Arguments
    ///
    /// * `method` - method to presents a proof for (e.g. "did:example")
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.TypeOptions.html)
    /// * `payload` - serialized [`PresentProofPayload`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.PresentProofPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - The offer as a JSON object
    async fn vc_zkp_present_proof(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);
        let payload: PresentProofPayload = parse!(&payload, "payload");

        let _ = Prover::present_proof(
            payload.proof_request,
            payload.credential_schema_map,
            payload.public_key_schema_map,
            payload.nquads_schema_map,
            payload.master_secret,
        )?;

        Err(Box::from("Not implemented"))
        // Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
        //     &result,
        // )?)))
    }

    /// Creates a new zero-knowledge proof credential proposal. This message is the first in the
    /// credential issuance flow and is sent by the potential credential holder to the credential issuer.
    ///
    /// # Arguments
    ///
    /// * `method` - method to create a credential proposal for (e.g. "did:example")
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.TypeOptions.html)
    /// * `payload` - serialized [`CreateCredentialProposalPayload`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.CreateCredentialProposalPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - The proposal as a JSON object
    async fn vc_zkp_create_credential_proposal(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);
        let payload: CreateCredentialProposalPayload = parse!(&payload, "payload");
        let result: CredentialProposal =
            Prover::propose_credential(&payload.issuer, &payload.subject, &payload.schema);

        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &result,
        )?)))
    }

    /// Requests a credential. This message is the response to a credential offering and is sent by the potential
    /// credential holder. It incorporates the target schema, credential definition offered by the issuer, and
    /// the encoded values the holder wants to get signed. The credential is not stored on-chain and needs to be
    /// kept private.
    ///
    /// # Arguments
    ///
    /// * `method` - method to request a credential for (e.g. "did:example")
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.TypeOptions.html)
    /// * `payload` - serialized [`RequestCredentialPayload`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.RequestCredentialPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - A JSON object consisting of the `CredentialRequest` and `CredentialSecretsBlindingFactors` (to be stored at the proofer's site in a private manner)
    async fn vc_zkp_request_credential(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);
        let payload: RequestCredentialPayload = serde_json::from_str(&payload)
            .map_err(|e| format!("{} when parsing payload {}", &e, &payload))?;
        let schema: CredentialSchema =
            get_document!(&mut self.vade, &payload.credential_schema, "schema");

        let result = Prover::request_credential(
            &payload.credential_offering,
            &schema,
            &payload.master_secret,
            payload.credential_values,
            &payload.issuer_pub_key,
        )?;

        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &result,
        )?)))
    }

    /// Requests a zero-knowledge proof for one or more credentials issued under one or more specific schemas and
    /// is sent by a verifier to a prover.
    /// The proof request consists of the fields the verifier wants to be revealed per schema.
    ///
    /// # Arguments
    ///
    /// * `method` - method to request a proof for (e.g. "did:example")
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.TypeOptions.html)
    /// * `payload` - serialized [`RequestProofPayload`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.RequestProofPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - A `ProofRequest` as JSON
    async fn vc_zkp_request_proof(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);
        let payload: RequestProofPayload = parse!(&payload, "payload");
        let result: BbsProofRequest = Verifier::create_proof_request(
            payload.verifier_did,
            payload.schemas,
            payload.reveal_attributes,
        )?;

        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &result,
        )?)))
    }

    /// Revokes a credential. After revocation the published revocation registry needs to be updated with information
    /// returned by this function. To revoke a credential, tbe revoker must be in possession of the private key associated
    /// with the credential's revocation registry. After revocation, the published revocation registry must be updated.
    /// Only then is the credential truly revoked.
    ///
    /// Note that `options.identity` needs to be whitelisted for this function.
    ///
    /// # Arguments
    ///
    /// * `method` - method to revoke a credential for (e.g. "did:example")
    /// * `options` - serialized [`AuthenticationOptions`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.AuthenticationOptions.html)
    /// * `payload` - serialized [`RevokeCredentialPayload`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.RevokeCredentialPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - The updated revocation registry definition as a JSON object. Contains information
    /// needed to update the respective revocation registry.
    async fn vc_zkp_revoke_credential(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);
        let options: AuthenticationOptions = parse!(&options, "options");
        let payload: RevokeCredentialPayload = parse!(&payload, "payload");
        let rev_list: RevocationListCredential =
            get_document!(&mut self.vade, &payload.revocation_list, "revocation list");

        let updated_list = Issuer::revoke_credential(
            &payload.issuer,
            rev_list,
            payload.revocation_id,
            &payload.issuer_public_key_did,
            &payload.issuer_proving_key,
            &self.signer,
        )
        .await?;

        let serialized = serde_json::to_string(&updated_list)?;

        self.set_did_document(
            &updated_list.id,
            &serialized,
            &options.private_key,
            &options.identity,
        )
        .await?;

        Ok(VadePluginResultValue::Success(Some(serialized)))
    }

    /// Verifies one or multiple proofs sent in a proof presentation.
    ///
    /// # Arguments
    ///
    /// * `method` - method to verify a proof for (e.g. "did:example")
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.TypeOptions.html)
    /// * `payload` - serialized [`ValidateProofPayload`](https://docs.rs/vade_evan_cl/*/vade_evan_cl/struct.ValidateProofPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - A JSON object representing a `ProofVerification` type, specifying whether verification was successful
    async fn vc_zkp_verify_proof(
        &mut self,
        _method: &str,
        _options: &str,
        _payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        Err(Box::from("Not implemented"))
    }
}
