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

use crate::{
    application::{
        datatypes::{
            BbsCredential,
            BbsCredentialOffer,
            BbsCredentialRequest,
            BbsProofRequest,
            BbsProofVerification,
            CredentialProposal,
            CredentialSchema,
            CredentialSubject,
            ProofPresentation,
            RevocationListCredential,
            SchemaProperty,
            UnfinishedBbsCredential,
        },
        issuer::Issuer,
        prover::Prover,
        utils::{generate_uuid, get_dpk_from_string},
        verifier::Verifier,
    },
    crypto::crypto_verifier::CryptoVerifier,
};
use async_trait::async_trait;
use bbs::{
    keys::{DeterministicPublicKey, SecretKey},
    SignatureBlinding,
    SignatureMessage,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashMap, error::Error};
use vade::{Vade, VadePlugin, VadePluginResultValue};
use vade_evan_substrate::signing::Signer;

const EVAN_METHOD: &str = "did:evan";
const EVAN_METHOD_ZKP: &str = "did:evan:zkp";
const PROOF_METHOD_BBS: &str = "bbs";

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
    pub issuer_public_key_did: String,
    pub issuer_proving_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueCredentialPayload {
    pub issuer: String,
    pub issuer_public_key_id: String,
    pub issuer_public_key: String,
    pub issuer_secret_key: String,
    pub subject: String,
    pub schema: String,
    pub credential_request: BbsCredentialRequest,
    pub credential_offer: BbsCredentialOffer,
    pub required_indices: Vec<u32>,
    pub nquads: Vec<String>,
    pub revocation_list_did: String,
    pub revocation_list_id: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OfferCredentialPayload {
    pub issuer: String,
    pub credential_proposal: CredentialProposal,
    pub nquad_count: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentProofPayload {
    pub proof_request: BbsProofRequest,
    pub credential_schema_map: HashMap<String, BbsCredential>,
    pub revealed_properties_schema_map: HashMap<String, CredentialSubject>,
    pub public_key_schema_map: HashMap<String, String>,
    pub nquads_schema_map: HashMap<String, Vec<String>>,
    pub master_secret: String,
    pub prover_did: String,
    pub prover_public_key_did: String,
    pub prover_proving_key: String,
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
    pub master_secret: String,
    pub credential_values: HashMap<String, String>,
    pub issuer_pub_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestProofPayload {
    pub verifier_did: String,
    pub schemas: Vec<String>,
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

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCredentialSchemaPayload {
    pub issuer: String,
    pub schema_name: String,
    pub description: String,
    pub properties: HashMap<String, SchemaProperty>,
    pub required_properties: Vec<String>,
    pub allow_additional_properties: bool,
    pub issuer_public_key_did: String,
    pub issuer_proving_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinishCredentialPayload {
    pub credential: UnfinishedBbsCredential,
    pub master_secret: String,
    pub nquads: Vec<String>,
    pub issuer_public_key: String,
    pub blinding: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyProofPayload {
    pub presentation: ProofPresentation,
    pub proof_request: BbsProofRequest,
    pub keys_to_schema_map: HashMap<String, String>,
    pub signer_address: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateKeysPayload {
    pub key_owner_did: String,
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
            Some(PROOF_METHOD_BBS) => (),
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

    async fn create_new_keys(
        &mut self,
        options: AuthenticationOptions,
        payload: CreateKeysPayload,
    ) -> Result<String, Box<dyn Error>> {
        let keys = Issuer::create_new_keys();
        let pub_key = base64::encode(keys.0.to_bytes_compressed_form());
        let secret_key = base64::encode(keys.1.to_bytes_compressed_form());

        let key_id = format!("bbs-key-{}", generate_uuid());

        let serialised_keys = format!(
            r###"{{
                "didUrl": "{}#{}",
                "publicKey": "{}",
                "secretKey": "{}"
            }}"###,
            &payload.key_owner_did, key_id, pub_key, secret_key
        );

        let mut did_document: Value =
            get_document!(&mut self.vade, &payload.key_owner_did, "did document");

        let public_key_values = did_document["assertionMethod"].as_array();
        let mut public_keys = public_key_values.unwrap_or(&vec![]).clone();

        // See https://w3c-ccg.github.io/ldp-bbs2020/#bls12-381 for explanations why G2 Key (date: 07.04.2021, may be subject to change)
        let new_key = format!(
            r###"{{
                "id": "{}#{}",
                "type": "Bls12381G2Key2020",
                "publicKeyBase58": "{}"
            }}"###,
            &payload.key_owner_did,
            &key_id,
            &bs58::encode(keys.0.to_bytes_compressed_form()).into_string()
        );
        public_keys.push(serde_json::from_str(&new_key)?);
        did_document["assertionMethod"] = serde_json::Value::Array(public_keys);

        self.set_did_document(
            &payload.key_owner_did,
            &serde_json::to_string(&did_document)?,
            &options.private_key,
            &options.identity,
        )
        .await?;

        Ok(serialised_keys)
    }
}

#[async_trait(?Send)]
impl VadePlugin for VadeEvanBbs {
    /// Runs a custom function, currently supports
    ///
    /// - `create_master_secret` to create new master secrets
    /// - `create_new_keys` to create a new key pair for BBS+ based signatures and persist  this in the given identity's DID document
    ///
    /// # Arguments
    ///
    /// * `method` - method to call a function for (e.g. "did:example")
    /// * `function` - currently supports `create_master_secret` and  `create_new_keys`
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.TypeOptions.html)
    /// * `payload` - necessary for `create_new_keys`, can be left empty for `create_master_secret`
    async fn run_custom_function(
        &mut self,
        method: &str,
        function: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);
        match function {
            "create_master_secret" => Ok(VadePluginResultValue::Success(Some(
                serde_json::to_string(&Prover::create_master_secret())?,
            ))),
            "create_new_keys" => {
                let options: AuthenticationOptions = parse!(&options, "options");
                let payload: CreateKeysPayload = parse!(&payload, "payload");
                Ok(VadePluginResultValue::Success(Some(
                    self.create_new_keys(options, payload).await?,
                )))
            }
            _ => Ok(VadePluginResultValue::Ignored),
        }
    }

    /// Creates a new zero-knowledge proof credential schema.
    ///
    /// Note that `options.identity` needs to be whitelisted for this function.
    ///
    /// # Arguments
    ///
    /// * `method` - method to create a credential schema for (e.g. "did:example")
    /// * `options` - serialized [`AuthenticationOptions`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.AuthenticationOptions.html)
    /// * `payload` - serialized [`CreateCredentialSchemaPayload`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.CreateCredentialSchemaPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - The created schema as a JSON object
    async fn vc_zkp_create_credential_schema(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);
        let options: AuthenticationOptions = parse!(&options, "options");
        let payload: CreateCredentialSchemaPayload = parse!(&payload, "payload");

        let generated_did = self
            .generate_did(&options.private_key, &options.identity)
            .await?;

        let schema = Issuer::create_credential_schema(
            &generated_did,
            &payload.issuer,
            &payload.schema_name,
            &payload.description,
            payload.properties,
            payload.required_properties,
            payload.allow_additional_properties,
            &payload.issuer_public_key_did,
            &payload.issuer_proving_key,
            &self.signer,
        )
        .await?;

        let serialized = serde_json::to_string(&schema)?;
        self.set_did_document(
            &generated_did,
            &serialized,
            &options.private_key,
            &options.identity,
        )
        .await?;

        Ok(VadePluginResultValue::Success(Some(serialized)))
    }

    /// Creates a new revocation list and stores it on-chain. The list consists of a encoded bit list which can
    /// hold up to 131,072 revokable ids. The list is GZIP encoded and will be updated on every revocation.
    /// The output is a W3C credential with a JWS signature by the given key.
    ///
    /// Note that `options.identity` needs to be whitelisted for this function.
    ///
    /// # Arguments
    ///
    /// * `method` - method to create a revocation list for (e.g. "did:example")
    /// * `options` - serialized [`AuthenticationOptions`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.AuthenticationOptions.html)
    /// * `payload` - serialized [`CreateRevocationListPayload`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.CreateRevocationListPayload.html)
    ///
    /// # Returns
    /// * created revocation list as a JSON object as serialized [`RevocationList`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.RevocationList.html)
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

        Ok(VadePluginResultValue::Success(Some(serialized_list)))
    }

    /// Issues a new credential. This requires an issued schema, revocations list, an credential offer
    /// and a credential request message. This method returns an unfinished credential which has to be post-processed
    /// by the holder.
    ///
    /// # Arguments
    ///
    /// * `method` - method to issue a credential for (e.g. "did:example")
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.TypeOptions.html)
    /// * `payload` - serialized [`IssueCredentialPayload`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.IssueCredentialPayload.html)
    ///
    /// # Returns
    /// * serialized [`UnfinishedBbsCredential`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.UnfinishedBbsCredential.html)
    async fn vc_zkp_issue_credential(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);
        let payload: IssueCredentialPayload = parse!(&payload, "payload");
        let public_key: DeterministicPublicKey = DeterministicPublicKey::from(
            base64::decode(&payload.issuer_public_key)?.into_boxed_slice(),
        );
        let sk: SecretKey =
            SecretKey::from(base64::decode(&payload.issuer_secret_key)?.into_boxed_slice());

        let schema: CredentialSchema = get_document!(&mut self.vade, &payload.schema, "schema");

        let unfinished_credential = Issuer::issue_credential(
            &payload.issuer,
            &payload.subject,
            &payload.credential_offer,
            &payload.credential_request,
            &payload.issuer_public_key_id,
            &public_key,
            &sk,
            schema,
            payload.required_indices,
            payload.nquads,
            &payload.revocation_list_did,
            payload.revocation_list_id,
        )?;

        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &unfinished_credential,
        )?)))
    }

    /// Creates a `CredentialOffer` message. A `CredentialOffer` is sent by an issuer and is the response
    /// to a `CredentialProposal`. The `CredentialOffer` specifies which schema the issuer
    /// is capable and willing to use for credential issuance.
    ///
    /// # Arguments
    ///
    /// * `method` - method to create a credential offer for (e.g. "did:example")
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.TypeOptions.html)
    /// * `payload` - serialized [`OfferCredentialPayload`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.OfferCredentialPayload.html)
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
        let result: BbsCredentialOffer = Issuer::offer_credential(
            &payload.credential_proposal,
            &payload.issuer,
            payload.nquad_count,
        )?;
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
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.TypeOptions.html)
    /// * `payload` - serialized [`PresentProofPayload`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.PresentProofPayload.html)
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

        let master_secret: SignatureMessage =
            SignatureMessage::from(base64::decode(&payload.master_secret)?.into_boxed_slice());

        let mut public_key_schema_map: HashMap<String, DeterministicPublicKey> = HashMap::new();
        for (schema_did, base64_public_key) in payload.public_key_schema_map.iter() {
            public_key_schema_map
                .insert(schema_did.clone(), get_dpk_from_string(base64_public_key)?);
        }

        let result = Prover::present_proof(
            &payload.proof_request,
            &payload.credential_schema_map,
            &payload.revealed_properties_schema_map,
            &public_key_schema_map,
            &payload.nquads_schema_map,
            &master_secret,
            &payload.prover_did,
            &payload.prover_public_key_did,
            &payload.prover_proving_key,
            &self.signer,
        )
        .await?;

        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &result,
        )?)))
    }

    /// Creates a new bbs credential proposal. This message is the first in the
    /// credential issuance flow and is sent by the potential credential holder to the credential issuer.
    ///
    /// # Arguments
    ///
    /// * `method` - method to create a credential proposal for (e.g. "did:example")
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.TypeOptions.html)
    /// * `payload` - serialized [`CreateCredentialProposalPayload`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.CreateCredentialProposalPayload.html)
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
    /// credential holder. It incorporates the target schema offered by the issuer, and
    /// the encoded values the holder wants to get signed. The credential is not stored on-chain and needs to be
    /// kept private.
    ///
    /// # Arguments
    ///
    /// * `method` - method to request a credential for (e.g. "did:example")
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.TypeOptions.html)
    /// * `payload` - serialized [`RequestCredentialPayload`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.RequestCredentialPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - A JSON object consisting of the `BbsCredentialRequest` and `SignatureBlinding` (to be stored at the holder's site in a private manner)
    async fn vc_zkp_request_credential(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);
        let payload: RequestCredentialPayload = serde_json::from_str(&payload)
            .map_err(|e| format!("{} when parsing payload {}", &e, &payload))?;
        let master_secret: SignatureMessage =
            SignatureMessage::from(base64::decode(&payload.master_secret)?.into_boxed_slice());
        let public_key: DeterministicPublicKey = DeterministicPublicKey::from(
            base64::decode(&payload.issuer_pub_key)?.into_boxed_slice(),
        );
        let schema: CredentialSchema =
            get_document!(&mut self.vade, &payload.credential_schema, "schema");
        let (credential_request, signature_blinding): (BbsCredentialRequest, SignatureBlinding) =
            Prover::request_credential(
                &payload.credential_offering,
                &schema,
                &master_secret,
                payload.credential_values,
                &public_key,
            )?;
        let result = serde_json::to_string(&(
            credential_request,
            base64::encode(signature_blinding.to_bytes_compressed_form()),
        ))?;
        Ok(VadePluginResultValue::Success(Some(result)))
    }

    /// Requests a proof for one or more credentials issued under one or more specific schemas and
    /// is sent by a verifier to a prover.
    /// The proof request consists of the fields the verifier wants to be revealed per schema.
    ///
    /// # Arguments
    ///
    /// * `method` - method to request a proof for (e.g. "did:example")
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.TypeOptions.html)
    /// * `payload` - serialized [`RequestProofPayload`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.RequestProofPayload.html)
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

    /// Revokes a credential. The information returned by this function needs to be persisted in order to update the revocation list. To revoke a credential, the revoker must be in possession of the private key associated
    /// with the credential's revocation list. After revocation, the published revocation list is updated on-chain.
    /// Only then is the credential truly revoked.
    ///
    /// Note that `options.identity` needs to be whitelisted for this function.
    ///
    /// # Arguments
    ///
    /// * `method` - method to revoke a credential for (e.g. "did:example")
    /// * `options` - serialized [`AuthenticationOptions`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.AuthenticationOptions.html)
    /// * `payload` - serialized [`RevokeCredentialPayload`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.RevokeCredentialPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - The updated revocation list as a JSON object. Contains information
    /// needed to update the respective revocation list.
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
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.TypeOptions.html)
    /// * `payload` - serialized [`ValidateProofPayload`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.ValidateProofPayload.html)
    ///
    /// # Returns
    /// * `Option<String>` - A JSON object representing a `BbdProofVerification` type, specifying whether verification was successful
    async fn vc_zkp_verify_proof(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);

        let payload: VerifyProofPayload = parse!(&payload, "payload");

        let mut public_key_schema_map: HashMap<String, DeterministicPublicKey> = HashMap::new();
        for (schema_did, base64_public_key) in payload.keys_to_schema_map.iter() {
            public_key_schema_map
                .insert(schema_did.clone(), get_dpk_from_string(base64_public_key)?);
        }

        let mut verfication_result = Verifier::verify_proof(
            &payload.presentation,
            &payload.proof_request,
            &public_key_schema_map,
            &payload.signer_address,
        )?;
        if verfication_result.status != "rejected" {
            // check revocation status
            for cred in &payload.presentation.verifiable_credential {
                let revocation_list: RevocationListCredential = get_document!(
                    &mut self.vade,
                    &cred.credential_status.revocation_list_credential,
                    "revocationlist"
                );
                let revoked =
                    CryptoVerifier::is_revoked(&cred.credential_status, &revocation_list)?;
                if revoked {
                    verfication_result = BbsProofVerification {
                        presented_proof: payload.presentation.id.to_string(),
                        status: "rejected".to_string(),
                        reason: Some(format!("Credential id {} is revoked", cred.id)),
                    };
                }
            }
        }

        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &verfication_result,
        )?)))
    }

    /// Finishes a credential, e.g. by incorporating the prover's master secret into the credential signature after issuance.
    ///
    /// # Arguments
    ///
    /// * `method` - method to update a finish credential for (e.g. "did:example")
    /// * `options` - JSON string with additional information supporting the request (e.g. authentication data)
    /// * `payload` - JSON string with information for the request (e.g. actual data to write)
    ///
    /// # Returns
    /// * serialized [`Credential`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/application/datatypes/struct.Credential.html) consisting of the credential
    async fn vc_zkp_finish_credential(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn std::error::Error>> {
        ignore_unrelated!(method, options);

        let payload: FinishCredentialPayload = parse!(&payload, "payload");

        let blinding: SignatureBlinding =
            SignatureBlinding::from(base64::decode(&payload.blinding)?.into_boxed_slice());
        let master_secret: SignatureMessage =
            SignatureMessage::from(base64::decode(&payload.master_secret)?.into_boxed_slice());

        let public_key: DeterministicPublicKey = get_dpk_from_string(&payload.issuer_public_key)?;

        let credential = Prover::finish_credential(
            &payload.credential,
            &master_secret,
            &payload.nquads,
            &public_key,
            &blinding,
        )?;

        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &credential,
        )?)))
    }
}
