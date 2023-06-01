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
            LdProofVcDetailOptionsCredentialStatusType,
            ProofPresentation,
            RevocationListCredential,
            SchemaProperty,
            UnfinishedBbsCredential,
            UnsignedBbsCredential,
        },
        issuer::Issuer,
        prover::Prover,
        utils::{
            concat_required_and_reveal_statements,
            convert_to_nquads,
            decode_base64,
            generate_uuid,
            get_dpk_from_string,
            get_nquads_schema_map,
        },
        verifier::Verifier,
    },
    crypto::{crypto_utils::get_public_key_from_private_key, crypto_verifier::CryptoVerifier},
    CredentialStatus,
    DraftBbsCredential,
};
use async_trait::async_trait;
use bbs::{
    keys::{DeterministicPublicKey, SecretKey},
    SignatureBlinding,
    SignatureMessage,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, error::Error};
use vade::{VadePlugin, VadePluginResultValue};
use vade_signer::Signer;

const EVAN_METHOD: &str = "did:evan";
const PROOF_METHOD_BBS: &str = "bbs";

/// Message passed to vade containing the desired credential type.
/// Does not perform action if type does not indicate credential type BBS+.
/// This can be done by passing "bbs" as the value for "type".
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypeOptions {
    pub r#type: Option<String>,
}

/// Contains information necessary to make on-chain transactions (e.g. updating a DID Document).
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationOptions {
    /// Reference to the private key, will be forwarded to external signer if available
    pub private_key: String,
    /// DID of the identity
    pub identity: String,
}

/// API payload needed to create a revocation list
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRevocationListPayload {
    /// DID of the issuer
    pub issuer_did: String,
    /// DID of the issuer's public key used to verify the credential's signature
    pub issuer_public_key_did: String,
    /// Private key of the issuer used to sign the credential
    pub issuer_proving_key: String,
    /// future did id for revocation list
    pub credential_did: String,
}

// ####### Keep until nquads are implemented in Rust #######
// #[derive(Serialize, Deserialize)]
// #[serde(rename_all = "camelCase")]
// pub struct IssueCredentialPayload {
//     pub issuer: String,
//     pub issuer_public_key_id: String,
//     pub issuer_public_key: String,
//     pub issuer_secret_key: String,
//     pub subject: String,
//     pub schema: String,
//     pub credential_request: BbsCredentialRequest,
//     pub credential_offer: BbsCredentialOffer,
//     pub required_indices: Vec<u32>,
//     pub nquads: Vec<String>,
//     pub revocation_list_did: String,
//     pub revocation_list_id: String,
// }

/// API payload for issuing a new credential
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueCredentialPayload {
    /// credential request
    pub credential_request: BbsCredentialRequest,
    /// status to be appended to credential in offer
    pub credential_status: Option<CredentialStatus>,
    /// DID url of the public key of the issuer used to later verify the signature
    pub issuer_public_key_id: String,
    /// The public bbs+ key of the issuer used to later verify the signature
    pub issuer_public_key: String,
    /// The secret bbs+ key used to create the signature
    pub issuer_secret_key: String,
}
/// API payload for creating a BbsCredentialOffer to be sent by an issuer.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OfferCredentialPayload {
    /// credential draft, outlining structure of future credential (without proof and status)
    pub draft_credential: DraftBbsCredential,
    pub credential_status_type: LdProofVcDetailOptionsCredentialStatusType,
    pub required_reveal_statements: Vec<u32>,
}

/// API payload for creating a zero-knowledge proof out of a BBS+ signature.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresentProofPayload {
    /// The proof request sent by a verifier
    pub proof_request: BbsProofRequest,
    /// All relevant credentials references via the requested credential schema ID
    pub credential_schema_map: HashMap<String, BbsCredential>,
    /// Properties to be revealed for each credential by schema ID
    pub revealed_properties_schema_map: HashMap<String, CredentialSubject>,
    /// Public key per credential by schema ID
    pub public_key_schema_map: HashMap<String, String>,
    /// Prover's master secret
    pub master_secret: String,
    /// DID of the prover
    pub prover_did: String,
    /// Key DID of the prover's public key for the created assertion proof
    pub prover_public_key_did: String,
    /// Prover's secret key to create an assertion proof with
    pub prover_proving_key: String,
}

/// API payload to create a credential proposal to be sent by a holder.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCredentialProposalPayload {
    /// DID of the issuer
    pub issuer: String,
    /// DID of a credential schema to propose
    pub schema: String,
}

/// API payload to create a credential request to be sent by a holder as a response
/// to a BbsCredentialOffer.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestCredentialPayload {
    /// offered credential
    pub credential_offer: BbsCredentialOffer,
    /// Master secret of the holder/receiver
    pub master_secret: String,
    /// Public key of the issuer
    pub issuer_pub_key: String,
    /// Credential Schema credential
    pub credential_schema: CredentialSchema,
}

/// API payload to create a BbsProofRequest to be sent by a verifier.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestProofPayload {
    /// DID of the verifier
    pub verifier_did: Option<String>,
    /// List of schema IDs to request
    pub schemas: Vec<String>,
    /// Attributes to reveal per schema ID
    pub reveal_attributes: HashMap<String, Vec<usize>>,
}

/// API payload to revoke a credential as this credential's issuer.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeCredentialPayload {
    /// DID of the issuer
    pub issuer: String,
    /// revocation list credential
    pub revocation_list: RevocationListCredential,
    /// Credential ID to revoke
    pub revocation_id: String,
    /// DID of the issuer's public key for verifying assertion proofs
    pub issuer_public_key_did: String,
    /// DID of the issuer's secret key for creating assertion proofs
    pub issuer_proving_key: String,
}

/// API payload needed to create a credential schema needed for issuing credentials
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCredentialSchemaPayload {
    /// DID of the schema issuer/owner
    pub issuer: String,
    /// Name given to the schema
    pub schema_name: String,
    /// A text describing the schema's purpose
    pub description: String,
    /// The properties the schema holds
    pub properties: HashMap<String, SchemaProperty>,
    /// Names of required properties
    pub required_properties: Vec<String>,
    /// Tells a verifier whether properties not found in the schema are to be deemed valid
    pub allow_additional_properties: bool,
    /// DID of the issuer's public key to validate the schema's assertion proof
    pub issuer_public_key_did: String,
    /// Secret key to sign the schema with
    pub issuer_proving_key: String,
    /// DID of the new created schema credential
    pub credential_did: String,
}

/// API payload for finishing a UnfinishedBbsCredential as a holder.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinishCredentialPayload {
    /// Credential with blind signature to finish
    pub credential: UnfinishedBbsCredential,
    /// Holder's master secret
    pub master_secret: String,
    /// Issuer's BBS+ public key
    pub issuer_public_key: String,
    /// Blinding created during credential request creation
    pub blinding: String,
}

/// API payload for verifying a received proof as a verifier.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyProofPayload {
    /// BBS+ Presentation to verify
    pub presentation: ProofPresentation,
    /// Proof request sent by verifier
    pub proof_request: BbsProofRequest,
    /// Relevant BBS+ public keys for each credential schema occurring in this proof
    pub keys_to_schema_map: HashMap<String, String>,
    /// Signer address
    pub signer_address: String,
    /// revocation list credential
    pub revocation_list: Option<RevocationListCredential>,
}

/// API payload to create new BBS+ keys and persist them on the DID document.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateKeysPayload {
    pub key_owner_did: String,
}

/// API payload to derive public key from base 64 encoded private key.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPublicKeyFromPrivateKeyPayload {
    pub private_key: String,
}

macro_rules! parse {
    ($data:expr, $type_name:expr) => {{
        serde_json::from_str($data)
            .map_err(|e| format!("{} when parsing {} {}", &e, $type_name, $data))?
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
}

impl VadeEvanBbs {
    /// Creates new instance of `VadeEvanBbs`.
    pub fn new(signer: Box<dyn Signer>) -> VadeEvanBbs {
        VadeEvanBbs { signer }
    }
}

impl VadeEvanBbs {
    async fn create_new_keys(
        &mut self,
        payload: CreateKeysPayload,
    ) -> Result<String, Box<dyn Error>> {
        let keys = Issuer::create_new_keys();
        let pub_key = base64::encode(keys.0.to_bytes_compressed_form());
        let secret_key = base64::encode(keys.1.to_bytes_compressed_form());

        let key_id = format!("bbs-key-{}", generate_uuid());

        let serialized_keys = format!(
            r###"{{
                "didUrl": "{}#{}",
                "publicKey": "{}",
                "secretKey": "{}"
            }}"###,
            &payload.key_owner_did, key_id, pub_key, secret_key
        );

        Ok(serialized_keys)
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
                let payload: CreateKeysPayload = parse!(&payload, "payload");
                Ok(VadePluginResultValue::Success(Some(
                    self.create_new_keys(payload).await?,
                )))
            }
            "get_public_key_from_private_key" => {
                let payload: GetPublicKeyFromPrivateKeyPayload = parse!(&payload, "payload");
                let pk_base_64 = get_public_key_from_private_key(&payload.private_key)?;
                Ok(VadePluginResultValue::Success(Some(pk_base_64)))
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
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.TypeOptions.html)
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
        let payload: CreateCredentialSchemaPayload = parse!(&payload, "payload");

        let schema = Issuer::create_credential_schema(
            &payload.credential_did,
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

        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &schema,
        )?)))
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
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.TypeOptions.html)
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
        let payload: CreateRevocationListPayload = parse!(&payload, "payload");

        let revocation_list = Issuer::create_revocation_list(
            &payload.credential_did,
            &payload.issuer_did,
            &payload.issuer_public_key_did,
            &payload.issuer_proving_key,
            &self.signer,
        )
        .await?;

        let serialized_list = serde_json::to_string(&revocation_list)?;

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
            decode_base64(
                &payload.issuer_public_key,
                "Issuer Deterministic Public Key",
            )?
            .into_boxed_slice(),
        );
        let sk: SecretKey = SecretKey::from(
            decode_base64(&payload.issuer_secret_key, "Issuer Secret Key")?.into_boxed_slice(),
        );

        let unfinished_credential = Issuer::sign_nquads(
            &payload.credential_request,
            payload.credential_status,
            &payload.issuer_public_key_id,
            &public_key,
            &sk,
        )
        .await?;

        // ######### Please keep this commented until we have an Rust nquad library #########
        // let unfinished_credential = Issuer::issue_credential(
        //     &payload.issuer,
        //     &payload.subject,
        //     &payload.credential_offer,
        //     &payload.credential_request,
        //     &payload.issuer_public_key_id,
        //     &public_key,
        //     &sk,
        //     schema,
        //     payload.required_indices,
        //     payload.nquads,
        //     &payload.revocation_list_did,
        //     &payload.revocation_list_id,
        // )?;

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
            &payload.draft_credential,
            &payload.required_reveal_statements,
            &payload.credential_status_type,
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

        let master_secret: SignatureMessage = SignatureMessage::from(
            decode_base64(&payload.master_secret, "Master Secret")?.into_boxed_slice(),
        );

        let mut public_key_schema_map: HashMap<String, DeterministicPublicKey> = HashMap::new();
        for (schema_did, base64_public_key) in payload.public_key_schema_map.iter() {
            public_key_schema_map
                .insert(schema_did.clone(), get_dpk_from_string(base64_public_key)?);
        }

        let unsigned_credentials_without_proof: Vec<UnsignedBbsCredential> = (&payload)
            .credential_schema_map
            .values()
            .into_iter()
            .map(|c| UnsignedBbsCredential::from_bbs_credential(c))
            .collect::<Result<Vec<UnsignedBbsCredential>, _>>()?;

        let nquads_schema_map = get_nquads_schema_map(
            &payload.proof_request,
            &unsigned_credentials_without_proof,
            false,
        )
        .await?;

        let result = Prover::present_proof(
            &payload.proof_request,
            &payload.credential_schema_map,
            &payload.revealed_properties_schema_map,
            &public_key_schema_map,
            &nquads_schema_map,
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
            Prover::propose_credential(&payload.issuer, &payload.schema);

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
        let master_secret: SignatureMessage = SignatureMessage::from(
            decode_base64(&payload.master_secret, "Master Secret")?.into_boxed_slice(),
        );
        let public_key: DeterministicPublicKey = DeterministicPublicKey::from(
            decode_base64(&payload.issuer_pub_key, "Issuer Deterministic Public Key")?
                .into_boxed_slice(),
        );
        let (credential_request, signature_blinding): (BbsCredentialRequest, SignatureBlinding) =
            Prover::request_credential(
                &payload.credential_offer,
                &payload.credential_schema,
                &master_secret,
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
    /// * `options` - serialized [`TypeOptions`](https://docs.rs/vade_evan_bbs/*/vade_evan_bbs/struct.TypeOptions.html)
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
        let payload: RevokeCredentialPayload = parse!(&payload, "payload");
        let updated_list = Issuer::revoke_credential(
            &payload.issuer,
            payload.revocation_list,
            &payload.revocation_id,
            &payload.issuer_public_key_did,
            &payload.issuer_proving_key,
            &self.signer,
        )
        .await?;

        let serialized = serde_json::to_string(&updated_list)?;

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
    /// * `Option<String>` - A JSON object representing a `BbsProofVerification` type, specifying whether verification was successful
    async fn vc_zkp_verify_proof(
        &mut self,
        method: &str,
        options: &str,
        payload: &str,
    ) -> Result<VadePluginResultValue<Option<String>>, Box<dyn Error>> {
        ignore_unrelated!(method, options);

        let payload: VerifyProofPayload = parse!(&payload, "payload");

        let mut proof_request = payload.proof_request.to_owned();
        for sub_request in &mut proof_request.sub_proof_requests {
            let vc = payload
                .presentation
                .verifiable_credential
                .iter()
                .find(|cred| cred.credential_schema.id == sub_request.schema)
                .ok_or_else(|| {
                    format!(
                        "Invalid Schema! No credential with schema {} found in presentation",
                        sub_request.schema
                    )
                })?;
            let required_reveal_statements = &vc.proof.required_reveal_statements;
            let revealed_statements = &sub_request.revealed_attributes;
            let all_revealed_statements = concat_required_and_reveal_statements(
                required_reveal_statements,
                revealed_statements,
            )?;
            sub_request.revealed_attributes = all_revealed_statements;
        }
        let mut public_key_schema_map: HashMap<String, DeterministicPublicKey> = HashMap::new();
        for (schema_did, base64_public_key) in payload.keys_to_schema_map.iter() {
            public_key_schema_map
                .insert(schema_did.clone(), get_dpk_from_string(base64_public_key)?);
        }

        let unsigned_credentials_without_proof: Vec<UnsignedBbsCredential> = (&payload)
            .presentation
            .verifiable_credential
            .iter()
            .map(|c| UnsignedBbsCredential::from_proof_presentation(c))
            .collect::<Result<Vec<UnsignedBbsCredential>, _>>()?;

        let nquads_schema_map =
            get_nquads_schema_map(&proof_request, &unsigned_credentials_without_proof, true)
                .await?;

        let mut verification_result = Verifier::verify_proof(
            &payload.presentation,
            &proof_request,
            &public_key_schema_map,
            &payload.signer_address,
            &nquads_schema_map,
        )?;
        if verification_result.status != "rejected" {
            // check revocation status
            let revocation_list = payload
                .revocation_list
                .ok_or_else(|| "Invalid revocation list!")?;
            for cred in &payload.presentation.verifiable_credential {
                if cred.credential_status.is_some() {
                    let credential_status = cred
                        .credential_status
                        .as_ref()
                        .ok_or_else(|| "Invalid credential status!")?;

                    let revoked = CryptoVerifier::is_revoked(&credential_status, &revocation_list)?;
                    if revoked {
                        verification_result = BbsProofVerification {
                            presented_proof: payload.presentation.id.to_string(),
                            status: "rejected".to_string(),
                            reason: Some(format!("Credential id {} is revoked", cred.id)),
                        };
                    }
                }
            }
        }

        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &verification_result,
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

        let blinding: SignatureBlinding = SignatureBlinding::from(
            decode_base64(&payload.blinding, "Signature Blinding")?.into_boxed_slice(),
        );
        let master_secret: SignatureMessage = SignatureMessage::from(
            decode_base64(&payload.master_secret, "Master Secret")?.into_boxed_slice(),
        );

        let public_key: DeterministicPublicKey = get_dpk_from_string(&payload.issuer_public_key)?;

        let unfinished_without_proof: UnsignedBbsCredential =
            serde_json::from_str(&serde_json::to_string(&payload.credential)?)?;
        let nquads = convert_to_nquads(&serde_json::to_string(&unfinished_without_proof)?).await?;

        let credential = Prover::finish_credential(
            &payload.credential,
            &master_secret,
            &nquads,
            &public_key,
            &blinding,
        )?;

        Ok(VadePluginResultValue::Success(Some(serde_json::to_string(
            &credential,
        )?)))
    }
}
