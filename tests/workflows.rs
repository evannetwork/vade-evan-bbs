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

use serde_json::Value;
use std::{collections::HashMap, env, error::Error};
use utilities::test_data::{
    accounts::local::{
        HOLDER_DID,
        ISSUER_DID,
        ISSUER_PRIVATE_KEY,
        ISSUER_PUBLIC_KEY_DID,
        SIGNER_1_ADDRESS,
        SIGNER_1_DID,
        SIGNER_1_PRIVATE_KEY,
        SIGNER_2_DID,
        SIGNER_2_PRIVATE_KEY,
        VERIFIER_DID,
    },
    bbs_coherent_context_test_data::{
        MASTER_SECRET,
        PUB_KEY,
        SECRET_KEY,
        SUBJECT_DID,
        UNSIGNED_CREDENTIAL,
    },
    did::EXAMPLE_DID_DOCUMENT_2,
    environment::DEFAULT_VADE_EVAN_SUBSTRATE_IP,
    vc_zkp::{SCHEMA_DESCRIPTION, SCHEMA_NAME, SCHEMA_PROPERTIES, SCHEMA_REQUIRED_PROPERTIES},
};
use vade::Vade;
use vade_evan_bbs::*;
use vade_evan_substrate::{
    signing::{LocalSigner, Signer},
    ResolverConfig,
    VadeEvanSubstrate,
};

const EVAN_METHOD: &str = "did:evan";
const TYPE_OPTIONS: &str = r#"{ "type": "bbs" }"#;
const SCHEMA_DID: &str =
    "did:evan:zkp:0xd641c26161e769cef4b41760211972b274a8f37f135a34083e4e48b3f1035eda";

fn get_resolver() -> VadeEvanSubstrate {
    let signer: Box<dyn Signer> = Box::new(LocalSigner::new());
    VadeEvanSubstrate::new(ResolverConfig {
        signer,
        target: env::var("VADE_EVAN_SUBSTRATE_IP")
            .unwrap_or_else(|_| DEFAULT_VADE_EVAN_SUBSTRATE_IP.to_string()),
    })
}

fn get_vade() -> Vade {
    let mut vade = Vade::new();
    vade.register_plugin(Box::from(get_vade_evan()));
    vade.register_plugin(Box::from(get_resolver()));

    vade
}

fn get_vade_evan() -> VadeEvanBbs {
    // vade to work with
    let substrate_resolver = get_resolver();
    let mut internal_vade = Vade::new();
    internal_vade.register_plugin(Box::from(substrate_resolver));

    let signer: Box<dyn Signer> = Box::new(LocalSigner::new());
    VadeEvanBbs::new(internal_vade, signer)
}

async fn _create_credential_schema(vade: &mut Vade) -> Result<CredentialSchema, Box<dyn Error>> {
    let payload = format!(
        r###"{{
        "issuer": "{}",
        "schemaName": "{}",
        "description": "{}",
        "properties": {},
        "requiredProperties": {},
        "allowAdditionalProperties": false,
        "issuerPublicKeyDid": "{}",
        "issuerProvingKey": "{}"
    }}"###,
        ISSUER_DID,
        SCHEMA_NAME,
        SCHEMA_DESCRIPTION,
        SCHEMA_PROPERTIES,
        SCHEMA_REQUIRED_PROPERTIES,
        ISSUER_PUBLIC_KEY_DID,
        ISSUER_PRIVATE_KEY
    );
    let results = vade
        .vc_zkp_create_credential_schema(EVAN_METHOD, &get_options(), &payload)
        .await?;

    // check results
    assert_eq!(results.len(), 1);

    let result: CredentialSchema = serde_json::from_str(results[0].as_ref().unwrap()).unwrap();
    Ok(result)
}

async fn create_revocation_list(
    vade: &mut Vade,
) -> Result<RevocationListCredential, Box<dyn Error>> {
    let payload = format!(
        r###"{{
        "issuerDid": "{}",
        "issuerPublicKeyDid": "{}",
        "issuerProvingKey": "{}"
    }}"###,
        ISSUER_DID, ISSUER_PUBLIC_KEY_DID, ISSUER_PRIVATE_KEY
    );
    let results = vade
        .vc_zkp_create_revocation_registry_definition(EVAN_METHOD, &get_options(), &payload)
        .await?;

    // check results
    assert_eq!(results.len(), 1);
    let result: RevocationListCredential =
        serde_json::from_str(results[0].as_ref().unwrap()).unwrap();
    Ok(result)
}

fn get_options() -> String {
    format!(
        r###"{{
            "type": "bbs",
            "privateKey": "{}",
            "identity": "{}"
        }}"###,
        SIGNER_1_PRIVATE_KEY, SIGNER_1_DID,
    )
}

async fn create_credential_proposal(vade: &mut Vade) -> Result<CredentialProposal, Box<dyn Error>> {
    let proposal_payload = CreateCredentialProposalPayload {
        issuer: ISSUER_DID.to_string(),
        subject: SUBJECT_DID.to_string(),
        schema: SCHEMA_DID.to_string(),
    };
    let proposal_payload_json = serde_json::to_string(&proposal_payload)?;
    let result = vade
        .vc_zkp_create_credential_proposal(EVAN_METHOD, TYPE_OPTIONS, &proposal_payload_json)
        .await?;
    let proposal: CredentialProposal = serde_json::from_str(&result[0].as_ref().unwrap())?;

    Ok(proposal)
}

async fn create_credential_offer(
    vade: &mut Vade,
    offer_payload: OfferCredentialPayload,
) -> Result<BbsCredentialOffer, Box<dyn Error>> {
    let offer_payload_json = serde_json::to_string(&offer_payload)?;
    let result = vade
        .vc_zkp_create_credential_offer(EVAN_METHOD, TYPE_OPTIONS, &offer_payload_json)
        .await?;

    let offering: BbsCredentialOffer = serde_json::from_str(&result[0].as_ref().unwrap())?;

    Ok(offering)
}

async fn create_credential_request(
    vade: &mut Vade,
    credential_values: HashMap<String, String>,
    offer: BbsCredentialOffer,
) -> Result<(BbsCredentialRequest, String, Vec<String>), Box<dyn Error>> {
    let mut nquads = Vec::new();
    let mut keys: Vec<String> = credential_values.keys().map(|k| k.to_string()).collect();
    keys.sort();
    for key in &keys {
        let val = credential_values.get(key).ok_or("AAA".to_owned())?;
        let string = format!("{}: {}", key, val);
        nquads.insert(nquads.len(), string);
    }

    let request = RequestCredentialPayload {
        credential_offering: offer,
        master_secret: MASTER_SECRET.to_string(),
        credential_values: credential_values.clone(),
        issuer_pub_key: PUB_KEY.to_string(),
    };

    let request_json = serde_json::to_string(&request)?;
    let result = vade
        .vc_zkp_request_credential(EVAN_METHOD, TYPE_OPTIONS, &request_json)
        .await?;

    let (credential_request, signature_blinding_base64): (BbsCredentialRequest, String) =
        serde_json::from_str(&result[0].as_ref().unwrap())?;

    Ok((credential_request, signature_blinding_base64, nquads))
}

async fn create_unfinished_credential(
    vade: &mut Vade,
    credential_request: BbsCredentialRequest,
    revocation_list_did: String,
    revocation_list_id: String,
    nquads: Vec<String>,
    offer: BbsCredentialOffer,
) -> Result<UnfinishedBbsCredential, Box<dyn Error>> {
    let key_id = format!("{}#key-1", ISSUER_DID);
    let unsigned_vc = get_unsigned_vc(
        revocation_list_did,
        revocation_list_id,
        credential_request.credential_values.clone(),
    )?;
    let issue_cred = IssueCredentialPayload {
        unsigned_vc,
        issuer_public_key_id: key_id.clone(),
        issuer_public_key: PUB_KEY.to_string(),
        issuer_secret_key: SECRET_KEY.to_string(),
        credential_request: credential_request.clone(),
        credential_offer: offer,
        required_indices: [1].to_vec(),
        nquads: nquads.clone(),
    };
    let issue_cred_json = serde_json::to_string(&issue_cred)?;

    let result = vade
        .vc_zkp_issue_credential(EVAN_METHOD, TYPE_OPTIONS, &issue_cred_json)
        .await?;

    let unfinished_credential: UnfinishedBbsCredential =
        serde_json::from_str(&result[0].as_ref().unwrap())?;

    Ok(unfinished_credential)
}

async fn create_finished_credential(
    vade: &mut Vade,
    unfinished_credential: UnfinishedBbsCredential,
    signature_blinding_base64: String,
    nquads: Vec<String>,
) -> Result<BbsCredential, Box<dyn Error>> {
    let finish_request = FinishCredentialPayload {
        credential: unfinished_credential,
        master_secret: MASTER_SECRET.to_string(),
        nquads,
        issuer_public_key: PUB_KEY.to_string(),
        blinding: signature_blinding_base64,
    };

    let finish_request_json = serde_json::to_string(&finish_request)?;
    let result = vade
        .vc_zkp_finish_credential(EVAN_METHOD, TYPE_OPTIONS, &finish_request_json)
        .await?;

    let finished_credential: BbsCredential = serde_json::from_str(&result[0].as_ref().unwrap())?;

    Ok(finished_credential)
}

async fn create_proof_request(vade: &mut Vade) -> Result<BbsProofRequest, Box<dyn Error>> {
    let mut reveal_attributes = HashMap::new();
    reveal_attributes.insert(SCHEMA_DID.clone().to_string(), vec![1]);
    let proof_request_payload = RequestProofPayload {
        verifier_did: VERIFIER_DID.to_string(),
        schemas: vec![SCHEMA_DID.to_string()],
        reveal_attributes,
    };
    let proof_request_json = serde_json::to_string(&proof_request_payload)?;
    let result = vade
        .vc_zkp_request_proof(EVAN_METHOD, TYPE_OPTIONS, &proof_request_json)
        .await?;
    let proof_request: BbsProofRequest = serde_json::from_str(&result[0].as_ref().unwrap())?;

    Ok(proof_request)
}

async fn revoke_credential(
    vade: &mut Vade,
    revocation_list_did: String,
    revocation_list_id: String,
) -> Result<(), Box<dyn Error>> {
    let revoke_credential_payload = RevokeCredentialPayload {
        issuer: ISSUER_DID.to_string(),
        revocation_list: revocation_list_did,
        revocation_id: revocation_list_id.to_string(),
        issuer_public_key_did: ISSUER_PUBLIC_KEY_DID.to_string(),
        issuer_proving_key: ISSUER_PRIVATE_KEY.to_string(),
    };
    let revoke_credential_json = serde_json::to_string(&revoke_credential_payload)?;
    vade.vc_zkp_revoke_credential(EVAN_METHOD, &get_options(), &revoke_credential_json)
        .await?;
    Ok(())
}

async fn create_presentation(
    vade: &mut Vade,
    finished_credential: BbsCredential,
    proof_request: BbsProofRequest,
    public_key_schema_map: HashMap<String, String>,
    nquads: Vec<String>,
) -> Result<ProofPresentation, Box<dyn Error>> {
    let mut credential_schema_map = HashMap::new();
    credential_schema_map.insert(SCHEMA_DID.to_string(), finished_credential.clone());

    let revealed_data = finished_credential.credential_subject.data.clone();
    let mut revealed_properties_schema_map = HashMap::new();
    let revealed = CredentialSubject {
        id: HOLDER_DID.to_string(),
        data: revealed_data,
    };
    revealed_properties_schema_map.insert(SCHEMA_DID.to_string(), revealed);

    let mut nquads_schema_map = HashMap::new();
    nquads_schema_map.insert(SCHEMA_DID.to_string(), nquads);

    let present_proof_payload = PresentProofPayload {
        proof_request: proof_request.clone(),
        credential_schema_map,
        public_key_schema_map: public_key_schema_map.clone(),
        revealed_properties_schema_map,
        nquads_schema_map,
        master_secret: MASTER_SECRET.to_string(),
        prover_did: VERIFIER_DID.to_string(),
        prover_public_key_did: format!("{}#key-1", VERIFIER_DID),
        prover_proving_key: SIGNER_1_PRIVATE_KEY.to_string(),
    };

    let present_proof_json = serde_json::to_string(&present_proof_payload)?;
    let result = vade
        .vc_zkp_present_proof(EVAN_METHOD, TYPE_OPTIONS, &present_proof_json)
        .await?;
    let presentation: ProofPresentation = serde_json::from_str(&result[0].as_ref().unwrap())?;

    Ok(presentation)
}

async fn ensure_whitelist(vade: &mut Vade, signer: &str) -> Result<(), Box<dyn Error>> {
    let auth_string = format!(
        r###"{{
            "privateKey": "{}",
            "identity": "{}"
        }}"###,
        SIGNER_2_PRIVATE_KEY, SIGNER_2_DID,
    );
    let mut json_editable: Value = serde_json::from_str(&auth_string)?;
    json_editable["operation"] = Value::from("ensureWhitelisted");
    let options = serde_json::to_string(&json_editable)?;

    let result = vade.did_update(signer, &options, &"".to_string()).await;

    match result {
        Ok(values) => assert!(!values.is_empty()),
        Err(e) => panic!("could not whitelist identity; {}", &e),
    };

    let resolver = get_resolver();

    assert_eq!(
        true,
        resolver
            .is_whitelisted(&SIGNER_2_DID, &SIGNER_2_PRIVATE_KEY)
            .await?
    );

    Ok(())
}

fn get_unsigned_vc(
    revocation_list_did: String,
    revocation_list_id: String,
    credential_values: HashMap<String, String>,
) -> Result<UnsignedBbsCredential, Box<dyn Error>> {
    let mut unsigned_vc: UnsignedBbsCredential = serde_json::from_str(UNSIGNED_CREDENTIAL)?;
    unsigned_vc.credential_status.revocation_list_index = revocation_list_id.clone();
    unsigned_vc.credential_status.revocation_list_credential = revocation_list_did.clone();
    unsigned_vc.credential_status.id = format!("{}#{}", revocation_list_did, revocation_list_id);
    unsigned_vc.credential_subject.data = credential_values;

    return Ok(unsigned_vc);
}

#[tokio::test]
async fn workflow_can_create_credential_proposal() -> Result<(), Box<dyn Error>> {
    let mut vade = get_vade();

    let proposal = create_credential_proposal(&mut vade).await?;

    assert_eq!(&proposal.subject, &SUBJECT_DID);
    assert_eq!(&proposal.issuer, &ISSUER_DID);
    assert_eq!(&proposal.schema, &SCHEMA_DID.clone());
    assert_eq!(&proposal.r#type, CREDENTIAL_PROPOSAL_TYPE);

    Ok(())
}

#[tokio::test]
async fn workflow_can_create_credential_offer_with_proposal() -> Result<(), Box<dyn Error>> {
    let mut vade = get_vade();

    let proposal = create_credential_proposal(&mut vade).await?;

    // Create credential offering
    let offer_payload = OfferCredentialPayload {
        issuer: ISSUER_DID.to_string(),
        credential_proposal: proposal.clone(),
        nquad_count: 3, /* Arbitrary, not needed here */
    };

    let offering = create_credential_offer(&mut vade, offer_payload).await?;
    assert_eq!(&offering.issuer, &ISSUER_DID);
    assert_eq!(&offering.schema, &proposal.schema);
    assert_eq!(&offering.subject, &proposal.subject);
    assert_eq!(&offering.r#type, &CREDENTIAL_OFFER_TYPE);

    Ok(())
}

#[tokio::test]
async fn workflow_cannot_create_credential_offer_with_different_issuer(
) -> Result<(), Box<dyn Error>> {
    let mut vade = get_vade();
    let proposal = create_credential_proposal(&mut vade).await?;

    // Create credential offering
    let offer_payload = OfferCredentialPayload {
        issuer: SUBJECT_DID.to_string(),
        credential_proposal: proposal.clone(),
        nquad_count: 3, /* Arbitrary, not needed here */
    };

    let err_result = create_credential_offer(&mut vade, offer_payload)
        .await
        .map_err(|e| format!("{}", e))
        .err();

    assert_eq!(
        err_result,
        Some(
            "could not run vc_zkp_create_credential_offer for \"did:evan\"; Cannot offer credential: Proposal is not targeted at this issuer".to_string()
        )
    );

    Ok(())
}

#[tokio::test]
async fn workflow_can_create_credential_request() -> Result<(), Box<dyn Error>> {
    let mut vade = get_vade();

    let proposal = create_credential_proposal(&mut vade).await?;

    // Create credential offering
    let offer_payload = OfferCredentialPayload {
        issuer: ISSUER_DID.to_string(),
        credential_proposal: proposal.clone(),
        nquad_count: 3, /* Arbitrary, not needed here */
    };

    let offer = create_credential_offer(&mut vade, offer_payload).await?;

    // Create credential request
    let mut credential_values = HashMap::new();
    credential_values.insert("test_property_string".to_owned(), "value".to_owned());

    let (credential_request, _, _) =
        create_credential_request(&mut vade, credential_values, offer.clone()).await?;

    assert_eq!(credential_request.schema, SCHEMA_DID);
    assert_eq!(credential_request.subject, offer.subject);
    assert_eq!(credential_request.r#type, CREDENTIAL_REQUEST_TYPE);

    Ok(())
}

#[tokio::test]
async fn workflow_cannot_create_credential_request_with_missing_required_schema_property(
) -> Result<(), Box<dyn Error>> {
    let mut vade = get_vade();

    let proposal = create_credential_proposal(&mut vade).await?;

    // Create credential offering
    let offer_payload = OfferCredentialPayload {
        issuer: ISSUER_DID.to_string(),
        credential_proposal: proposal.clone(),
        nquad_count: 3, /* Arbitrary, not needed here */
    };

    let offer = create_credential_offer(&mut vade, offer_payload).await?;

    // Create credential request
    let mut credential_values = HashMap::new();
    credential_values.insert("not_required_property".to_owned(), "value".to_owned());

    let err_result = create_credential_request(&mut vade, credential_values, offer)
        .await
        .map_err(|e| format!("{}", e))
        .err();

    assert_eq!(
        err_result,
        Some(
            "could not run vc_zkp_request_credential for \"did:evan\"; Cannot request credential: Missing required schema property: test_property_string"
                .to_string()
        )
    );

    Ok(())
}

#[tokio::test]
async fn workflow_cannot_create_credential_request_with_empty_values() -> Result<(), Box<dyn Error>>
{
    let mut vade = get_vade();

    let proposal = create_credential_proposal(&mut vade).await?;

    // Create credential offering
    let offer_payload = OfferCredentialPayload {
        issuer: ISSUER_DID.to_string(),
        credential_proposal: proposal.clone(),
        nquad_count: 3, /* Arbitrary, not needed here */
    };

    let offer = create_credential_offer(&mut vade, offer_payload).await?;

    // Create credential request
    let credential_values = HashMap::new();

    let err_result = create_credential_request(&mut vade, credential_values, offer)
        .await
        .map_err(|e| format!("{}", e))
        .err();

    assert_eq!(
        err_result,
        Some(
            "could not run vc_zkp_request_credential for \"did:evan\"; Cannot create blind signature context. Provided no credential values"
                .to_string()
        )
    );

    Ok(())
}

#[tokio::test]
async fn workflow_can_create_unfinished_credential() -> Result<(), Box<dyn Error>> {
    let mut vade = get_vade();

    let proposal = create_credential_proposal(&mut vade).await?;

    // Create credential offering
    let offer_payload = OfferCredentialPayload {
        issuer: ISSUER_DID.to_string(),
        credential_proposal: proposal.clone(),
        nquad_count: 1,
    };

    let offer = create_credential_offer(&mut vade, offer_payload).await?;

    // Create credential request
    let mut credential_values = HashMap::new();
    credential_values.insert("test_property_string".to_owned(), "value".to_owned());

    let (credential_request, _, _) =
        create_credential_request(&mut vade, credential_values, offer.clone()).await?;

    assert_eq!(credential_request.schema, SCHEMA_DID);
    assert_eq!(credential_request.subject, offer.subject);
    assert_eq!(credential_request.r#type, CREDENTIAL_REQUEST_TYPE);

    Ok(())
}

#[tokio::test]
async fn workflow_can_create_finished_credential() -> Result<(), Box<dyn Error>> {
    let mut vade = get_vade();

    let revocation_list = create_revocation_list(&mut vade).await?;

    let proposal = create_credential_proposal(&mut vade).await?;

    let mut credential_values = HashMap::new();
    credential_values.insert("test_property_string".to_owned(), "value".to_owned());

    let offer_payload = OfferCredentialPayload {
        issuer: ISSUER_DID.to_string(),
        credential_proposal: proposal.clone(),
        nquad_count: credential_values.len(),
    };

    let offer = create_credential_offer(&mut vade, offer_payload).await?;

    let (credential_request, signature_blinding_base64, nquads) =
        create_credential_request(&mut vade, credential_values, offer.clone()).await?;

    let unfinished_credential = create_unfinished_credential(
        &mut vade,
        credential_request.clone(),
        revocation_list.id,
        "0".to_string(),
        nquads.clone(),
        offer,
    )
    .await?;

    let key_id = format!("{}#key-1", ISSUER_DID);
    let finished_credential = create_finished_credential(
        &mut vade,
        unfinished_credential,
        signature_blinding_base64,
        nquads,
    )
    .await?;

    assert_eq!(&finished_credential.issuer, ISSUER_DID);
    assert_eq!(&finished_credential.credential_subject.id, SUBJECT_DID);
    assert_eq!(&finished_credential.credential_schema.id, &SCHEMA_DID);
    assert_eq!(
        &finished_credential.proof.required_reveal_statements,
        &[1].to_vec()
    );
    assert_eq!(&finished_credential.proof.r#type, CREDENTIAL_SIGNATURE_TYPE);
    assert_eq!(
        &finished_credential.proof.proof_purpose,
        CREDENTIAL_PROOF_PURPOSE
    );
    assert_eq!(&finished_credential.proof.verification_method, &key_id);
    assert!(&finished_credential
        .credential_subject
        .data
        .keys()
        .all(|key| credential_request.credential_values.contains_key(key)
            && credential_request.credential_values.get(key)
                == finished_credential.credential_subject.data.get(key)));

    assert!(base64::decode(&finished_credential.proof.signature).is_ok());

    Ok(())
}

#[tokio::test]
async fn workflow_can_propose_request_issue_verify_a_credential() -> Result<(), Box<dyn Error>> {
    let mut vade = get_vade();

    let revocation_list = create_revocation_list(&mut vade).await?;

    let proposal = create_credential_proposal(&mut vade).await?;

    let mut credential_values = HashMap::new();
    credential_values.insert("test_property_string".to_owned(), "value".to_owned());
    credential_values.insert("test_property_string1".to_owned(), "value".to_owned());
    credential_values.insert("test_property_string2".to_owned(), "value".to_owned());
    credential_values.insert("test_property_string3".to_owned(), "value".to_owned());
    credential_values.insert("test_property_string4".to_owned(), "value".to_owned());

    // Create credential offering
    let offer_payload = OfferCredentialPayload {
        issuer: ISSUER_DID.to_string(),
        credential_proposal: proposal.clone(),
        nquad_count: credential_values.len(),
    };

    let offer = create_credential_offer(&mut vade, offer_payload).await?;

    let (credential_request, signature_blinding_base64, nquads) =
        create_credential_request(&mut vade, credential_values, offer.clone()).await?;

    let unfinished_credential = create_unfinished_credential(
        &mut vade,
        credential_request,
        revocation_list.id,
        "0".to_string(),
        nquads.clone(),
        offer,
    )
    .await?;

    let finished_credential = create_finished_credential(
        &mut vade,
        unfinished_credential.clone(),
        signature_blinding_base64.clone(),
        nquads.clone(),
    )
    .await?;

    // create proof request
    let mut proof_request = create_proof_request(&mut vade).await?;
    proof_request.sub_proof_requests[0].revealed_attributes = vec![1, 3];

    // create proof
    let mut public_key_schema_map = HashMap::new();
    public_key_schema_map.insert(SCHEMA_DID.to_string(), PUB_KEY.to_string());
    let presentation = create_presentation(
        &mut vade,
        finished_credential.clone(),
        proof_request.clone(),
        public_key_schema_map.clone(),
        nquads,
    )
    .await?;

    let mut nqsm: HashMap<String, Vec<String>> = HashMap::new();
    nqsm.insert(
        SCHEMA_DID.to_string(),
        vec![
            "test_property_string: value".to_string(),
            "test_property_string2: value".to_string(),
        ],
    );

    // verify proof
    let verify_proof_payload = VerifyProofPayload {
        presentation: presentation.clone(),
        proof_request: proof_request.clone(),
        keys_to_schema_map: public_key_schema_map,
        signer_address: SIGNER_1_ADDRESS.to_string(),
        nquads_to_schema_map: nqsm,
    };
    let verify_proof_json = serde_json::to_string(&verify_proof_payload)?;
    vade.vc_zkp_verify_proof(EVAN_METHOD, TYPE_OPTIONS, &verify_proof_json)
        .await?;

    Ok(())
}

#[tokio::test]
async fn workflow_cannot_verify_revoked_credential() -> Result<(), Box<dyn Error>> {
    let mut vade = get_vade();

    let revocation_list = create_revocation_list(&mut vade).await?;

    let proposal = create_credential_proposal(&mut vade).await?;

    let mut credential_values = HashMap::new();
    credential_values.insert("test_property_string".to_owned(), "value".to_owned());

    // Create credential offering
    let offer_payload = OfferCredentialPayload {
        issuer: ISSUER_DID.to_string(),
        credential_proposal: proposal.clone(),
        nquad_count: credential_values.len(),
    };

    let offer = create_credential_offer(&mut vade, offer_payload).await?;

    let (credential_request, signature_blinding_base64, nquads) =
        create_credential_request(&mut vade, credential_values, offer.clone()).await?;

    let unfinished_credential = create_unfinished_credential(
        &mut vade,
        credential_request,
        revocation_list.id.clone(),
        "0".to_string(),
        nquads.clone(),
        offer,
    )
    .await?;

    let finished_credential = create_finished_credential(
        &mut vade,
        unfinished_credential,
        signature_blinding_base64,
        nquads.clone(),
    )
    .await?;

    // revoke credential
    revoke_credential(&mut vade, revocation_list.id, "0".to_string()).await?;

    // create proof request
    let proof_request = create_proof_request(&mut vade).await?;

    // create proof
    let mut public_key_schema_map = HashMap::new();
    public_key_schema_map.insert(SCHEMA_DID.to_string(), PUB_KEY.to_string());
    let presentation = create_presentation(
        &mut vade,
        finished_credential.clone(),
        proof_request.clone(),
        public_key_schema_map.clone(),
        nquads,
    )
    .await?;

    let mut nqsm: HashMap<String, Vec<String>> = HashMap::new();
    nqsm.insert(
        SCHEMA_DID.to_string(),
        vec!["test_property_string: value".to_string()],
    );
    // verify proof
    let presentation_id = &presentation.id.to_owned();
    let verify_proof_payload = VerifyProofPayload {
        presentation,
        proof_request,
        keys_to_schema_map: public_key_schema_map,
        signer_address: SIGNER_1_ADDRESS.to_string(),
        nquads_to_schema_map: nqsm,
    };
    let verify_proof_json = serde_json::to_string(&verify_proof_payload)?;
    let results = vade
        .vc_zkp_verify_proof(EVAN_METHOD, TYPE_OPTIONS, &verify_proof_json)
        .await?;

    let result: BbsProofVerification =
        serde_json::from_str(&results[0].as_ref().ok_or("could not get result")?)?;

    assert_eq!(&result.presented_proof, presentation_id);
    assert_eq!(&result.status, &"rejected".to_string());
    assert_eq!(
        result
            .reason
            .or_else(|| Some("no reason provided".to_string())),
        Some(format!(
            "Credential id {} is revoked",
            finished_credential.id
        ))
    );
    Ok(())
}

async fn whitelist_and_create_did_doc_for_signer_2(
    mut vade: &mut Vade,
) -> Result<(), Box<dyn Error>> {
    ensure_whitelist(&mut vade, &SIGNER_2_DID).await?;

    // Set example did document to make sure it resolves
    let auth_string = format!(
        r###"{{
            "privateKey": "{}",
            "identity": "{}"
        }}"###,
        SIGNER_2_PRIVATE_KEY, SIGNER_2_DID,
    );
    let mut json_editable: Value = serde_json::from_str(&auth_string)?;
    json_editable["operation"] = Value::from("setDidDocument");

    vade.did_update(
        &SIGNER_2_DID,
        &serde_json::to_string(&json_editable)?,
        &EXAMPLE_DID_DOCUMENT_2,
    )
    .await?;

    Ok(())
}

#[tokio::test]
async fn workflow_can_create_and_persist_keys() -> Result<(), Box<dyn Error>> {
    let mut vade = get_vade();

    whitelist_and_create_did_doc_for_signer_2(&mut vade).await?;

    let options = format!(
        r#"{{
            "identity": "{}",
            "privateKey": "{}",
            "type": "bbs"
        }}"#,
        &SIGNER_2_DID, &SIGNER_2_PRIVATE_KEY
    );

    let payload = format!(
        r#"{{
            "keyOwnerDid": "{}"
        }}"#,
        &SIGNER_2_DID
    );

    let result = vade
        .run_custom_function(EVAN_METHOD, "create_new_keys", &options, &payload)
        .await?;

    // Get values from plugin result
    let created_keys: Value = serde_json::from_str(
        &result[0]
            .as_ref()
            .ok_or("Unexpected empty vector from create_new_keys")?,
    )?;
    let created_key_id = created_keys["didUrl"]
        .as_str()
        .ok_or("Expected key id field to be a string")?;
    let created_pub_key_b64 = created_keys["publicKey"]
        .as_str()
        .ok_or("Expected publicKey field to be a string")?;
    let created_pub_key_raw = base64::decode(created_pub_key_b64)?;

    // Resolve the (hopefully) updated did document
    let resolve_result = vade.did_resolve(&SIGNER_2_DID).await?[0].clone();
    let updated_doc: Value =
        serde_json::from_str(&resolve_result.ok_or("Return value was empty")?)?;
    let assertion_methods = updated_doc["assertionMethod"]
        .as_array()
        .ok_or("Expected an array for assertionMethod")?;
    assert_eq!(1, assertion_methods.len());

    let newly_added: Value = assertion_methods[0].clone();
    let resolved_key_id = newly_added["id"]
        .as_str()
        .ok_or("Expected key id field to be a string")?;
    let resolved_pub_key_raw = bs58::decode(
        newly_added["publicKeyBase58"]
            .as_str()
            .ok_or("Expected publicKeyBase58 field to be a string")?,
    )
    .into_vec()?;

    // Test
    assert!(resolved_key_id.starts_with(&format!("{}#bbs-key-", &SIGNER_2_DID)));
    assert_eq!(resolved_key_id, created_key_id);
    assert_eq!(created_pub_key_raw, resolved_pub_key_raw);

    Ok(())
}
