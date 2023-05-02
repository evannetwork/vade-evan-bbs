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

use std::{collections::HashMap, error::Error};
use utilities::test_data::{
    accounts::local::{
        ISSUER_DID,
        ISSUER_PRIVATE_KEY,
        ISSUER_PUBLIC_KEY_DID,
        SIGNER_1_ADDRESS,
        SIGNER_1_DID,
        SIGNER_1_PRIVATE_KEY,
        VERIFIER_DID,
    },
    bbs_coherent_context_test_data::{MASTER_SECRET, PUB_KEY, SCHEMA, SCHEMA_DID, SECRET_KEY},
};
use vade::Vade;
use vade_evan_bbs::*;
use vade_signer::{LocalSigner, Signer};

const EVAN_METHOD: &str = "did:evan";
const TYPE_OPTIONS: &str = r#"{ "type": "bbs" }"#;

fn get_vade() -> Vade {
    let mut vade = Vade::new();
    vade.register_plugin(Box::from(get_vade_evan_bbs()));

    vade
}

fn get_vade_evan_bbs() -> VadeEvanBbs {
    let signer: Box<dyn Signer> = Box::new(LocalSigner::new());
    VadeEvanBbs::new(signer)
}

async fn create_revocation_list(
    vade: &mut Vade,
) -> Result<RevocationListCredential, Box<dyn Error>> {
    let payload = format!(
        r###"{{
        "issuerDid": "{}",
        "issuerPublicKeyDid": "{}",
        "issuerProvingKey": "{}",
        "credentialDid": "did:evan:revocation123"
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
    offer: BbsCredentialOffer,
) -> Result<(BbsCredentialRequest, String), Box<dyn Error>> {
    let mut nquads = Vec::new();
    let credential_values = &offer.ld_proof_vc_detail.credential.credential_subject.data;
    let mut keys: Vec<String> = credential_values.keys().map(|k| k.to_string()).collect();
    keys.sort();
    for key in &keys {
        let val = credential_values.get(key).ok_or("AAA".to_owned())?;
        let string = format!("{}: {}", key, val);
        nquads.insert(nquads.len(), string);
    }
    let credential_schema: CredentialSchema = serde_json::from_str(&SCHEMA)?;
    let request = RequestCredentialPayload {
        credential_offer: offer,
        master_secret: MASTER_SECRET.to_string(),
        issuer_pub_key: PUB_KEY.to_string(),
        credential_schema,
    };

    let request_json = serde_json::to_string(&request)?;
    let result = vade
        .vc_zkp_request_credential(EVAN_METHOD, TYPE_OPTIONS, &request_json)
        .await?;

    let (credential_request, signature_blinding_base64): (BbsCredentialRequest, String) =
        serde_json::from_str(&result[0].as_ref().unwrap())?;

    Ok((credential_request, signature_blinding_base64))
}

async fn create_unfinished_credential(
    vade: &mut Vade,
    credential_request: BbsCredentialRequest,
    revocation_list_did: String,
    revocation_list_id: String,
) -> Result<UnfinishedBbsCredential, Box<dyn Error>> {
    let key_id = format!("{}#bbs-key-1", ISSUER_DID);
    let issue_cred = IssueCredentialPayload {
        credential_request: credential_request.clone(),
        credential_status: Some(get_credential_status(
            revocation_list_did,
            revocation_list_id,
        )),
        issuer_public_key_id: key_id.clone(),
        issuer_public_key: PUB_KEY.to_string(),
        issuer_secret_key: SECRET_KEY.to_string(),
        required_indices: [1].to_vec(),
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
) -> Result<BbsCredential, Box<dyn Error>> {
    let finish_request = FinishCredentialPayload {
        credential: unfinished_credential,
        master_secret: MASTER_SECRET.to_string(),
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
        verifier_did: Some(VERIFIER_DID.to_string()),
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
    revocation_list: RevocationListCredential,
    revocation_list_id: String,
) -> Result<RevocationListCredential, Box<dyn Error>> {
    let revoke_credential_payload = RevokeCredentialPayload {
        issuer: ISSUER_DID.to_string(),
        revocation_list: revocation_list,
        revocation_id: revocation_list_id.to_string(),
        issuer_public_key_did: ISSUER_PUBLIC_KEY_DID.to_string(),
        issuer_proving_key: ISSUER_PRIVATE_KEY.to_string(),
    };
    let revoke_credential_json = serde_json::to_string(&revoke_credential_payload)?;
    let updated_revocation_result = vade
        .vc_zkp_revoke_credential(EVAN_METHOD, &get_options(), &revoke_credential_json)
        .await?[0]
        .clone();
    Ok(serde_json::from_str(
        &updated_revocation_result.ok_or("Return value was empty")?,
    )?)
}

async fn create_presentation(
    vade: &mut Vade,
    finished_credential: BbsCredential,
    proof_request: BbsProofRequest,
    public_key_schema_map: HashMap<String, String>,
) -> Result<ProofPresentation, Box<dyn Error>> {
    let mut credential_schema_map = HashMap::new();
    credential_schema_map.insert(SCHEMA_DID.to_string(), finished_credential.clone());

    let revealed_data = finished_credential.credential_subject.data.clone();
    let mut revealed_properties_schema_map = HashMap::new();
    let revealed = CredentialSubject {
        data: revealed_data,
    };
    revealed_properties_schema_map.insert(SCHEMA_DID.to_string(), revealed);

    let present_proof_payload = PresentProofPayload {
        proof_request: proof_request.clone(),
        credential_schema_map,
        public_key_schema_map: public_key_schema_map.clone(),
        revealed_properties_schema_map,
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

fn get_credential_status(
    revocation_list_did: String,
    revocation_list_id: String,
) -> CredentialStatus {
    CredentialStatus {
        id: format!("{}#{}", revocation_list_did, revocation_list_id),
        r#type: "RevocationList2021Status".to_string(),
        revocation_list_index: revocation_list_id.clone(),
        revocation_list_credential: revocation_list_did.clone(),
    }
}

#[tokio::test]
async fn workflow_can_create_credential_proposal() -> Result<(), Box<dyn Error>> {
    let mut vade = get_vade();

    let proposal = create_credential_proposal(&mut vade).await?;

    assert_eq!(&proposal.issuer, &ISSUER_DID);
    assert_eq!(&proposal.schema, &SCHEMA_DID.clone());

    Ok(())
}

#[tokio::test]
async fn workflow_can_create_credential_offer_with_proposal() -> Result<(), Box<dyn Error>> {
    let mut vade = get_vade();

    // Create credential offering
    let schema = CredentialSchema::from_str(SCHEMA)?;
    let offer_payload = OfferCredentialPayload {
        draft_credential: schema.to_draft_credential(CredentialDraftOptions {
            issuer_did: ISSUER_DID.to_string(),
            id: None,
            issuance_date: None,
            valid_until: None,
        }),
    };

    let offering = create_credential_offer(&mut vade, offer_payload).await?;
    assert_eq!(&offering.ld_proof_vc_detail.credential.issuer, &ISSUER_DID);

    Ok(())
}

#[tokio::test]
async fn workflow_can_create_credential_request() -> Result<(), Box<dyn Error>> {
    let mut vade = get_vade();

    // Create credential offering
    let schema = CredentialSchema::from_str(SCHEMA)?;
    let offer_payload = OfferCredentialPayload {
        draft_credential: schema.to_draft_credential(CredentialDraftOptions {
            issuer_did: ISSUER_DID.to_string(),
            id: None,
            issuance_date: None,
            valid_until: None,
        }),
    };

    let offer = create_credential_offer(&mut vade, offer_payload).await?;

    let (credential_request, _) = create_credential_request(&mut vade, offer.clone()).await?;

    assert_eq!(
        credential_request
            .credential_offer
            .ld_proof_vc_detail
            .credential
            .credential_schema
            .id,
        SCHEMA_DID
    );

    Ok(())
}

#[tokio::test]
async fn workflow_cannot_create_credential_request_with_missing_required_schema_property(
) -> Result<(), Box<dyn Error>> {
    let mut vade = get_vade();

    // Create credential offering
    let schema = CredentialSchema::from_str(SCHEMA)?;
    let offer_payload = OfferCredentialPayload {
        draft_credential: schema.to_draft_credential(CredentialDraftOptions {
            issuer_did: ISSUER_DID.to_string(),
            id: None,
            issuance_date: None,
            valid_until: None,
        }),
    };

    let mut offer = create_credential_offer(&mut vade, offer_payload).await?;
    let credential_values = &mut offer.ld_proof_vc_detail.credential.credential_subject.data;
    credential_values.clear();
    credential_values.insert("not_required_property".to_owned(), "value".to_owned());

    let err_result = create_credential_request(&mut vade, offer)
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

    // Create credential offering
    let schema = CredentialSchema::from_str(SCHEMA)?;
    let offer_payload = OfferCredentialPayload {
        draft_credential: schema.to_draft_credential(CredentialDraftOptions {
            issuer_did: ISSUER_DID.to_string(),
            id: None,
            issuance_date: None,
            valid_until: None,
        }),
    };

    let mut offer = create_credential_offer(&mut vade, offer_payload).await?;
    offer
        .ld_proof_vc_detail
        .credential
        .credential_subject
        .data
        .clear();

    let err_result = create_credential_request(&mut vade, offer)
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

    // Create credential offering
    let schema = CredentialSchema::from_str(SCHEMA)?;
    let offer_payload = OfferCredentialPayload {
        draft_credential: schema.to_draft_credential(CredentialDraftOptions {
            issuer_did: ISSUER_DID.to_string(),
            id: None,
            issuance_date: None,
            valid_until: None,
        }),
    };

    let offer = create_credential_offer(&mut vade, offer_payload).await?;

    let (credential_request, _) = create_credential_request(&mut vade, offer.clone()).await?;

    assert_eq!(
        credential_request
            .credential_offer
            .ld_proof_vc_detail
            .credential
            .credential_schema
            .id,
        SCHEMA_DID
    );

    Ok(())
}

#[tokio::test]
async fn workflow_can_create_finished_credential() -> Result<(), Box<dyn Error>> {
    let mut vade = get_vade();

    let revocation_list = create_revocation_list(&mut vade).await?;

    let mut credential_values = HashMap::new();
    credential_values.insert("test_property_string".to_owned(), "value".to_owned());

    let schema = CredentialSchema::from_str(SCHEMA)?;
    let mut credential_draft = schema.to_draft_credential(CredentialDraftOptions {
        issuer_did: ISSUER_DID.to_string(),
        id: None,
        issuance_date: None,
        valid_until: None,
    });
    credential_draft.credential_subject.data = credential_values;

    let offer_payload = OfferCredentialPayload {
        draft_credential: credential_draft,
    };

    let offer = create_credential_offer(&mut vade, offer_payload).await?;

    let (credential_request, signature_blinding_base64) =
        create_credential_request(&mut vade, offer.clone()).await?;

    let unfinished_credential = create_unfinished_credential(
        &mut vade,
        credential_request.clone(),
        revocation_list.id,
        "0".to_string(),
    )
    .await?;

    let key_id = format!("{}#bbs-key-1", ISSUER_DID);
    let finished_credential =
        create_finished_credential(&mut vade, unfinished_credential, signature_blinding_base64)
            .await?;

    assert_eq!(&finished_credential.issuer, ISSUER_DID);

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
                == finished_credential.credential_subject.data.get(key)));

    assert!(base64::decode(&finished_credential.proof.signature).is_ok());

    Ok(())
}

#[tokio::test]
async fn workflow_can_create_finished_credential_without_credential_status(
) -> Result<(), Box<dyn Error>> {
    let mut vade = get_vade();

    let revocation_list = create_revocation_list(&mut vade).await?;
    let mut credential_values = HashMap::new();
    credential_values.insert("test_property_string".to_owned(), "value".to_owned());
    let schema = CredentialSchema::from_str(SCHEMA)?;
    let draft_credential = schema.to_draft_credential(CredentialDraftOptions {
        issuer_did: ISSUER_DID.to_string(),
        id: None,
        issuance_date: None,
        valid_until: None,
    });

    let offer_payload = OfferCredentialPayload { draft_credential };

    let offer = create_credential_offer(&mut vade, offer_payload).await?;

    let (credential_request, signature_blinding_base64) =
        create_credential_request(&mut vade, offer.clone()).await?;

    let unfinished_credential = create_unfinished_credential(
        &mut vade,
        credential_request.clone(),
        revocation_list.id,
        "0".to_string(),
    )
    .await?;

    let key_id = format!("{}#bbs-key-1", ISSUER_DID);
    let finished_credential =
        create_finished_credential(&mut vade, unfinished_credential, signature_blinding_base64)
            .await?;

    assert_eq!(&finished_credential.issuer, ISSUER_DID);
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
    assert!(&finished_credential.credential_status.is_none());

    assert!(base64::decode(&finished_credential.proof.signature).is_ok());

    Ok(())
}

#[tokio::test]
async fn workflow_can_propose_request_issue_verify_a_credential() -> Result<(), Box<dyn Error>> {
    let mut vade = get_vade();

    let revocation_list = create_revocation_list(&mut vade).await?;

    // Create credential offering
    let schema = CredentialSchema::from_str(SCHEMA)?;
    let mut credential_draft = schema.to_draft_credential(CredentialDraftOptions {
        issuer_did: ISSUER_DID.to_string(),
        id: None,
        issuance_date: None,
        valid_until: None,
    });
    let mut credential_values = HashMap::new();
    credential_values.insert("test_property_string3".to_owned(), "value".to_owned());
    credential_values.insert("test_property_string1".to_owned(), "value".to_owned());
    credential_values.insert("test_property_string2".to_owned(), "value".to_owned());
    credential_values.insert("test_property_string".to_owned(), "value".to_owned());
    credential_values.insert("test_property_string4".to_owned(), "value".to_owned());
    credential_draft.credential_subject.data = credential_values;
    let offer_payload = OfferCredentialPayload {
        draft_credential: credential_draft,
    };

    let offer = create_credential_offer(&mut vade, offer_payload).await?;

    let (credential_request, signature_blinding_base64) =
        create_credential_request(&mut vade, offer.clone()).await?;

    let unfinished_credential = create_unfinished_credential(
        &mut vade,
        credential_request,
        revocation_list.id.clone(),
        "0".to_string(),
    )
    .await?;

    let finished_credential = create_finished_credential(
        &mut vade,
        unfinished_credential.clone(),
        signature_blinding_base64.clone(),
    )
    .await?;

    // create proof request
    let mut proof_request = create_proof_request(&mut vade).await?;
    proof_request.sub_proof_requests[0].revealed_attributes = vec![10, 11];

    // create proof
    let mut public_key_schema_map = HashMap::new();
    public_key_schema_map.insert(SCHEMA_DID.to_string(), PUB_KEY.to_string());
    let presentation = create_presentation(
        &mut vade,
        finished_credential.clone(),
        proof_request.clone(),
        public_key_schema_map.clone(),
    )
    .await?;

    // verify proof
    let verify_proof_payload = VerifyProofPayload {
        presentation: presentation.clone(),
        proof_request: proof_request.clone(),
        keys_to_schema_map: public_key_schema_map,
        signer_address: SIGNER_1_ADDRESS.to_string(),
        revocation_list: Some(revocation_list.clone()),
    };
    let verify_proof_json = serde_json::to_string(&verify_proof_payload)?;
    let results = vade
        .vc_zkp_verify_proof(EVAN_METHOD, TYPE_OPTIONS, &verify_proof_json)
        .await?;

    let result: BbsProofVerification =
        serde_json::from_str(&results[0].as_ref().ok_or("could not get result")?)?;

    assert_eq!(&result.presented_proof, &presentation.id);
    assert_eq!(&result.status, &"verified".to_string());

    Ok(())
}

#[tokio::test]
async fn workflow_cannot_verify_revoked_credential() -> Result<(), Box<dyn Error>> {
    let mut vade = get_vade();

    let revocation_list = create_revocation_list(&mut vade).await?;

    // Create credential offering
    let schema = CredentialSchema::from_str(SCHEMA)?;
    let mut credential_draft = schema.to_draft_credential(CredentialDraftOptions {
        issuer_did: ISSUER_DID.to_string(),
        id: None,
        issuance_date: None,
        valid_until: None,
    });
    let mut credential_values = HashMap::new();
    credential_values.insert("test_property_string3".to_owned(), "value".to_owned());
    credential_values.insert("test_property_string1".to_owned(), "value".to_owned());
    credential_values.insert("test_property_string2".to_owned(), "value".to_owned());
    credential_values.insert("test_property_string".to_owned(), "value".to_owned());
    credential_values.insert("test_property_string4".to_owned(), "value".to_owned());
    credential_draft.credential_subject.data = credential_values;
    let offer_payload = OfferCredentialPayload {
        draft_credential: credential_draft,
    };

    let offer = create_credential_offer(&mut vade, offer_payload).await?;

    let (credential_request, signature_blinding_base64) =
        create_credential_request(&mut vade, offer.clone()).await?;

    let unfinished_credential = create_unfinished_credential(
        &mut vade,
        credential_request,
        revocation_list.id.clone(),
        "0".to_string(),
    )
    .await?;

    let finished_credential =
        create_finished_credential(&mut vade, unfinished_credential, signature_blinding_base64)
            .await?;

    // revoke credential
    let updated_revocation = revoke_credential(&mut vade, revocation_list, "0".to_string()).await?;

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
    )
    .await?;

    // verify proof
    let presentation_id = &presentation.id.to_owned();
    let verify_proof_payload = VerifyProofPayload {
        presentation,
        proof_request,
        keys_to_schema_map: public_key_schema_map,
        signer_address: SIGNER_1_ADDRESS.to_string(),
        revocation_list: Some(updated_revocation),
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

#[tokio::test]
async fn workflow_can_get_public_key_from_private_key() -> Result<(), Box<dyn Error>> {
    let mut vade = get_vade();

    let options = r#"{ "type": "bbs" }"#;

    let payload = format!(r#"{{ "privateKey": "{}" }}"#, &SECRET_KEY);

    let result = vade
        .run_custom_function(
            EVAN_METHOD,
            "get_public_key_from_private_key",
            &options,
            &payload,
        )
        .await?;

    let result_public_key = result[0]
        .as_ref()
        .ok_or("missing public key in vade result")?;

    assert_eq!(result_public_key, PUB_KEY);

    Ok(())
}
