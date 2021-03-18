use std::collections::HashMap;
use std::error::Error;
use utilities::test_data::bbs_coherent_context_test_data::EXAMPLE_REVOCATION_LIST_DID;
use utilities::test_data::{
    accounts::local::{
        ISSUER_DID, ISSUER_PRIVATE_KEY, ISSUER_PUBLIC_KEY_DID, SIGNER_1_DID, SIGNER_1_PRIVATE_KEY,
    },
    bbs_coherent_context_test_data::{MASTER_SECRET, PUB_KEY, SECRET_KEY, SUBJECT_DID},
    environment::DEFAULT_VADE_EVAN_SUBSTRATE_IP,
    vc_zkp::{SCHEMA_DESCRIPTION, SCHEMA_NAME, SCHEMA_PROPERTIES, SCHEMA_REQUIRED_PROPERTIES},
};
use vade::Vade;
use vade_evan_bbs::application::datatypes::{
    BbsCredential, BbsCredentialOffer, BbsCredentialRequest, CredentialSchema,
    UnfinishedBbsCredential, CREDENTIAL_OFFER_TYPE, CREDENTIAL_PROOF_PURPOSE,
    CREDENTIAL_PROPOSAL_TYPE, CREDENTIAL_REQUEST_TYPE, CREDENTIAL_SIGNATURE_TYPE,
};
use vade_evan_bbs::{
    application::datatypes::CredentialProposal,
    vade_evan_bbs::{
        CreateCredentialProposalPayload, FinishCredentialPayload, IssueCredentialPayload,
        OfferCredentialPayload, RequestCredentialPayload, VadeEvanBbs,
    },
};

use std::env;
use vade_evan_substrate::{
    signing::{LocalSigner, Signer},
    ResolverConfig, VadeEvanSubstrate,
};

const EVAN_METHOD: &str = "did:evan";
const TYPE_OPTIONS: &str = r#"{ "type": "cl" }"#;
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
        .vc_zkp_create_credential_schema(EVAN_METHOD, &_get_options(), &payload)
        .await?;

    // check results
    assert_eq!(results.len(), 1);

    let result: CredentialSchema = serde_json::from_str(results[0].as_ref().unwrap()).unwrap();
    Ok(result)
}

fn _get_options() -> String {
    format!(
        r###"{{
            "type": "cl",
            "privateKey": "{}",
            "identity": "{}"
        }}"###,
        SIGNER_1_PRIVATE_KEY, SIGNER_1_DID,
    )
}
#[tokio::test]
async fn test_issuance_workflow() -> Result<(), Box<dyn Error>> {
    let mut vade = get_vade();

    // Create credential proposal
    let proposal_payload = CreateCredentialProposalPayload {
        issuer: ISSUER_DID.to_string(),
        subject: SUBJECT_DID.to_string(),
        schema: SCHEMA_DID.to_string(),
    };
    let proposal_payload_json = serde_json::to_string(&proposal_payload)?;
    let mut result = vade
        .vc_zkp_create_credential_proposal(EVAN_METHOD, TYPE_OPTIONS, &proposal_payload_json)
        .await?;
    let proposal: CredentialProposal = serde_json::from_str(&result[0].as_ref().unwrap())?;
    assert_eq!(&proposal.subject, &SUBJECT_DID);
    assert_eq!(&proposal.issuer, &ISSUER_DID);
    assert_eq!(&proposal.schema, &SCHEMA_DID.clone());
    assert_eq!(&proposal.r#type, CREDENTIAL_PROPOSAL_TYPE);

    // Create credential offering
    let offer = OfferCredentialPayload {
        issuer: ISSUER_DID.to_string(),
        credential_proposal: proposal.clone(),
    };

    let offer_json = serde_json::to_string(&offer)?;
    result = vade
        .vc_zkp_create_credential_offer(EVAN_METHOD, TYPE_OPTIONS, &offer_json)
        .await?;
    let offering: BbsCredentialOffer = serde_json::from_str(&result[0].as_ref().unwrap())?;
    assert_eq!(&offering.issuer, &ISSUER_DID);
    assert_eq!(&offering.schema, &proposal.schema);
    assert_eq!(&offering.subject, &proposal.subject);
    assert_eq!(&offering.r#type, &CREDENTIAL_OFFER_TYPE);

    // Create credential request
    let mut credential_values = HashMap::new();
    credential_values.insert("test_property_string".to_owned(), "value".to_owned());
    let mut nquads = Vec::new();
    let mut keys: Vec<String> = credential_values.keys().map(|k| k.to_string()).collect();
    keys.sort();
    for key in &keys {
        let val = credential_values.get(key).ok_or("AAA".to_owned())?;
        let string = format!("{}: {}", key, val);
        nquads.insert(nquads.len(), string);
    }

    let request = RequestCredentialPayload {
        credential_offering: offering.clone(),
        credential_schema: SCHEMA_DID.to_string(),
        master_secret: MASTER_SECRET.to_string(),
        credential_values: credential_values.clone(),
        issuer_pub_key: PUB_KEY.to_string(),
    };
    let request_json = serde_json::to_string(&request)?;
    result = vade
        .vc_zkp_request_credential(EVAN_METHOD, TYPE_OPTIONS, &request_json)
        .await?;
    println!("{}", &result[0].as_ref().unwrap());

    let (credential_request, signature_blinding_base64): (BbsCredentialRequest, String) =
        serde_json::from_str(&result[0].as_ref().unwrap())?;
    assert_eq!(credential_request.schema, SCHEMA_DID);
    assert_eq!(credential_request.subject, offering.subject);
    assert_eq!(credential_request.r#type, CREDENTIAL_REQUEST_TYPE);

    // Issue unfinished credential
    let key_id = format!("{}#key-1", ISSUER_DID);
    let issue_cred = IssueCredentialPayload {
        issuer: ISSUER_DID.to_string(),
        issuer_public_key_id: key_id.clone(),
        issuer_public_key: PUB_KEY.to_string(),
        issuer_secret_key: SECRET_KEY.to_string(),
        subject: offering.clone().subject,
        schema: SCHEMA_DID.to_string(),
        credential_request: credential_request.clone(),
        credential_offer: offering,
        required_indices: [1].to_vec(),
        nquads: nquads.clone(),
        revocation_list_did: EXAMPLE_REVOCATION_LIST_DID.to_string(),
        revocation_list_id: "0".to_string(),
    };
    let issue_cred_json = serde_json::to_string(&issue_cred)?;

    result = vade
        .vc_zkp_issue_credential(EVAN_METHOD, TYPE_OPTIONS, &issue_cred_json)
        .await?;

    let unfinished_credential: UnfinishedBbsCredential =
        serde_json::from_str(&result[0].as_ref().unwrap())?;

    // Finish credential
    let finish_request = FinishCredentialPayload {
        credential: unfinished_credential,
        master_secret: MASTER_SECRET.to_string(),
        nquads,
        issuer_public_key: PUB_KEY.to_string(),
        blinding: signature_blinding_base64,
    };

    let finish_request_json = serde_json::to_string(&finish_request)?;
    result = vade
        .vc_zkp_finish_credential(EVAN_METHOD, TYPE_OPTIONS, &finish_request_json)
        .await?;

    let finished_credential: BbsCredential = serde_json::from_str(&result[0].as_ref().unwrap())?;

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
