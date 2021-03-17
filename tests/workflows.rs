use bbs::{
    keys::{DeterministicPublicKey, SecretKey},
    SignatureMessage,
};
use std::collections::HashMap;
use std::error::Error;
use utilities::test_data::bbs_coherent_context_test_data::EXAMPLE_REVOCATION_LIST_DID;
use utilities::test_data::{
    accounts::local::{HOLDER_DID, ISSUER_DID},
    bbs_coherent_context_test_data::{
        MASTER_SECRET, NQUADS, PUB_KEY, REVOCATION_LIST_CREDENTIAL, SCHEMA_DID, SECRET_KEY,
        SIGNATURE_BLINDING, SUBJECT_DID,
    },
    environment::DEFAULT_VADE_EVAN_SUBSTRATE_IP,
    vc_zkp::{EXAMPLE_CREDENTIAL_PROPOSAL, EXAMPLE_CREDENTIAL_SCHEMA},
};
use vade::Vade;
use vade_evan_bbs::application::datatypes::{
    BbsCredential, BbsCredentialOffer, CredentialSchema, RevocationListCredential,
    CREDENTIAL_OFFER_TYPE, CREDENTIAL_PROOF_PURPOSE, CREDENTIAL_PROPOSAL_TYPE,
    CREDENTIAL_REQUEST_TYPE, CREDENTIAL_SIGNATURE_TYPE,
};
use vade_evan_bbs::{
    self,
    application::{issuer::Issuer, prover::Prover},
};
use vade_evan_bbs::{
    application::datatypes::CredentialProposal,
    vade_evan_bbs::{FinishCredentialPayload, OfferCredentialPayload, VadeEvanBbs},
};

use std::env;
use vade_evan_substrate::{
    signing::{LocalSigner, Signer},
    ResolverConfig, VadeEvanSubstrate,
};

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

#[tokio::test]
async fn test_issuance_workflow() -> Result<(), Box<dyn Error>> {
    const EVAN_METHOD: &str = "did:evan";
    const TYPE_OPTIONS: &str = r#"{ "type": "cl" }"#;
    let mut vade = get_vade();
    // Create credential proposal
    let mut result = vade
        .vc_zkp_create_credential_proposal(EVAN_METHOD, TYPE_OPTIONS, &EXAMPLE_CREDENTIAL_PROPOSAL)
        .await?;
    let proposal: CredentialProposal = serde_json::from_str(&result[0].as_ref().unwrap())?;
    assert_eq!(&proposal.subject, &SUBJECT_DID);
    assert_eq!(&proposal.issuer, &ISSUER_DID);
    assert_eq!(&proposal.schema, &SCHEMA_DID);
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

    // let request = RequestCredentialPayload {
    //     credential_offering: offering.clone(),
    //     credential_schema: SCHEMA_DID.to_string(),
    //     master_secret: MASTER_SECRET.to_string(),
    //     credential_values,
    //     issuer_pub_key: PUB_KEY.to_string(),
    // };
    // let request_json = serde_json::to_string(&request)?;

    let schema: CredentialSchema = serde_json::from_str(EXAMPLE_CREDENTIAL_SCHEMA)?;
    let schema_string = serde_json::to_string(&schema)?;
    let master_secret: SignatureMessage =
        SignatureMessage::from(base64::decode(&MASTER_SECRET)?.into_boxed_slice());
    let public_key: DeterministicPublicKey =
        DeterministicPublicKey::from(base64::decode(&PUB_KEY)?.into_boxed_slice());
    // let revocation_list: RevocationListCredential =
    //     serde_json::from_str(REVOCATION_LIST_CREDENTIAL)?;

    // result = vade
    //     .vc_zkp_request_credential(EVAN_METHOD, TYPE_OPTIONS, &request_json)
    //     .await?;
    // // println!("I am here!!!!");
    // let credential_request: BbsCredentialRequest =
    //     serde_json::from_str(&result[0].as_ref().unwrap())?;
    let revocation_list: RevocationListCredential =
        serde_json::from_str(REVOCATION_LIST_CREDENTIAL)?;
    let (credential_request, _) = Prover::request_credential(
        &offering,
        &schema,
        &master_secret,
        credential_values,
        &public_key,
    )
    .map_err(|e| format!("{}", e))?;
    // println!("{}", &result[0].as_ref().unwrap());

    assert_eq!(credential_request.schema, schema.id);
    assert_eq!(credential_request.subject, offering.subject);
    assert_eq!(credential_request.r#type, CREDENTIAL_REQUEST_TYPE);

    let credential_request_json = serde_json::to_string(&credential_request)?;
    println!("{}", &credential_request_json);
    // // Issue credential
    let key_id = format!("{}#key-1", ISSUER_DID);
    let sk: SecretKey = SecretKey::from(base64::decode(&SECRET_KEY)?.into_boxed_slice());
    let nquads = Vec::new();

    // let issue_cred = IssueCredentialPayload {
    //     issuer: ISSUER_DID.to_string(),
    //     issuer_public_key_id: key_id.clone(),
    //     issuer_public_key: PUB_KEY.to_string(),
    //     issuer_secret_key: SECRET_KEY.to_string(),
    //     subject: offering.clone().subject,
    //     schema: schema_string,
    //     credential_request: credential_request.clone(),
    //     credential_offer: offering,
    //     required_indices: [1].to_vec(),
    //     nquads,
    //     revocation_list_did: EXAMPLE_REVOCATION_LIST_DID.to_string(),
    //     revocation_list_id: "0".to_string(),
    // };
    // let issue_cred_json = serde_json::to_string(&issue_cred)?;
    // // println!("---------------------------------------------1");
    // println!("{}", &issue_cred_json);

    // result = vade
    //     .vc_zkp_issue_credential(EVAN_METHOD, TYPE_OPTIONS, &issue_cred_json)
    //     .await?;

    // let unfinished_credential: UnfinishedBbsCredential =
    //     serde_json::from_str(&result[0].as_ref().unwrap())?;
    let unfinished_credential = Issuer::issue_credential(
        &ISSUER_DID,
        &HOLDER_DID,
        &offering,
        &credential_request,
        &key_id,
        &public_key,
        &sk,
        schema.clone(),
        [1].to_vec(),
        nquads,
        EXAMPLE_REVOCATION_LIST_DID,
        "0",
    )?;

    // // Finish credential
    let nquads: Vec<String> = NQUADS.iter().map(|q| q.to_string()).collect();
    let finish_request = FinishCredentialPayload {
        credential: unfinished_credential,
        master_secret: MASTER_SECRET.to_string(),
        nquads,
        issuer_public_key: PUB_KEY.to_string(),
        blinding: SIGNATURE_BLINDING.to_string(),
    };

    let finish_request_json = serde_json::to_string(&finish_request)?;
    result = vade
        .vc_zkp_finish_credential(EVAN_METHOD, TYPE_OPTIONS, &finish_request_json)
        .await?;

    let finished_credential: BbsCredential = serde_json::from_str(&result[0].as_ref().unwrap())?;

    assert_eq!(&finished_credential.issuer, ISSUER_DID);
    assert_eq!(&finished_credential.credential_subject.id, HOLDER_DID);
    assert_eq!(&finished_credential.credential_schema.id, &schema.id);
    // proof
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
    // Credential subject
    // Are the values correctly copied into the credentials?
    assert!(&finished_credential
        .credential_subject
        .data
        .keys()
        .all(|key| credential_request.credential_values.contains_key(key)
            && credential_request.credential_values.get(key)
                == finished_credential.credential_subject.data.get(key)));
    // There is now a property 'signature' and it is base64 encoded
    assert!(base64::decode(&finished_credential.proof.signature).is_ok());
    // let blinding: SignatureBlinding =
    //     SignatureBlinding::from(base64::decode(&SIGNATURE_BLINDING)?.into_boxed_slice());
    // match Prover::finish_credential(
    //     &unfinished_credential,
    //     &master_secret,
    //     &nquads,
    //     &public_key,
    //     &blinding,
    // ) {
    //     Ok(cred) => {
    //         assert_eq!(&cred.issuer, ISSUER_DID);
    //         assert_eq!(&cred.credential_subject.id, HOLDER_DID);
    //         assert_eq!(&cred.credential_schema.id, &schema.id);
    //         // proof
    //         assert_eq!(&cred.proof.required_reveal_statements, &[1].to_vec());
    //         assert_eq!(&cred.proof.r#type, CREDENTIAL_SIGNATURE_TYPE);
    //         assert_eq!(&cred.proof.proof_purpose, CREDENTIAL_PROOF_PURPOSE);
    //         assert_eq!(&cred.proof.verification_method, &key_id);
    //         // Credential subject
    //         // Are the values correctly copied into the credentials?
    //         assert!(&cred
    //             .credential_subject
    //             .data
    //             .keys()
    //             .all(|key| credential_request.credential_values.contains_key(key)
    //                 && credential_request.credential_values.get(key)
    //                     == cred.credential_subject.data.get(key)));
    //         // There is now a property 'signature' and it is base64 encoded
    //         assert!(base64::decode(&cred.proof.signature).is_ok());
    //     }
    //     Err(e) => {
    //         assert!(false, "Unexpected error when finishing credential: {}", e);
    //     }
    // }
    Ok(())
}
