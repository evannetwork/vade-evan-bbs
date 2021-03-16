use vade_evan_bbs::application::{issuer::Issuer, prover::Prover};
use vade_evan_bbs::application::datatypes::{
    CredentialSchema, CREDENTIAL_PROPOSAL_TYPE,
    CREDENTIAL_REQUEST_TYPE, CREDENTIAL_OFFER_TYPE, CREDENTIAL_SIGNATURE_TYPE, CREDENTIAL_PROOF_PURPOSE
};
use bbs::{
    keys::{ DeterministicPublicKey, SecretKey }, SignatureBlinding,
    SignatureMessage,
};
use std::collections::HashMap;
use std::error::Error;
use utilities::test_data::{
    accounts::local::{ HOLDER_DID, ISSUER_DID},
    bbs_coherent_context_test_data::{
        MASTER_SECRET, NQUADS, PUB_KEY, SIGNATURE_BLINDING, SECRET_KEY, EXAMPLE_REVOCATION_LIST_DID,
    },
    vc_zkp::{ EXAMPLE_CREDENTIAL_SCHEMA}};
#[test]

fn test_issuance_workflow() -> Result<(), Box<dyn Error>>{
    // Create credential proposal
    let proposal = Prover::propose_credential(&ISSUER_DID, &HOLDER_DID, "schemadid");
    assert_eq!(&proposal.subject, &HOLDER_DID);
    assert_eq!(&proposal.issuer, &ISSUER_DID);
    assert_eq!(&proposal.schema, "schemadid");
    assert_eq!(&proposal.r#type, CREDENTIAL_PROPOSAL_TYPE);
    
    // Create credential offering
    let offering = Issuer::offer_credential(&proposal, &ISSUER_DID)?;
    assert_eq!(&offering.issuer, &ISSUER_DID);
    assert_eq!(&offering.schema, &proposal.schema);
    assert_eq!(&offering.subject, &proposal.subject);
    assert_eq!(&offering.r#type, &CREDENTIAL_OFFER_TYPE);

    // Create credential request
    let mut credential_values = HashMap::new();
    credential_values.insert("test_property_string".to_owned(), "value".to_owned());
    
    let schema: CredentialSchema = serde_json::from_str(EXAMPLE_CREDENTIAL_SCHEMA)?;

    let master_secret: SignatureMessage =
    SignatureMessage::from(base64::decode(&MASTER_SECRET)?.into_boxed_slice());

    let public_key: DeterministicPublicKey =
    DeterministicPublicKey::from(base64::decode(&PUB_KEY)?.into_boxed_slice());

    let (credential_request, _) = Prover::request_credential(&offering, &schema, &master_secret, credential_values, &public_key)
    .map_err(|e| format!("{}", e))?;
    assert_eq!(credential_request.schema, schema.id);
    assert_eq!(credential_request.subject, offering.subject);
    assert_eq!(credential_request.r#type, CREDENTIAL_REQUEST_TYPE);

    // Issue credential
    let key_id = format!("{}#key-1", ISSUER_DID);
    let sk: SecretKey = SecretKey::from(base64::decode(&SECRET_KEY)?.into_boxed_slice());
    let nquads = Vec::new();
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
        &EXAMPLE_REVOCATION_LIST_DID,
        "0",
    )?;
    
    // Finish credential
    let nquads: Vec<String> = NQUADS.iter().map(|q| q.to_string()).collect();
    let blinding: SignatureBlinding =
    SignatureBlinding::from(base64::decode(&SIGNATURE_BLINDING)?.into_boxed_slice());
    match Prover::finish_credential(
        &unfinished_credential,
        &master_secret,
        &nquads,
        &public_key,
        &blinding,
    ) {
        Ok(cred) => {
            assert_eq!(&cred.issuer, ISSUER_DID);
            assert_eq!(&cred.credential_subject.id, HOLDER_DID);
            assert_eq!(&cred.credential_schema.id, &schema.id);
            // proof
            assert_eq!(&cred.proof.required_reveal_statements, &[1].to_vec());
            assert_eq!(&cred.proof.r#type, CREDENTIAL_SIGNATURE_TYPE);
            assert_eq!(&cred.proof.proof_purpose, CREDENTIAL_PROOF_PURPOSE);
            assert_eq!(&cred.proof.verification_method, &key_id);
            // Credential subject
            // Are the values correctly copied into the credentials?
            assert!(&cred
                .credential_subject
                .data
                .keys()
                .all(|key| credential_request.credential_values.contains_key(key)
                    && credential_request.credential_values.get(key)
                        == cred.credential_subject.data.get(key)));
            // There is now a property 'signature' and it is base64 encoded
            assert!(base64::decode(&cred.proof.signature).is_ok());
        }
        Err(e) => {
            assert!(false, "Unexpected error when finishing credential: {}", e);
        }
    }
    Ok(())
}
