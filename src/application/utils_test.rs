use crate::application::
    datatypes::{
    BbsCredentialRequest,
    UnfinishedBbsCredential, CREDENTIAL_PROOF_PURPOSE,
    CREDENTIAL_SIGNATURE_TYPE,
};

use crate::utils::test_data::{
    accounts::local::{HOLDER_DID, ISSUER_DID }};

pub fn is_base_64(input: String) -> bool {
    match base64::decode(input) {
        Ok(_) => true,
        Err(_) => false,
    }
}

pub fn assert_credential(
    credential_request: BbsCredentialRequest,
    cred: UnfinishedBbsCredential,
    pub_key_id: &str,
    schema_id: &str,
) {
    assert_eq!(&cred.issuer, ISSUER_DID);
    assert_eq!(&cred.credential_subject.id, HOLDER_DID);
    assert_eq!(&cred.credential_schema.id, schema_id);
    // proof
    assert_eq!(&cred.proof.required_reveal_statements, &[1].to_vec());
    assert_eq!(&cred.proof.r#type, CREDENTIAL_SIGNATURE_TYPE);
    assert_eq!(&cred.proof.proof_purpose, CREDENTIAL_PROOF_PURPOSE);
    assert_eq!(&cred.proof.verification_method, pub_key_id);
    assert!(
        is_base_64(cred.proof.blind_signature.to_owned()),
        "Signature seems not to be base64 encoded"
    );
    // Credential subject
    // Are the values correctly copied into the credentials?
    assert!(&cred
        .credential_subject
        .data
        .keys()
        .all(|key| credential_request.credential_values.contains_key(key)
            && credential_request.credential_values.get(key)
                == cred.credential_subject.data.get(key)));
}