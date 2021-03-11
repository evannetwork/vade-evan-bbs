use crate::application::{
    datatypes::{BbsUnfinishedCredentialSignature, CredentialSchemaReference, CredentialSubject},
    utils::{generate_uuid, get_now_as_iso_string},
};
use crate::{
    application::datatypes::{
        BbsCredentialOffer, BbsCredentialRequest, CredentialProposal, CredentialSchema,
        UnfinishedBbsCredential, CREDENTIAL_OFFER_TYPE, CREDENTIAL_PROOF_PURPOSE,
        CREDENTIAL_SCHEMA_TYPE, CREDENTIAL_SIGNATURE_TYPE, DEFAULT_CREDENTIAL_CONTEXTS,
    },
    crypto::crypto_issuer::CryptoIssuer,
};
use bbs::{
    issuer::Issuer as BbsIssuer,
    keys::{DeterministicPublicKey, SecretKey},
    ProofNonce,
};
use std::error::Error;

pub struct Issuer {}

impl Issuer {
    /// Creates a new credential offer, as a response to a `CredentialProposal` sent by a prover.
    ///
    /// # Arguments
    /// * `credential_proposal` - The proposal to respond to
    /// * `issuer_did` - DID of the issuer that is supposed to issue the offer
    ///
    /// # Returns
    /// * `BbsCredentialOffer` - The message to be sent to the prover.
    pub fn offer_credential(
        credential_proposal: &CredentialProposal,
        issuer_did: &str,
    ) -> Result<BbsCredentialOffer, Box<dyn Error>> {
        let mut nonce =
            base64::encode(BbsIssuer::generate_signing_nonce().to_bytes_compressed_form());
        if credential_proposal.issuer != issuer_did {
            return Err(Box::from(
                "Cannot offer credential: Proposal is not targeted at this issuer",
            ));
        }

        Ok(BbsCredentialOffer {
            issuer: issuer_did.to_owned(),
            subject: credential_proposal.subject.to_owned(),
            r#type: CREDENTIAL_OFFER_TYPE.to_string(),
            schema: credential_proposal.schema.to_owned(),
            nonce,
        })
    }

    pub fn issue_credential(
        issuer_did: &str,
        subject_did: &str,
        credential_offer: &BbsCredentialOffer,
        credential_request: &BbsCredentialRequest,
        issuer_public_key_id: &str,
        issuer_public_key: &DeterministicPublicKey,
        issuer_secret_key: &SecretKey,
        credential_schema: CredentialSchema,
        required_indices: Vec<u32>,
        nquads: Vec<String>,
    ) -> Result<UnfinishedBbsCredential, Box<dyn Error>> {
        let credential_subject = CredentialSubject {
            id: subject_did.to_owned(),
            data: credential_request.credential_values.clone(),
        };

        let schema_reference = CredentialSchemaReference {
            id: credential_schema.id,
            r#type: CREDENTIAL_SCHEMA_TYPE.to_string(),
        };

        let nonce = ProofNonce::from(base64::decode(&credential_offer.nonce)?.into_boxed_slice());
        let blind_signature = CryptoIssuer::create_signature(
            &credential_request.blind_signature_context,
            &nonce,
            nquads.clone(),
            issuer_public_key,
            issuer_secret_key,
        )
        .map_err(|e| format!("Error creating bbs+ signature: {}", e))?;

        let vc_signature = BbsUnfinishedCredentialSignature {
            r#type: CREDENTIAL_SIGNATURE_TYPE.to_string(),
            created: get_now_as_iso_string(),
            proof_purpose: CREDENTIAL_PROOF_PURPOSE.to_owned(),
            verification_method: issuer_public_key_id.to_owned(),
            required_reveal_statements: required_indices,
            blind_signature: base64::encode(blind_signature.to_bytes_compressed_form()),
        };

        let credential_id = generate_uuid();
        let credential = UnfinishedBbsCredential {
            context: DEFAULT_CREDENTIAL_CONTEXTS
                .iter()
                .map(|c| String::from(c.to_owned()))
                .collect::<Vec<_>>(),
            id: credential_id,
            r#type: vec!["VerifiableCredential".to_string()],
            issuer: issuer_did.to_owned(),
            credential_subject,
            credential_schema: schema_reference,
            proof: vc_signature,
        };
        Ok(credential)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        application::{
            datatypes::{BbsCredentialOffer, BbsCredentialRequest, UnfinishedBbsCredential},
            prover::Prover,
        },
        utils::test_data::{
            accounts::local::{HOLDER_DID, ISSUER_DID},
            vc_zkp::{EXAMPLE_CREDENTIAL_PROPOSAL, EXAMPLE_CREDENTIAL_SCHEMA},
        },
    };
    use bbs::issuer::Issuer as BbsIssuer;
    use bbs::prover::Prover as BbsProver;
    use bbs::SignatureBlinding;
    use bbs::SignatureMessage;
    use std::collections::HashMap;

    fn request_credential(
        pub_key: &DeterministicPublicKey,
        offer: &BbsCredentialOffer,
        amount_of_values: u8,
    ) -> Result<(BbsCredentialRequest, CredentialSchema, Vec<String>), Box<dyn Error>> {
        let schema: CredentialSchema = serde_json::from_str(EXAMPLE_CREDENTIAL_SCHEMA)?;
        let secret = BbsProver::new_link_secret();
        let mut credential_values = HashMap::new();
        credential_values.insert("test_property_string".to_owned(), "value".to_owned());
        for i in 1..amount_of_values {
            credential_values.insert(format!("test_property_string{}", i), "value".to_owned());
        }

        // Nquad-ize. Flatten the json-ld document graph.
        // This will be done by TnT for now as we currently could not find a suitable rust library
        let mut nquads = Vec::new();
        let mut keys: Vec<String> = credential_values.keys().map(|k| k.to_string()).collect();
        keys.sort();
        for key in &keys {
            let val = credential_values.get(key).ok_or("AAA".to_owned())?;
            let string = format!("{}: {}", key, val);
            nquads.insert(nquads.len(), string);
        }

        let (credential_request, blinding) =
            Prover::request_credential(offer, &schema, &secret, credential_values, pub_key)
                .map_err(|e| format!("{}", e))?;

        return Ok((credential_request, schema, nquads));
    }

    fn is_base_64(input: String) -> bool {
        match base64::decode(input) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    fn assert_credential(
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

    #[test]
    fn can_offer_credential() -> Result<(), Box<dyn Error>> {
        let proposal: CredentialProposal = serde_json::from_str(&EXAMPLE_CREDENTIAL_PROPOSAL)?;
        let offer = Issuer::offer_credential(&proposal, &ISSUER_DID)?;

        assert_eq!(&offer.issuer, &ISSUER_DID);
        assert_eq!(&offer.schema, &proposal.schema);
        assert_eq!(&offer.subject, &proposal.subject);
        assert_eq!(&offer.r#type, &CREDENTIAL_OFFER_TYPE);

        Ok(())
    }

    #[test]
    fn credential_offer_fails_on_wrong_issuer() -> Result<(), Box<dyn Error>> {
        let proposal: CredentialProposal = serde_json::from_str(&EXAMPLE_CREDENTIAL_PROPOSAL)?;
        let offer = Issuer::offer_credential(&proposal, "random_issuer");

        match offer {
            Ok(_) => assert!(false),
            Err(e) => assert_eq!(
                format!("{}", e),
                "Cannot offer credential: Proposal is not targeted at this issuer"
            ),
        };

        Ok(())
    }

    #[test]
    fn can_issue_credential_one_property() -> Result<(), Box<dyn Error>> {
        let (dpk, sk) = BbsIssuer::new_short_keys(None);
        let proposal: CredentialProposal = serde_json::from_str(&EXAMPLE_CREDENTIAL_PROPOSAL)?;
        let offer = Issuer::offer_credential(&proposal, &ISSUER_DID)?;
        let key_id = format!("{}#key-1", ISSUER_DID);
        let (credential_request, schema, nquads) = request_credential(&dpk, &offer, 1)?;

        match Issuer::issue_credential(
            &ISSUER_DID,
            &HOLDER_DID,
            &offer,
            &credential_request,
            &key_id,
            &dpk,
            &sk,
            schema.clone(),
            [1].to_vec(),
            nquads,
        ) {
            Ok(cred) => {
                assert_credential(
                    credential_request.clone(),
                    cred.clone(),
                    &key_id,
                    &schema.id,
                );
            }
            Err(e) => assert!(false, "Received error when issuing credential: {}", e),
        }
        Ok(())
    }

    #[test]
    fn can_issue_credential_five_properties() -> Result<(), Box<dyn Error>> {
        let (dpk, sk) = BbsIssuer::new_short_keys(None);
        let proposal: CredentialProposal = serde_json::from_str(&EXAMPLE_CREDENTIAL_PROPOSAL)?;
        let offer = Issuer::offer_credential(&proposal, &ISSUER_DID)?;
        let key_id = format!("{}#key-1", ISSUER_DID);
        let (credential_request, schema, nquads) = request_credential(&dpk, &offer, 5)?;

        match Issuer::issue_credential(
            &ISSUER_DID,
            &HOLDER_DID,
            &offer,
            &credential_request,
            &key_id,
            &dpk,
            &sk,
            schema.clone(),
            [1].to_vec(),
            nquads,
        ) {
            Ok(cred) => {
                assert_credential(
                    credential_request.clone(),
                    cred.clone(),
                    &key_id,
                    &schema.id,
                );
            }
            Err(e) => assert!(false, "Received error when issuing credential: {}", e),
        }
        Ok(())
    }
}
