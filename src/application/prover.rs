use super::datatypes::{
    BbsCredential, BbsCredentialOffer, BbsCredentialRequest, CredentialProposal, CredentialSchema,
    UnfinishedBbsCredential, CREDENTIAL_PROPOSAL_TYPE, CREDENTIAL_REQUEST_TYPE,
};
use crate::crypto::crypto_prover::CryptoProver;
use bbs::{
    keys::DeterministicPublicKey, signature::BlindSignature, SignatureBlinding, SignatureMessage,
};
use std::collections::HashMap;
use std::convert::{From, TryFrom, TryInto};
use std::error::Error;

pub struct Prover {}

// TODO: Add error class

impl Prover {
    /// Create a new credential proposal to send to a potential issuer.
    ///
    /// # Arguments
    /// * `issuer_did` - DID of the issuer the proposal is for
    /// * `subject_did` - DID of the proposal creator and potential subject of the credential
    /// * `schema_did` - DID of the schema to propose the credential for
    ///
    /// # Returns
    /// * `CredentialProposal` - The message to be sent to an issuer
    pub fn propose_credential(
        issuer_did: &str,
        subject_did: &str,
        schema_did: &str,
    ) -> CredentialProposal {
        CredentialProposal {
            issuer: issuer_did.to_owned(),
            subject: subject_did.to_owned(),
            schema: schema_did.to_owned(),
            r#type: CREDENTIAL_PROPOSAL_TYPE.to_string(),
        }
    }

    /// Request a new credential based on a received credential offering.
    ///
    /// # Arguments
    /// * `credential_offering` - The received credential offering sent by the potential issuer
    /// * `credential_definition` - The credential definition that is referenced in the credential offering
    /// * `master_secret` - The master secret to incorporate into the blinded values to be signed by the issuer
    /// * `credential_values` - A mapping of property names to their stringified cleartext values
    ///
    /// # Returns
    /// * `CredentialRequest` - The request to be sent to the issuer
    /// * `CredentialSecretsBlindingFactors` - Blinding factors used for blinding the credential values. Need to be stored privately at the prover's site
    pub fn request_credential(
        credential_offering: &BbsCredentialOffer,
        credential_schema: &CredentialSchema,
        master_secret: &SignatureMessage,
        credential_values: HashMap<String, String>,
        issuer_pub_key: &DeterministicPublicKey,
    ) -> Result<(BbsCredentialRequest, SignatureBlinding), Box<dyn Error>> {
        for required in &credential_schema.required {
            if credential_values.get(required).is_none() {
                let error = format!(
                    "Cannot request credential: Missing required schema property: {}",
                    required
                );
                return Err(Box::from(error));
            }
        }

        if credential_values.len() == 0 {
            return Err(Box::from(
                "Cannot create blind signature context. Provided no credential values",
            ));
        }

        let (blind_signature_context, blinding) = CryptoProver::create_blind_signature_context(
            &issuer_pub_key,
            &master_secret,
            &credential_offering.nonce,
        )
        .map_err(|e| {
            format!(
                "Cannot request credential: Could not create signature blinding: {}",
                e
            )
        })?;

        Ok((
            BbsCredentialRequest {
                schema: credential_schema.id.clone(),
                subject: credential_offering.subject.clone(),
                r#type: CREDENTIAL_REQUEST_TYPE.to_string(),
                credential_values: credential_values,
                blind_signature_context: blind_signature_context,
            },
            blinding,
        ))
    }

    pub fn finish_credential(
        unfinished_credential: &UnfinishedBbsCredential,
        master_secret: &SignatureMessage,
        nquads: &Vec<String>,
        issuer_public_key: &DeterministicPublicKey,
        blinding: &SignatureBlinding,
    ) -> Result<BbsCredential, Box<dyn Error>> {
        let raw: Box<[u8]> =
            base64::decode(unfinished_credential.proof.blind_signature.clone())?.into_boxed_slice();
        let blind_signature: BlindSignature = raw.try_into()?;

        let final_signature = CryptoProver::finish_credential_signature(
            nquads.clone(),
            master_secret,
            issuer_public_key,
            &blind_signature,
            blinding,
        )?;

        let credential = BbsCredential::new(
            unfinished_credential.clone(),
            base64::encode(final_signature.to_bytes_compressed_form()),
        );
        Ok(credential)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_data::{
        accounts::local::{HOLDER_DID, ISSUER_DID},
        bbs_coherent_context_test_data::{
            MASTER_SECRET, NQUADS, PUB_KEY, SIGNATURE_BLINDING, UNFINISHED_CREDENTIAL,
        },
        vc_zkp::{EXAMPLE_CREDENTIAL_OFFERING, EXAMPLE_CREDENTIAL_SCHEMA},
    };
    use bbs::issuer::Issuer as BbsIssuer;
    use bbs::keys::SecretKey;
    use bbs::prover::Prover as BbsProver;
    use bbs::SignatureBlinding;

    fn setup_test() -> Result<
        (
            DeterministicPublicKey,
            SecretKey,
            BbsCredentialOffer,
            CredentialSchema,
            SignatureMessage,
            HashMap<String, String>,
        ),
        Box<dyn Error>,
    > {
        let (dpk, sk) = BbsIssuer::new_short_keys(None);
        let offering: BbsCredentialOffer = serde_json::from_str(EXAMPLE_CREDENTIAL_OFFERING)?;
        let schema: CredentialSchema = serde_json::from_str(EXAMPLE_CREDENTIAL_SCHEMA)?;
        let secret = BbsProver::new_link_secret();
        let mut credential_values = HashMap::new();
        credential_values.insert("test_property_string".to_owned(), "value".to_owned());

        return Ok((dpk, sk, offering, schema, secret, credential_values));
    }

    #[test]
    fn can_propose_credential() {
        let proposal = Prover::propose_credential(&ISSUER_DID, &HOLDER_DID, "schemadid");
        assert_eq!(&proposal.subject, &HOLDER_DID);
        assert_eq!(&proposal.issuer, &ISSUER_DID);
        assert_eq!(&proposal.schema, "schemadid");
        assert_eq!(&proposal.r#type, CREDENTIAL_PROPOSAL_TYPE);
    }

    #[test]
    fn can_request_credential() -> Result<(), Box<dyn Error>> {
        let (dpk, _, offering, schema, secret, credential_values) = setup_test()?;
        let (credential_request, _) =
            Prover::request_credential(&offering, &schema, &secret, credential_values, &dpk)
                .map_err(|e| format!("{}", e))?;
        assert_eq!(credential_request.schema, schema.id);
        assert_eq!(credential_request.subject, offering.subject);
        assert_eq!(credential_request.r#type, CREDENTIAL_REQUEST_TYPE);
        Ok(())
    }

    #[test]
    fn throws_when_omitting_required_credential_value() -> Result<(), Box<dyn Error>> {
        let (dpk, _, offering, schema, secret, mut credential_values) = setup_test()?;
        credential_values.remove("test_property_string");
        match Prover::request_credential(&offering, &schema, &secret, credential_values, &dpk) {
            Ok(_) => assert!(false),
            Err(e) => assert_eq!(
                format!("{}", e),
                "Cannot request credential: Missing required schema property: test_property_string"
            ),
        }
        Ok(())
    }

    #[test]
    fn can_finish_credential() -> Result<(), Box<dyn Error>> {
        let unfinished_credential: UnfinishedBbsCredential =
            serde_json::from_str(&UNFINISHED_CREDENTIAL)?;
        let master_secret: SignatureMessage =
            SignatureMessage::from(base64::decode(&MASTER_SECRET)?.into_boxed_slice());
        let nquads: Vec<String> = NQUADS.iter().map(|q| q.to_string()).collect();
        let public_key: DeterministicPublicKey =
            DeterministicPublicKey::from(base64::decode(&PUB_KEY)?.into_boxed_slice());
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
                assert!(base64::decode(cred.proof.signature).is_ok());
            }
            Err(e) => {
                assert!(false, "Unexpected error when finishing credential: {}", e);
            }
        }

        Ok(())
    }
}
