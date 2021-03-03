use crate::{
    application::datatypes::{
        BbsCredential, BbsCredentialOffer, BbsCredentialRequest, CredentialProposal,
        CredentialSchema, UnfinishedBbsCredential, CREDENTIAL_OFFER_TYPE, CREDENTIAL_PROOF_PURPOSE,
        CREDENTIAL_SCHEMA_TYPE, CREDENTIAL_SIGNATURE_TYPE, DEFAULT_CREDENTIAL_CONTEXT,
    },
    crypto::crypto_issuer::CryptoIssuer,
};

use bbs::{
    issuer::Issuer as BbsIssuer,
    keys::{DeterministicPublicKey, SecretKey},
};
use std::error::Error;

use crate::application::{
    datatypes::{
        BbsCredentialSignature, BbsUnfinishedCredentialSignature, CredentialSchemaReference,
        CredentialSubject,
    },
    utils::{generate_uuid, get_now_as_iso_string},
};

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
        let nonce = BbsIssuer::generate_signing_nonce();

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
    ) -> Result<UnfinishedBbsCredential, Box<dyn Error>> {
        let credential_subject = CredentialSubject {
            id: subject_did.to_owned(),
            data,
        };

        let schema_reference = CredentialSchemaReference {
            id: credential_schema.id,
            r#type: CREDENTIAL_SCHEMA_TYPE.to_string(),
        };

        let blind_signature = CryptoIssuer::create_signature(
            &credential_request.blind_signature_context,
            &credential_offer.nonce,
            credential_request.credential_values.clone(),
            issuer_public_key,
            issuer_secret_key,
        )
        .map_err(|e| format!("Error creating bbs+ signature: {}", e))?;

        let credential_id = generate_uuid();

        let vc_signature = BbsUnfinishedCredentialSignature {
            r#type: CREDENTIAL_SIGNATURE_TYPE.to_string(),
            created: get_now_as_iso_string(),
            proof_purpose: CREDENTIAL_PROOF_PURPOSE.to_owned(),
            verification_method: issuer_public_key_id.to_owned(),
            required_reveal_statements: get_required_indices(
                credential_request.credential_values.clone(),
                &credential_schema,
            ),
            blind_signature: serde_json::to_string(&blind_signature)?,
        };

        let credential = UnfinishedBbsCredential {
            context: DEFAULT_CREDENTIAL_CONTEXT,
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
    use crate::application::datatypes::CredentialSchema;
    use crate::utils::test_data::{
        accounts::local::{HOLDER_DID, ISSUER_DID},
        vc_zkp::{EXAMPLE_CREDENTIAL_PROPOSAL, EXAMPLE_CREDENTIAL_SCHEMA},
    };

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
    fn can_issue_credential() -> Result<(), Box<dyn Error>> {
        let credential = Issuer::issue_credential();
        Ok(())
    }
}
