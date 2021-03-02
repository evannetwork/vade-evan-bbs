use crate::application::datatypes::{
    BbsCredential, BbsCredentialOffer, BbsCredentialRequest, CredentialProposal, CredentialSchema,
    CREDENTIAL_OFFER_TYPE,
};
use bbs::{issuer::Issuer as BbsIssuer, keys::SecretKey};
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
        credential_request: BbsCredentialRequest,
        private_key: SecretKey,
        credential_schema: CredentialSchema,
    ) -> Result<BbsCredential, Box<dyn Error>> {
        Ok(BbsCredential {})
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
    fn fails_on_wrong_issuer() -> Result<(), Box<dyn Error>> {
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
