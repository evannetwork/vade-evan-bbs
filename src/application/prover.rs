use super::datatypes::{
    BbsCredentialRequest, CredentialOffer, CredentialSchema, CREDENTIAL_REQUEST_TYPE,
};
use crate::crypto::crypto_prover::CryptoProver;
use bbs::{keys::DeterministicPublicKey, SignatureBlinding, SignatureMessage};
use std::collections::HashMap;
use std::error::Error;

pub struct Prover {}

// TODO: Add error class

impl Prover {
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
        credential_offering: &CredentialOffer,
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
        let (blind_signature_context, blinding) = CryptoProver::create_blind_signature_context(
            &issuer_pub_key,
            &credential_schema,
            &master_secret,
            &credential_offering.nonce,
        )
        .map_err(|e| format!("Could not create signature blinding: {}", e))?;

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_data::vc_zkp::{EXAMPLE_CREDENTIAL_OFFERING, EXAMPLE_CREDENTIAL_SCHEMA};
    use bbs::issuer::Issuer as BbsIssuer;
    use bbs::prover::Prover as BbsProver;

    fn setup_test() -> Result<
        (
            DeterministicPublicKey,
            CredentialOffer,
            CredentialSchema,
            SignatureMessage,
            HashMap<String, String>,
        ),
        Box<dyn Error>,
    > {
        let (dpk, _) = BbsIssuer::new_short_keys(None);
        let offering: CredentialOffer = serde_json::from_str(EXAMPLE_CREDENTIAL_OFFERING)?;
        let schema: CredentialSchema = serde_json::from_str(EXAMPLE_CREDENTIAL_SCHEMA)?;
        let secret = BbsProver::new_link_secret();
        let mut credential_values = HashMap::new();
        credential_values.insert("test_property_string".to_owned(), "value".to_owned());

        return Ok((dpk, offering, schema, secret, credential_values));
    }

    #[test]
    fn can_request_credential() -> Result<(), Box<dyn Error>> {
        let (dpk, offering, schema, secret, credential_values) = setup_test()?;
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
        let (dpk, offering, schema, secret, mut credential_values) = setup_test()?;
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
}
