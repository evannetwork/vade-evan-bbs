use super::datatypes::{BbsCredentialRequest, CredentialOffer, CredentialSchema};
use bbs::SignatureMessage;
use std::collections::HashMap;

pub struct Prover {}

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
        credential_offering: CredentialOffer,
        credential_schema: CredentialSchema,
        master_secret: SignatureMessage,
        credential_values: HashMap<String, String>,
    ) -> Result<(CredentialRequest, CredentialSecretsBlindingFactors), Box<dyn Error>> {
        for required in &credential_schema.required {
            if credential_values.get(required).is_none() {
                let error = format!("Missing required schema property; {}", required);
                return Err(Box::from(error));
            }
        }

        let crypto_cred_def = CryptoCredentialDefinition {
            public_key: credential_definition.public_key,
            credential_key_correctness_proof: credential_definition.public_key_correctness_proof,
        };

        let encoded_credential_values = Prover::encode_values(credential_values)?;

        let (crypto_cred_request, blinding_factors) = CryptoProver::request_credential(
            &credential_offering.subject,
            &encoded_credential_values,
            master_secret,
            crypto_cred_def,
            credential_offering.nonce,
        )?;

        Ok((
            BbsCredentialRequest {
                blinded_credential_secrets: crypto_cred_request.blinded_credential_secrets,
                blinded_credential_secrets_correctness_proof: crypto_cred_request
                    .blinded_credential_secrets_correctness_proof,
                credential_definition: credential_definition.id,
                credential_nonce: crypto_cred_request.credential_nonce,
                schema: credential_definition.schema,
                subject: credential_offering.subject,
                r#type: "EvanZKPCredentialRequest".to_string(),
                credential_values: encoded_credential_values,
            },
            blinding_factors,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_request_credential() {
        let credential_request = Prover::request_credential();
        assert_eq!(credential_request.subject, "");
    }
}
