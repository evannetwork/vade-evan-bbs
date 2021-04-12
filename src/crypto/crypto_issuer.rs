/*
  Copyright (c) 2018-present evan GmbH.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

use bbs::{
    issuer::Issuer as BbsIssuer,
    keys::{DeterministicPublicKey, SecretKey},
    signature::BlindSignature,
    BlindSignatureContext,
    HashElem,
    ProofNonce,
    SignatureMessage,
};
use std::{collections::BTreeMap, error::Error};

pub struct CryptoIssuer {}

impl CryptoIssuer {
    pub fn create_signature(
        blind_signature_context: &BlindSignatureContext,
        signing_nonce: &ProofNonce,
        credential_values: Vec<String>,
        issuer_public_key: &DeterministicPublicKey,
        issuer_secret_key: &SecretKey,
    ) -> Result<BlindSignature, Box<dyn Error>> {
        let mut messages: BTreeMap<usize, SignatureMessage> = BTreeMap::new();
        let mut i = 1; // 0 is always reserved for master secret
        for value in &credential_values {
            let message = SignatureMessage::hash(value);
            messages.insert(i, message);
            i += 1;
        }

        let pub_key = issuer_public_key
            .to_public_key(credential_values.len() + 1/* +1 for master secret */)
            .map_err(|_| "Error creating signature: Schema for blinded signature context does not match provided values")?;

        let signature = BbsIssuer::blind_sign(
            blind_signature_context,
            &messages,
            issuer_secret_key,
            &pub_key,
            signing_nonce,
        )
        .map_err(|e| format!("Cannot create signature: {}", e))?;

        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::crypto_prover::CryptoProver;
    use bbs::prover::Prover as BbsProver;

    #[test]
    fn can_create_signature() -> Result<(), Box<dyn Error>> {
        let (dpk, sk) = BbsIssuer::new_short_keys(None);

        // Prover
        let master_secret = BbsProver::new_link_secret();
        let nonce = BbsIssuer::generate_signing_nonce();
        let (blind_signature_context, _) = CryptoProver::create_blind_signature_context(
            &dpk,
            &master_secret,
            &nonce,
            2, /*sent by issuer in credential offering*/
        )?;

        // Issuer
        let mut values = Vec::new();
        values.insert(0, "test_property_string: test_value".to_owned());
        let signature =
            CryptoIssuer::create_signature(&blind_signature_context, &nonce, values, &dpk, &sk);

        match signature {
            Ok(_) => assert!(true),
            Err(e) => return Err(Box::from(format!("{}", e))),
        }

        Ok(())
    }

    #[test]
    fn throws_when_providing_wrong_blinding_context() -> Result<(), Box<dyn Error>> {
        let (dpk, sk) = BbsIssuer::new_short_keys(None);
        let (dpk2, _) = BbsIssuer::new_short_keys(None);

        let master_secret = BbsProver::new_link_secret();
        let nonce = BbsIssuer::generate_signing_nonce();
        let (blind_signature_context, _) = CryptoProver::create_blind_signature_context(
            &dpk2,
            &master_secret,
            &nonce,
            2, /*sent by issuer in credential offering*/
        )?;

        let mut values = Vec::new();
        values.insert(0, "test_property_string: test_value".to_owned());
        values.insert(1, "property_not_included_in_schema: test_value".to_owned());
        let signature =
            CryptoIssuer::create_signature(&blind_signature_context, &nonce, values, &dpk, &sk);

        match signature {
            Ok(_) => {
                return Err(Box::from(
                    "Signature creation shouldn't succeed in this test",
                ))
            }
            Err(e) => {
                let message = format!("{}", e);
                assert_eq!(message.contains("Cannot create signature:"), true);
            }
        }
        Ok(())
    }
}
