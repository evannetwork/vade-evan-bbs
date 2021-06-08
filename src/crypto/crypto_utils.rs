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

use crate::application::{
    datatypes::AssertionProof,
    utils::{decode_base64_config, get_now_as_iso_string},
};
use base64;
use secp256k1::{recover, Message, RecoveryId, Signature};
use serde::{Deserialize, Serialize};
use serde_json::{value::RawValue, Value};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::{convert::TryInto, error::Error};
use vade::ResultSyncifier;
use vade_evan_substrate::signing::Signer;

#[derive(Serialize, Deserialize, Debug)]
pub struct JwsData<'a> {
    #[serde(borrow)]
    pub doc: &'a RawValue,
}

/// Creates proof for VC document
///
/// # Arguments
/// * `vc` - vc to create proof for
/// * `verification_method` - issuer of VC
/// * `private_key` - private key to create proof as 32B hex string
/// * `signer` - `Signer` to sign with
///
/// # Returns
/// * `AssertionProof` - Proof object containing a JWT and metadata
pub async fn create_assertion_proof(
    document_to_sign: &Value,
    verification_method: &str,
    issuer: &str,
    private_key: &str,
    signer: &Box<dyn Signer + Send + Sync>,
) -> Result<AssertionProof, Box<dyn Error>> {
    // create to-be-signed jwt
    let header_str = r#"{"typ":"JWT","alg":"ES256K-R"}"#;
    let padded = base64::encode_config(header_str.as_bytes(), base64::URL_SAFE);
    let header_encoded = padded.trim_end_matches('=');

    let now = get_now_as_iso_string();

    // build data object and hash
    let mut data_json: Value = serde_json::from_str("{}")?;
    let doc_clone: Value = document_to_sign.clone();
    data_json["iat"] = Value::from(now.clone());
    data_json["doc"] = doc_clone;
    data_json["iss"] = Value::from(issuer);
    let padded = base64::encode_config(format!("{}", &data_json).as_bytes(), base64::URL_SAFE);
    let data_encoded = padded.trim_end_matches('=');

    // create hash of data (including header)
    let header_and_data = format!("{}.{}", header_encoded, data_encoded);
    let mut hasher = Sha256::new();
    hasher.input(&header_and_data);
    let hash = hasher.result();

    // sign this hash
    let hash_arr: [u8; 32] = hash.try_into().map_err(|_| "slice with incorrect length")?;
    let message = format!("0x{}", &hex::encode(hash_arr));
    let (sig_and_rec, _): ([u8; 65], _) = signer
        .sign_message(&message, &private_key)
        .await
        .syncify()?;
    let padded = base64::encode_config(&sig_and_rec, base64::URL_SAFE);
    let sig_base64url = padded.trim_end_matches('=');

    // build proof property as serde object
    let jws: String = format!("{}.{}", &header_and_data, sig_base64url);

    let proof = AssertionProof {
        r#type: "EcdsaPublicKeySecp256k1".to_string(),
        created: now,
        proof_purpose: "assertionMethod".to_string(),
        verification_method: verification_method.to_string(),
        jws,
    };

    Ok(proof)
}

/// Checks given Vc document.
/// A Vc document is considered as valid if returning ().
/// Resolver may throw to indicate
/// - that it is not responsible for this Vc
/// - that it considers this Vc as invalid
///
/// Currently the test `vc_id` `"test"` is accepted as valid.
///
/// # Arguments
///
/// * `vc_id` - vc_id to check document for
/// * `value` - value to check
pub fn check_assertion_proof(
    vc_document: &str,
    signer_address: &str,
) -> Result<(), Box<dyn Error>> {
    let mut vc: Value = serde_json::from_str(vc_document)?;
    if vc["proof"].is_null() {
        Ok(())
    } else {
        // separate proof and vc document (vc document will be a Map after this)
        let vc_without_proof = vc
            .as_object_mut()
            .ok_or("could not get vc object as mutable")?;
        let vc_proof = vc_without_proof
            .remove("proof")
            .ok_or("could not remove proof from vc")?;

        // recover address and payload text (pure jwt format)
        let (address, decoded_payload_text) = recover_address_and_data(
            vc_proof["jws"]
                .as_str()
                .ok_or("could not get jws from vc proof")?,
        )?;

        let jws: JwsData = serde_json::from_str(&decoded_payload_text)?;
        let doc = jws.doc.get();
        // parse recovered vc document into serde Map
        let parsed_caps1: Value = serde_json::from_str(&doc)?;
        let parsed_caps1_map = parsed_caps1
            .as_object()
            .ok_or("could not get jws doc as object")?;
        // compare documents
        if vc_without_proof != parsed_caps1_map {
            return Err(Box::from(
                "recovered VC document and given VC document do not match",
            ));
        }

        let address = format!("0x{}", address);
        let _key_to_use = vc_proof["verificationMethod"]
            .as_str()
            .ok_or("could not get verificationMethod from proof")?;
        if address != signer_address {
            return Err(Box::from(
                "recovered and signing given address do not match",
            ));
        }

        Ok(())
    }
}

/// Recovers Ethereum address of signer and data part of a jwt.
///
/// # Arguments
/// * `jwt` - jwt as str&
///
/// # Returns
/// * `(String, String)` - (Address, Data) tuple
pub fn recover_address_and_data(jwt: &str) -> Result<(String, String), Box<dyn Error>> {
    // jwt text parsing
    let split: Vec<&str> = jwt.split('.').collect();
    let (header, data, signature) = (split[0], split[1], split[2]);
    let header_and_data = format!("{}.{}", header, data);

    // recover data for later checks
    let data_decoded = match decode_base64_config(data.as_bytes(), base64::URL_SAFE, "") {
        Ok(decoded) => decoded,
        Err(_) => {
            match decode_base64_config(&format!("{}=", data).as_bytes(), base64::URL_SAFE, "") {
                Ok(decoded) => decoded,
                Err(_) => {
                    match decode_base64_config(
                        &format!("{}==", data).as_bytes(),
                        base64::URL_SAFE,
                        "",
                    ) {
                        Ok(decoded) => decoded,
                        Err(_) => decode_base64_config(
                            &format!("{}===", data).as_bytes(),
                            base64::URL_SAFE,
                            "JWT Data",
                        )?,
                    }
                }
            }
        }
    };
    let data_string = String::from_utf8(data_decoded)?;

    // decode signature for validation
    let signature_decoded = match decode_base64_config(signature.as_bytes(), base64::URL_SAFE, "") {
        Ok(decoded) => decoded,
        Err(_) => {
            match decode_base64_config(format!("{}=", signature).as_bytes(), base64::URL_SAFE, "") {
                Ok(decoded) => decoded,
                Err(_) => decode_base64_config(
                    format!("{}==", signature).as_bytes(),
                    base64::URL_SAFE,
                    "JWT Data",
                )?,
            }
        }
    };

    // create hash of data (including header)
    let mut hasher = Sha256::new();
    hasher.input(&header_and_data);
    let hash = hasher.result();

    // prepare arguments for public key recovery
    let hash_arr: [u8; 32] = hash
        .try_into()
        .map_err(|_| "header_and_data hash invalid")?;
    let ctx_msg = Message::parse(&hash_arr);
    let mut signature_array = [0u8; 64];
    signature_array[..64].clone_from_slice(&signature_decoded[..64]);
    // slice signature and recovery for recovery
    let ctx_sig = Signature::parse(&signature_array);
    let signature_normalized = if signature_decoded[64] < 27 {
        signature_decoded[64]
    } else {
        signature_decoded[64] - 27
    };
    let recovery_id = RecoveryId::parse(signature_normalized)?;

    // recover public key, build ethereum address from it
    let recovered_key = recover(&ctx_msg, &ctx_sig, &recovery_id)?;
    let mut hasher = Keccak256::new();
    hasher.input(&recovered_key.serialize()[1..65]);
    let hash = hasher.result();
    let address = hex::encode(&hash[12..32]);

    Ok((address, data_string))
}
