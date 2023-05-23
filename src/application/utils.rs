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

use base64::Config;
use bbs::{keys::DeterministicPublicKey, ProofNonce, SignatureMessage};
#[cfg(not(target_arch = "wasm32"))]
use chrono::Utc;
use serde::Serialize;
use ssi_json_ld::{json_to_dataset, urdna2015::normalize, JsonLdOptions, StaticLoader};
use std::{collections::HashMap, error::Error, panic};
use uuid::Uuid;

use crate::{BbsProofRequest, BbsSubProofRequest, UnsignedBbsCredential};

pub fn get_now_as_iso_string() -> String {
    #[cfg(target_arch = "wasm32")]
    return js_sys::Date::new_0().to_iso_string().to_string().into();
    #[cfg(not(target_arch = "wasm32"))]
    return Utc::now().format("%Y-%m-%dT%H:%M:%S.000Z").to_string();
}

pub fn generate_uuid() -> String {
    return format!("{}", Uuid::new_v4());
}

pub fn get_nonce_from_string(nonce: &str) -> Result<ProofNonce, Box<dyn Error>> {
    let key_bytes = decode_base64(nonce, "Nonce")?.into_boxed_slice();
    let key = panic::catch_unwind(|| ProofNonce::from(key_bytes))
        .map_err(|_| format!("Error parsing nonce, invalid sequence"))?;

    return Ok(key);
}

pub fn get_dpk_from_string(dpk: &str) -> Result<DeterministicPublicKey, Box<dyn Error>> {
    let nonce_bytes = decode_base64(dpk, "Deterministic public key")?.into_boxed_slice();
    let nonce = panic::catch_unwind(|| DeterministicPublicKey::from(nonce_bytes))
        .map_err(|_| format!("Error parsing key, invalid sequence"))?;

    return Ok(nonce);
}

#[allow(dead_code)]
pub fn get_signature_message_from_string(sig: &str) -> Result<SignatureMessage, Box<dyn Error>> {
    let msg_bytes = decode_base64(sig, "Signature Message")?.into_boxed_slice();
    let msg = panic::catch_unwind(|| SignatureMessage::from(msg_bytes))
        .map_err(|_| format!("Error parsing signature message, invalid sequence"))?;

    return Ok(msg);
}

#[allow(dead_code)]
pub fn decode_base64<T: AsRef<[u8]>>(
    encoded: T,
    error_message_context: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let decoded = base64::decode(encoded).map_err(|_| {
        format!(
            "Error interpreting {} as base64. Wrong encoding?",
            error_message_context
        )
    })?;

    Ok(decoded)
}

#[allow(dead_code)]
pub fn decode_base64_config<T: AsRef<[u8]>>(
    encoded: T,
    config: Config,
    error_message_context: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let decoded = base64::decode_config(encoded, config).map_err(|_| {
        format!(
            "Error interpreting {} as base64. Wrong encoding?",
            error_message_context
        )
    })?;

    Ok(decoded)
}

pub async fn convert_to_nquads(document_string: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let mut loader = StaticLoader;
    let options = JsonLdOptions {
        base: None,           // -b, Base IRI
        expand_context: None, // -c, IRI for expandContext option
        ..Default::default()
    };
    let dataset = json_to_dataset(
        &document_string,
        None, // will be patched into @context, e.g. Some(&r#"["https://schema.org/"]"#.to_string()),
        false,
        Some(&options),
        &mut loader,
    )
    .await
    .map_err(|err| err.to_string())?;
    let dataset_normalized = normalize(&dataset).map_err(|err| err.to_string())?;
    let normalized = dataset_normalized
        .to_nquads()
        .map_err(|err| err.to_string())?;
    let non_empty_lines = normalized
        .split("\n")
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    Ok(non_empty_lines)
}

#[allow(dead_code)]
pub async fn convert_to_credential_nquads<T>(credential: &T) -> Result<Vec<String>, Box<dyn Error>>
where
    T: Serialize,
{
    let unfinished_without_proof: UnsignedBbsCredential =
        serde_json::from_str(&serde_json::to_string(&credential)?)?;
    convert_to_nquads(&serde_json::to_string(&unfinished_without_proof)?).await
}

pub async fn get_nquads_schema_map(
    proof_request: &BbsProofRequest,
    unsigned_credentials: &Vec<UnsignedBbsCredential>,
    only_revealed: bool,
) -> Result<HashMap<String, Vec<String>>, Box<dyn Error>> {
    let mut credential_schema_map: HashMap<String, &UnsignedBbsCredential> = HashMap::new();
    for credential in unsigned_credentials {
        credential_schema_map.insert(credential.credential_schema.id.to_owned(), credential);
    }
    let mut nquads_schema_map: HashMap<String, Vec<String>> = HashMap::new();

    for BbsSubProofRequest {
        schema: requested_schema,
        revealed_attributes,
        ..
    } in &proof_request.sub_proof_requests
    {
        let credential = *credential_schema_map.get(requested_schema).ok_or_else(|| {
            format!(
                r#"schema "{}" not provided in credentials"#,
                &requested_schema
            )
        })?;

        let mut unfinished_without_proof: UnsignedBbsCredential =
            serde_json::from_str(&serde_json::to_string(&credential)?)?;

        // patch values from credential in presentation into draft credential for nquads
        for (key, value) in credential.credential_subject.data.iter() {
            unfinished_without_proof
                .credential_subject
                .data
                .insert(key.to_owned(), value.to_owned());
        }

        let nquads = convert_to_nquads(&serde_json::to_string(&unfinished_without_proof)?).await?;

        let attributes: Vec<String>;
        if only_revealed {
            attributes = revealed_attributes
                .iter()
                .map(|i| {
                    nquads
                        .get(*i - 1)
                        .ok_or_else(|| Box::from(format!(
                            r#"revealed attribute "{}" of schema "{}" could not be found in provided attribute nquads with length {}"#,
                            *i - 1,
                            &requested_schema,
                            &nquads.len(),
                        )))
                        .map(|value| value.to_owned())
                })
                .collect::<Result<Vec<String>, Box<dyn Error>>>()?;
        } else {
            attributes = nquads;
        }
        nquads_schema_map.insert(requested_schema.to_owned(), attributes);
    }

    Ok(nquads_schema_map)
}

/// Concatenates the revealed statements vector from proof request and required revealed statements vector
/// from credential proof to get all the indices need to be revealed in the presentation.
///
/// # Arguments
/// * `required_revealed_statements` - vec of required revealed indices
/// * `revealed_statements` - vec of requested revealed indices
///
/// # Returns
/// * `Vec<usize>` - A vector containing all the indices to be revealed by presentation
pub fn concate_required_and_reveal_statements(
    required_reveal_statements: Vec<u32>,
    revealed_statements: Vec<usize>,
) -> Result<Vec<usize>, Box<dyn Error>> {
    let mut all_revealed_statements: Vec<usize> = vec![];
    for required_index in required_reveal_statements {
        if required_index == 0 {
            return Err(Box::from(
                "Invalid reveal index, index 0 can't be revealed",
            ));
        }
        all_revealed_statements.push(required_index as usize);
    }

    for revealed_index in revealed_statements {
        if !all_revealed_statements.contains(&revealed_index) {
            all_revealed_statements.push(revealed_index);
        }
    }
    all_revealed_statements.sort();
    Ok(all_revealed_statements)
}

/// Checks if the required revealed statements are containing 0 index (master_secret)
/// Throws error if it contains the index 0 as required reveal index.
///
/// # Arguments
/// * `required_revealed_statements` - vec of required revealed indices
pub fn check_for_requird_reveal_index0(
    required_revealed_statements: &Vec<u32>,
) -> Result<(), Box<dyn Error>> {
    match required_revealed_statements
        .into_iter()
        .find(|index| **index == 0)
        .is_some()
    {
        true => Err(Box::from(
            "Invalid required_revealed_index, index 0 can't be revealed".to_owned(),
        )),
        false => Ok(()),
    }
}
