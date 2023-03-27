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
use regex::Regex;
use serde::Serialize;
use ssi_json_ld::{json_to_dataset, urdna2015::normalize, JsonLdOptions, StaticLoader};
use std::{collections::HashMap, error::Error, panic};
use uuid::Uuid;

use crate::{BbsProofRequest, ProofPresentation, UnsignedBbsCredential};

const NQUAD_REGEX: &str = r"^_:c14n0 <http://schema.org/([^>]+?)>";

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
    let dataset_normalized = normalize(&dataset).unwrap();
    let normalized = dataset_normalized.to_nquads().unwrap();
    let non_empty_lines = normalized
        .split("\n")
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    Ok(non_empty_lines)
}

pub async fn convert_to_credential_nquads<T>(credential: &T) -> Result<Vec<String>, Box<dyn Error>>
where
    T: Serialize,
{
    let unfinished_without_proof: UnsignedBbsCredential =
        serde_json::from_str(&serde_json::to_string(&credential)?)?;
    convert_to_nquads(&serde_json::to_string(&unfinished_without_proof)?).await
}

pub fn get_credential_values(nquads: &Vec<String>) -> Result<Vec<String>, Box<dyn Error>> {
    let regex = Regex::new(NQUAD_REGEX).map_err(|err| err.to_string())?;

    Ok(nquads
        .iter()
        .filter(|n| regex.is_match(&n))
        .map(|n| n.to_owned())
        .collect::<Vec<_>>())
}

pub async fn get_nquads_schema_map(
    proof_request: &BbsProofRequest,
    unsigned_credentials: &Vec<UnsignedBbsCredential>,
    only_revealed: bool,
) -> Result<HashMap<String, Vec<String>>, Box<dyn Error>> {
    let schema_vec: Vec<String> = proof_request
        .sub_proof_requests
        .iter()
        .map(|spr| spr.schema.to_owned())
        .collect();
    let mut nquads_schema_map: HashMap<String, Vec<String>> = HashMap::new();
    // for now test with one schema to avoid future madness
    // let schema_vec: Vec<String> = schemas.clone().cloned().collect();
    let schema: String = schema_vec.get(0).unwrap().to_owned();
    let credential = unsigned_credentials.get(0).unwrap().to_owned();
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
    let mut credential_values_nquads = get_credential_values(&nquads)?;
    credential_values_nquads.sort();

    let attributes: Vec<String>;
    if only_revealed {
        attributes = proof_request
            .sub_proof_requests
            .get(0)
            .unwrap()
            .revealed_attributes
            .iter()
            .map(|i| credential_values_nquads.get(*i - 1).unwrap().to_owned())
            .collect();
    } else {
        attributes = credential_values_nquads;
    }
    nquads_schema_map.insert(schema, attributes);

    Ok(nquads_schema_map)
}
