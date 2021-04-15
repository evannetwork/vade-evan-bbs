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
use std::{error::Error, panic};
use uuid::Uuid;

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
    let key_bytes = decode_base64(nonce)?.into_boxed_slice();
    let key = panic::catch_unwind(|| ProofNonce::from(key_bytes))
        .map_err(|_| format!("Error parsing nonce, invalid sequence"))?;

    return Ok(key);
}

pub fn get_dpk_from_string(dpk: &str) -> Result<DeterministicPublicKey, Box<dyn Error>> {
    let nonce_bytes = decode_base64(dpk)?.into_boxed_slice();
    let nonce = panic::catch_unwind(|| DeterministicPublicKey::from(nonce_bytes))
        .map_err(|_| format!("Error parsing key, invalid sequence"))?;

    return Ok(nonce);
}

#[allow(dead_code)]
pub fn get_signature_message_from_string(dpk: &str) -> Result<SignatureMessage, Box<dyn Error>> {
    let msg_bytes = base64::decode(dpk)?.into_boxed_slice();
    let msg = panic::catch_unwind(|| SignatureMessage::from(msg_bytes))
        .map_err(|_| format!("Error parsing signature message, invalid sequence"))?;

    return Ok(msg);
}

#[allow(dead_code)]
pub fn decode_base64(encoded: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let decoded = base64::decode(encoded)
        .map_err(|_| format!("Error interpreting given string as base64. Wrong encoding?"))?;

    Ok(decoded)
}

#[allow(dead_code)]
pub fn decode_base64_config(encoded: &str, config: Config) -> Result<Vec<u8>, Box<dyn Error>> {
    let decoded = base64::decode_config(encoded, config)
        .map_err(|_| format!("Error interpreting given string as base64. Wrong encoding?"))?;

    Ok(decoded)
}
