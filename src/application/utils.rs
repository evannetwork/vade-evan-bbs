use bbs::{keys::DeterministicPublicKey, ProofNonce, SignatureMessage};
#[cfg(not(target_arch = "wasm32"))]
use chrono::Utc;
use std::error::Error;
use std::panic;
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
    let key_bytes = base64::decode(nonce)?.into_boxed_slice();
    let key = panic::catch_unwind(|| ProofNonce::from(key_bytes))
        .map_err(|_| format!("Error parsing nonce, invalid sequence"))?;

    return Ok(key);
}

pub fn get_dpk_from_string(dpk: &str) -> Result<DeterministicPublicKey, Box<dyn Error>> {
    let nonce_bytes = base64::decode(dpk)?.into_boxed_slice();
    let nonce = panic::catch_unwind(|| DeterministicPublicKey::from(nonce_bytes))
        .map_err(|_| format!("Error parsing key, invalid sequence"))?;

    return Ok(nonce);
}

pub fn get_signature_message_from_string(dpk: &str) -> Result<SignatureMessage, Box<dyn Error>> {
    let msg_bytes = base64::decode(dpk)?.into_boxed_slice();
    let msg = panic::catch_unwind(|| SignatureMessage::from(msg_bytes))
        .map_err(|_| format!("Error parsing signature message, invalid sequence"))?;

    return Ok(msg);
}
