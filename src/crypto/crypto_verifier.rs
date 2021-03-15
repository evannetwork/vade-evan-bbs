use crate::application::datatypes::{
    BbsCredential, RevocationListCredential,
};
use std::error::Error;
use std::io::prelude::*;

use flate2::read::GzDecoder;

pub struct CryptoVerifier {}

impl CryptoVerifier {
    /// Checks if a given credential is revoked in the given revocation list
    ///
    /// # Arguments
    /// * `credential` - BbsCredential which has to be checked
    /// * `revocation_list` - Revocation list the credential belongs to
    ///
    /// # Returns
    /// * `bool` - bool value if the credential is revoked or not

    pub fn is_revoked(
        credential: &BbsCredential,
        revocation_list: &RevocationListCredential
    ) -> Result<bool, Box<dyn Error>> {

        let encoded_list = base64::decode_config(revocation_list.credential_subject.encoded_list.to_string(),base64::URL_SAFE)?;
        let mut decoder = GzDecoder::new(&encoded_list[..]);
        let mut decoded_list = Vec::new();
        decoder.read_to_end(&mut decoded_list)?;

        let revocation_list_index_number = credential.credential_status.revocation_list_index
            .parse::<usize>()
            .map_err(|e| format!("Error parsing revocation_list_id: {}", e))?;

        let byte_index_float: f32 = (revocation_list_index_number / 8) as f32;
        let byte_index: usize = byte_index_float.floor() as usize;
        let revoked = decoded_list[byte_index] & (1 << (revocation_list_index_number % 8)) != 0;
        Ok(revoked)

    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_data::bbs_coherent_context_test_data::{
        FINISHED_CREDENTIAL, REVOCATION_LIST_CREDENTIAL, REVOCATION_LIST_CREDENTIAL_REVOKED_ID_1
    };

    #[test]
    fn can_check_not_revoked_credential() -> Result<(), Box<dyn Error>> {
        let credential: BbsCredential = serde_json::from_str(&FINISHED_CREDENTIAL)?;
        let revocation_list: RevocationListCredential = serde_json::from_str(&REVOCATION_LIST_CREDENTIAL)?;

        match CryptoVerifier::is_revoked(&credential, &revocation_list) {
            Ok(revoked) => assert_eq!(false, revoked),
            Err(e) => assert!(false, "Unexpected error: {}", e),
        };
        Ok(())
    }

    #[test]
    fn can_check_revoked_credential() -> Result<(), Box<dyn Error>> {
        let credential: BbsCredential = serde_json::from_str(&FINISHED_CREDENTIAL)?;
        let revocation_list: RevocationListCredential = serde_json::from_str(&REVOCATION_LIST_CREDENTIAL_REVOKED_ID_1)?;

        match CryptoVerifier::is_revoked(&credential, &revocation_list) {
            Ok(revoked) => assert_eq!(true, revoked),
            Err(e) => assert!(false, "Unexpected error: {}", e),
        };
        Ok(())
    }
}