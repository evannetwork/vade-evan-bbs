use std::collections::HashMap;

pub fn canonicalize_credential_value_keys(
    credential_values: &HashMap<String, String>,
) -> Vec<String> {
    let mut keys: Vec<String> = credential_values.keys().map(|k| k.to_owned()).collect();
    keys.sort();

    return keys;
}
