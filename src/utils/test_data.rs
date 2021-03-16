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

#[allow(dead_code)]
pub mod accounts {
    pub mod local {
        #[allow(dead_code)]
        pub const ISSUER_ADDRESS: &str = "0xd2787429c2a5d88662a8c4af690a4479e0199c5e";

        #[allow(dead_code)]
        pub const ISSUER_DID: &str = "did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6";

        pub const HOLDER_DID: &str = "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403901";

        pub const VERIFIER_DID: &str =
            "did:evan:testcore:0x1234512345123451234512345123451234512345";

        #[allow(dead_code)]
        pub const ISSUER_PRIVATE_KEY: &str =
            "30d446cc76b19c6eacad89237d021eb2c85144b61d63cb852aee09179f460920";

        #[allow(dead_code)]
        pub const ISSUER_PUBLIC_KEY_DID: &str =
            "did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6#key-1";

        #[allow(dead_code)]
        pub const SIGNER_1_ADDRESS: &str = "0xcd5e1dbb5552c2baa1943e6b5f66d22107e9c05c";

        #[allow(dead_code)]
        pub const SIGNER_1_DID: &str =
            "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906";

        #[allow(dead_code)]
        pub const SIGNER_1_DID_DOCUMENT_JWS: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOjE1OTM0OTg0MjYsImRpZERvY3VtZW50Ijp7IkBjb250ZXh0IjoiaHR0cHM6Ly93M2lkLm9yZy9kaWQvdjEiLCJpZCI6ImRpZDpldmFuOnRlc3Rjb3JlOjB4MGQ4NzIwNGMzOTU3ZDczYjY4YWUyOGQwYWY5NjFkM2M3MjQwMzkwNiIsInB1YmxpY0tleSI6W3siaWQiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDBkODcyMDRjMzk1N2Q3M2I2OGFlMjhkMGFmOTYxZDNjNzI0MDM5MDYja2V5LTEiLCJ0eXBlIjoiU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOCIsImNvbnRyb2xsZXIiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDBkODcyMDRjMzk1N2Q3M2I2OGFlMjhkMGFmOTYxZDNjNzI0MDM5MDYiLCJldGhlcmV1bUFkZHJlc3MiOiIweGNkNWUxZGJiNTU1MmMyYmFhMTk0M2U2YjVmNjZkMjIxMDdlOWMwNWMifV0sImF1dGhlbnRpY2F0aW9uIjpbImRpZDpldmFuOnRlc3Rjb3JlOjB4MGQ4NzIwNGMzOTU3ZDczYjY4YWUyOGQwYWY5NjFkM2M3MjQwMzkwNiNrZXktMSJdLCJjcmVhdGVkIjoiMjAyMC0wMy0yNFQwODozMToxMi4zODBaIiwidXBkYXRlZCI6IjIwMjAtMDYtMzBUMDY6Mjc6MDYuNzAxWiJ9LCJpc3MiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDBkODcyMDRjMzk1N2Q3M2I2OGFlMjhkMGFmOTYxZDNjNzI0MDM5MDYifQ._fBhoqongCEZBizR508XHUtBWtbHs0y440-BihDNp7qfWizGFINXgALPRoaSe5-rwsTSpD3L23H-VUSOQyibqAA";

        #[allow(dead_code)]
        pub const SIGNER_1_PRIVATE_KEY: &str =
            "dfcdcb6d5d09411ae9cbe1b0fd9751ba8803dd4b276d5bf9488ae4ede2669106";

        #[allow(dead_code)]
        pub const SIGNER_2_DID: &str =
            "did:evan:testcore:0xc88d707c2436fa3ce4a1e52d751469acae689fdb";

        #[allow(dead_code)]
        pub const SIGNER_2_PRIVATE_KEY: &str =
            "16bd56948ba09a626551b3f39093da305b347ef4ef2182b2e667dfa5aaa0d4cd";
    }

    pub mod remote {
        #[allow(dead_code)]
        pub const SIGNER_1_PRIVATE_KEY: &str = "a1c48241-5978-4348-991e-255e92d81f1e";

        #[allow(dead_code)]
        pub const SIGNER_1_SIGNED_MESSAGE_HASH: &str =
            "0x52091d1299031b18c1099620a1786363855d9fcd91a7686c866ad64f83de13ff";
    }
}

#[allow(dead_code)]
pub mod did {
    #[allow(dead_code)]
    pub const EXAMPLE_DID_1: &str = "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403901";

    #[allow(dead_code)]
    pub const EXAMPLE_DID_DOCUMENT_1: &str = r###"{
        "@context": "https://w3id.org/did/v1",
        "id": "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403901",
        "publicKey": [
            {
                "id": "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906#key-1",
                "type": "Secp256k1VerificationKey2018",
                "controller": "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906",
                "ethereumAddress": "0xcd5e1dbb5552c2baa1943e6b5f66d22107e9c05c"
            }
        ],
        "authentication": [
            "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906#key-1"
        ],
        "created": "2011-11-11T11:11:11.111Z",
        "updated": "2011-11-11T11:11:11.111Z"
    }"###;

    #[allow(dead_code)]
    pub const EXAMPLE_DID_DOCUMENT_2: &str = r###"{
        "@context": "https://w3id.org/did/v1",
        "id": "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403902",
        "publicKey": [
            {
                "id": "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906#key-1",
                "type": "Secp256k1VerificationKey2018",
                "controller": "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906",
                "ethereumAddress": "0xcd5e1dbb5552c2baa1943e6b5f66d22107e9c05c"
            }
        ],
        "authentication": [
            "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906#key-1"
        ],
        "created": "2022-22-22T22:22:22.222Z",
        "updated": "2022-22-22T22:22:22.222Z"
    }"###;
}

#[allow(dead_code)]
pub mod environment {
    #[allow(dead_code)]
    pub const DEFAULT_VADE_EVAN_SIGNING_URL: &str =
        "https://tntkeyservices-c43a.azurewebsites.net/key/sign";

    #[allow(dead_code)]
    pub const DEFAULT_VADE_EVAN_SUBSTRATE_IP: &str = "13.69.59.185";
}

#[allow(dead_code)]
pub mod vc_zkp {
    pub const EXAMPLE_CREDENTIAL_PROPOSAL: &str = r###"
    {
        "issuer": "did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6",
        "subject": "did:evan:testcore:0x67ce8b01b3b75a9ba4a1462139a1edaa0d2f539f",
        "type": "EvanCredentialProposal",
        "schema": "did:evan:schema:0x1ace8b01be3bca9ba4a1462130a1e0ad0d2f539f"
    }
    "###;
    pub const EXAMPLE_CREDENTIAL_OFFERING: &str = r###"
    {
        "issuer": "did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6",
        "subject": "did:evan:testcore:0x67ce8b01b3b75a9ba4a1462139a1edaa0d2f539f",
        "type": "EvanBbsCredentialOffering",
        "schema": "did:evan:schema:0x1ace8b01be3bca9ba4a1462130a1e0ad0d2f539f",
        "nonce": "WzM0LDIxNSwyNDEsODgsMTg2LDExMiwyOSwxNTksNjUsMjE1LDI0MiwxNjQsMTksOCwyMDEsNzgsNTUsMTA4LDE1NCwxMTksMTg0LDIyNCwyMjUsNDAsNDgsMTgwLDY5LDE3OCwxNDgsNSw1OSwxMTFd"
    }
    "###;

    #[allow(dead_code)]
    pub const EXAMPLE_CREDENTIAL_SCHEMA: &str = r###"
    {
        "id": "did:evan:zkp:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6",
        "type": "EvanVCSchema",
        "name": "test_schema",
        "author": "did:evan:testcore:0x0F737D1478eA29df0856169F25cA9129035d6FD1",
        "createdAt": "2020-05-19T12:54:55.000Z",
        "description": "Test description",
        "properties": {
            "test_property_string": {
                "type": "string"
            }
        },
        "required": [
            "test_property_string"
        ],
        "additionalProperties": false,
        "proof": {
            "type": "EcdsaPublicKeySecp256k1",
            "created": "2020-05-19T12:54:55.000Z",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "null",
            "jws": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOiIyMDIwLTA1LTE5VDEyOjU0OjU1LjAwMFoiLCJkb2MiOnsiaWQiOiJkaWQ6ZXZhbjp6a3A6MHgxMjM0NTEyMzQ1MTIzNDUxMjM0NTEyMzQ1MTIzNDUiLCJ0eXBlIjoiRXZhblZDU2NoZW1hIiwibmFtZSI6InRlc3Rfc2NoZW1hIiwiYXV0aG9yIjoiZGlkOmV2YW46dGVzdGNvcmU6MHgwRjczN0QxNDc4ZUEyOWRmMDg1NjE2OUYyNWNBOTEyOTAzNWQ2RkQxIiwiY3JlYXRlZEF0IjoiMjAyMC0wNS0xOVQxMjo1NDo1NS4wMDBaIiwiZGVzY3JpcHRpb24iOiJUZXN0IGRlc2NyaXB0aW9uIiwicHJvcGVydGllcyI6eyJ0ZXN0X3Byb3BlcnR5X3N0cmluZyI6eyJ0eXBlIjoic3RyaW5nIn19LCJyZXF1aXJlZCI6WyJ0ZXN0X3Byb3BlcnR5X3N0cmluZyJdLCJhZGRpdGlvbmFsUHJvcGVydGllcyI6ZmFsc2V9LCJpc3MiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDBGNzM3RDE0NzhlQTI5ZGYwODU2MTY5RjI1Y0E5MTI5MDM1ZDZGRDEifQ.byfS5tIbnCN1M4PtfQQ9mq9mR2pIzgmBFoFNrGkINJBDVxPmKC2S337a2ulytG0G9upyAuOWVMBXESxQdF_MjwA"
        }
    }"###;

    #[allow(dead_code)]
    pub const EXAMPLE_CREDENTIAL_SCHEMA_FIVE_PROPERTIES: &str = r###"
    {
        "id": "did:evan:zkp:0x123451234512345123451234512345",
        "type": "EvanVCSchema",
        "name": "test_schema_five_properties",
        "author": "did:evan:testcore:0x0F737D1478eA29df0856169F25cA9129035d6FD1",
        "createdAt": "2020-05-19T12:54:55.000Z",
        "description": "Test description",
        "properties": {
            "test_property_string": {
                "type": "string"
            },
            "test_property_string2": {
                "type": "string"
            },
            "test_property_string3": {
                "type": "string"
            },
            "test_property_string4": {
                "type": "string"
            }
        },
        "required": [
            "test_property_string"
        ],
        "additionalProperties": false,
        "proof": {
            "type": "EcdsaPublicKeySecp256k1",
            "created": "2020-05-19T12:54:55.000Z",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "null",
            "jws": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOiIyMDIwLTA1LTE5VDEyOjU0OjU1LjAwMFoiLCJkb2MiOnsiaWQiOiJkaWQ6ZXZhbjp6a3A6MHgxMjM0NTEyMzQ1MTIzNDUxMjM0NTEyMzQ1MTIzNDUiLCJ0eXBlIjoiRXZhblZDU2NoZW1hIiwibmFtZSI6InRlc3Rfc2NoZW1hIiwiYXV0aG9yIjoiZGlkOmV2YW46dGVzdGNvcmU6MHgwRjczN0QxNDc4ZUEyOWRmMDg1NjE2OUYyNWNBOTEyOTAzNWQ2RkQxIiwiY3JlYXRlZEF0IjoiMjAyMC0wNS0xOVQxMjo1NDo1NS4wMDBaIiwiZGVzY3JpcHRpb24iOiJUZXN0IGRlc2NyaXB0aW9uIiwicHJvcGVydGllcyI6eyJ0ZXN0X3Byb3BlcnR5X3N0cmluZyI6eyJ0eXBlIjoic3RyaW5nIn19LCJyZXF1aXJlZCI6WyJ0ZXN0X3Byb3BlcnR5X3N0cmluZyJdLCJhZGRpdGlvbmFsUHJvcGVydGllcyI6ZmFsc2V9LCJpc3MiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDBGNzM3RDE0NzhlQTI5ZGYwODU2MTY5RjI1Y0E5MTI5MDM1ZDZGRDEifQ.byfS5tIbnCN1M4PtfQQ9mq9mR2pIzgmBFoFNrGkINJBDVxPmKC2S337a2ulytG0G9upyAuOWVMBXESxQdF_MjwA"
        }
    }"###;

    #[allow(dead_code)]
    pub const EXAMPLE_REVOCATION_REGISTRY_DEFINITION_DID: &str =
        "did:evan:testcore:0x0F737D1478eA29df0856169F25cA9129035d6FD2";

    #[allow(dead_code)]
    pub const SCHEMA_DESCRIPTION: &str = "Test description";

    #[allow(dead_code)]
    pub const SCHEMA_NAME: &str = "test_schema";

    #[allow(dead_code)]
    pub const SCHEMA_PROPERTIES: &str = r###"{
        "test_property_string": {
            "type": "string"
        }
    }"###;

    #[allow(dead_code)]
    pub const SCHEMA_PROPERTIES_EXTENDED: &str = r###"{
        "test_property_string": {
            "type": "string"
        },
        "test_property_string2": {
            "type": "string"
        }
    }"###;

    #[allow(dead_code)]
    pub const SCHEMA_PROPERTIES_MORE_EXTENDED: &str = r###"{
        "test_property_string": {
            "type": "string"
        },
        "test_property_string2": {
            "type": "string"
        },
        "test_property_string3": {
            "type": "string"
        }
    }"###;

    #[allow(dead_code)]
    pub const SCHEMA_REQUIRED_PROPERTIES: &str = r###"[
        "test_property_string"
    ]"###;

    #[allow(dead_code)]
    pub const SUBJECT_DID: &str = "did:evan:testcore:0x0F737D1478eA29df0856169F25cA9129035d6FD2";
}

#[allow(dead_code)]
pub mod bbs_coherent_context_test_data {
    pub const UNFINISHED_CREDENTIAL: &str = r###"{
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https:://schema.org"
        ],
        "id": "9311f783-eda0-4f2d-8287-3816868193ef",
        "type": [
            "VerifiableCredential"
        ],
        "issuer": "did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6",
        "credentialSubject": {
            "id": "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403901",
            "data": {
                "test_property_string3": "value",
                "test_property_string4": "value",
                "test_property_string": "value",
                "test_property_string1": "value",
                "test_property_string2": "value"
            }
        },
        "credentialSchema": {
            "id": "did:evan:zkp:0x123451234512345123451234512345",
            "type": "EvanZKPSchema"
        },
        "credentialStatus": {
            "id": "did:evan:zkp:0x1234512345123451234512345123456789#1",
            "type": "RevocationList2020Status",
            "revocationListIndex": "1",
            "revocationListCredential": "did:evan:zkp:0x1234512345123451234512345123456789"
        },
        "proof": {
            "type": "BbsBlsSignature2020",
            "created": "2021-03-10T10:00:35.000Z",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6#key-1",
            "requiredRevealStatements": [
                1
            ],
            "blindSignature": "gnXpPqIUfwng9+vKO0wTOPJQixMU3GXJXhQC4nG9GvVxK1MAGWVAmYR+ahyQAr2FCtjfvcuBvkyfVMo87LrqV0z7WjlFrgU0FveR07T5XGFpgx5JGVziusqI6x26hZu3dX8M2YwEM9rhewmcH166ew=="
        }
    }"###;

    pub const FINISHED_CREDENTIAL: &str = r###"{
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https:://schema.org"
        ],
        "id": "9311f783-eda0-4f2d-8287-3816868193ef",
        "type": [
            "VerifiableCredential"
        ],
        "issuer": "did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6",
        "credentialSubject": {
            "id": "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403901",
            "data": {
                "test_property_string3": "value",
                "test_property_string": "value",
                "test_property_string4": "value",
                "test_property_string1": "value",
                "test_property_string2": "value"
            }
        },
        "credentialSchema": {
            "id": "did:evan:zkp:0x123451234512345123451234512345",
            "type": "EvanZKPSchema"
        },
        "credentialStatus": {
            "id": "did:evan:zkp:0x1234512345123451234512345123456789#1",
            "type": "RevocationList2020Status",
            "revocationListIndex": "1",
            "revocationListCredential": "did:evan:zkp:0x1234512345123451234512345123456789"
        },
        "proof": {
            "type": "BbsBlsSignature2020",
            "created": "2021-03-10T10:00:35.000Z",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6#key-1",
            "requiredRevealStatements": [
                1
            ],
            "signature": "gnXpPqIUfwng9+vKO0wTOPJQixMU3GXJXhQC4nG9GvVxK1MAGWVAmYR+ahyQAr2FCtjfvcuBvkyfVMo87LrqV0z7WjlFrgU0FveR07T5XGEGeJvR9qOZAeaJsaMyjeazgsuVhoKZT+NGh0AxQNqqJA=="
        }
    }"###;

    pub const NQUADS: [&'static str; 5] = [
        "test_property_string: value",
        "test_property_string1: value",
        "test_property_string2: value",
        "test_property_string3: value",
        "test_property_string4: value",
    ];

    pub const SECRET_KEY: &str = "Ilm14JX/ULRybFcHOq93gzDu5McYuX9L7AE052Sz5SQ=";

    pub const PUB_KEY: &str = "jCv7l26izalfcsFe6j/IqtVlDolo2Y3lNld7xOG63GjSNHBVWrvZQe2O859q9JeVEV4yXtfYofGQSWrMVfgH5ySbuHpQj4fSgLu4xXyFgMidUO1sIe0NHRcXpOorP01o";

    pub const MASTER_SECRET: &str = "OASkVMA8q6b3qJuabvgaN9K1mKoqptCv4SCNvRmnWuI=";

    pub const SIGNATURE_BLINDING: &str = "EOMk3AbkM49POp6NgaojAWEKLK/2k3gHZQw2lCF776o=";

    pub const EXAMPLE_REVOCATION_LIST_DID: &str =
        "did:evan:zkp:0x1234512345123451234512345123456789";

    pub const REVOCATION_LIST_CREDENTIAL: &str = r###"{
        "@context":[
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/vc-status-list-2021/v1"
        ],
        "id":"did:evan:zkp:0x1234512345123451234512345123456789",
        "type":[
            "VerifiableCredential",
            "StatusList2021Credential"
        ],
        "issuer":"did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6#key-1",
        "issued":"2021-03-15T06:53:13.000Z",
        "credentialSubject":{
            "id":"did:evan:zkp:0x1234512345123451234512345123456789#list",
            "type":"RevocationList2021",
            "encodedList":"H4sIAAAAAAAA_-3AMQEAAADCoPVPbQwfKAAAAAAAAAAAAAAAAAAAAOBthtJUqwBAAAA="
        },
        "proof":{
            "type":"EcdsaPublicKeySecp256k1",
            "created":"2021-03-15T06:53:13.000Z",
            "proofPurpose":"assertionMethod",
            "verificationMethod":"did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6#key-1",
            "jws":"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOiIyMDIxLTAzLTE1VDA2OjUzOjEzLjAwMFoiLCJkb2MiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3czaWQub3JnL3ZjLXN0YXR1cy1saXN0LTIwMjEvdjEiXSwiaWQiOiJkaWQ6ZXZhbjp6a3A6MHgxMjM0NTEyMzQ1MTIzNDUxMjM0NTEyMzQ1MTIzNDU2Nzg5IiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlN0YXR1c0xpc3QyMDIxQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDYyNDBjZWRmYzg0MDU3OWI3ZmRjZDY4NmJkYzY1YTlhOGM0MmRlYTYja2V5LTEiLCJpc3N1ZWQiOiIyMDIxLTAzLTE1VDA2OjUzOjEzLjAwMFoiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDpldmFuOnprcDoweDEyMzQ1MTIzNDUxMjM0NTEyMzQ1MTIzNDUxMjM0NTY3ODkjbGlzdCIsInR5cGUiOiJSZXZvY2F0aW9uTGlzdDIwMjEiLCJlbmNvZGVkTGlzdCI6Ikg0c0lBQUFBQUFBQV8tM0FNUUVBQUFEQ29QVlBiUXdmS0FBQUFBQUFBQUFBQUFBQUFBQUFBT0J0aHRKVXF3QkFBQUE9In19LCJpc3MiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDYyNDBjZWRmYzg0MDU3OWI3ZmRjZDY4NmJkYzY1YTlhOGM0MmRlYTYifQ.F98jOR5Cs9HEe4gz6RRc0Unnc-YkX_PUWs20eLrrlqgkN4g7OKNcAlxqo4ARPKU2oqWMq5NWO3Fj2rK8dMZnDQA"
        }
    }"###;

    pub const REVOCATION_LIST_CREDENTIAL_REVOKED_ID_1: &str = r###"{
        "@context":[
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/vc-status-list-2021/v1"
        ],
        "id":"did:evan:zkp:0x1234512345123451234512345123456789",
        "type":[
            "VerifiableCredential",
            "StatusList2021Credential"
        ],
        "issuer":"did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6#key-1",
        "issued":"2021-03-15T07:20:08.000Z",
        "credentialSubject":{
            "id":"did:evan:zkp:0x1234512345123451234512345123456789#list",
            "type":"RevocationList2021",
            "encodedList":"H4sIAAAAAAAA_-3AMQ0AAAACIGf_0MbwgQYAAAAAAAAAAAAAAAAAAAB4G7mHB0sAQAAA"
        },
        "proof":{
            "type":"EcdsaPublicKeySecp256k1",
            "created":"2021-03-15T07:20:08.000Z",
            "proofPurpose":"assertionMethod",
            "verificationMethod":"did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6#key-1",
            "jws":"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOiIyMDIxLTAzLTE1VDA3OjIwOjA4LjAwMFoiLCJkb2MiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3czaWQub3JnL3ZjLXN0YXR1cy1saXN0LTIwMjEvdjEiXSwiaWQiOiJkaWQ6ZXZhbjp6a3A6MHgxMjM0NTEyMzQ1MTIzNDUxMjM0NTEyMzQ1MTIzNDU2Nzg5IiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlN0YXR1c0xpc3QyMDIxQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDYyNDBjZWRmYzg0MDU3OWI3ZmRjZDY4NmJkYzY1YTlhOGM0MmRlYTYja2V5LTEiLCJpc3N1ZWQiOiIyMDIxLTAzLTE1VDA3OjIwOjA4LjAwMFoiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDpldmFuOnprcDoweDEyMzQ1MTIzNDUxMjM0NTEyMzQ1MTIzNDUxMjM0NTY3ODkjbGlzdCIsInR5cGUiOiJSZXZvY2F0aW9uTGlzdDIwMjEiLCJlbmNvZGVkTGlzdCI6Ikg0c0lBQUFBQUFBQV8tM0FNUTBBQUFBQ0lHZl8wTWJ3Z1FZQUFBQUFBQUFBQUFBQUFBQUFBQUI0RzdtSEIwc0FRQUFBIn0sInByb29mIjp7InR5cGUiOiJFY2RzYVB1YmxpY0tleVNlY3AyNTZrMSIsImNyZWF0ZWQiOiIyMDIxLTAzLTE1VDA2OjUzOjEzLjAwMFoiLCJwcm9vZlB1cnBvc2UiOiJhc3NlcnRpb25NZXRob2QiLCJ2ZXJpZmljYXRpb25NZXRob2QiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDYyNDBjZWRmYzg0MDU3OWI3ZmRjZDY4NmJkYzY1YTlhOGM0MmRlYTYja2V5LTEiLCJqd3MiOiJleUowZVhBaU9pSktWMVFpTENKaGJHY2lPaUpGVXpJMU5rc3RVaUo5LmV5SnBZWFFpT2lJeU1ESXhMVEF6TFRFMVZEQTJPalV6T2pFekxqQXdNRm9pTENKa2IyTWlPbnNpUUdOdmJuUmxlSFFpT2xzaWFIUjBjSE02THk5M2QzY3Vkek11YjNKbkx6SXdNVGd2WTNKbFpHVnVkR2xoYkhNdmRqRWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MM1pqTFhOMFlYUjFjeTFzYVhOMExUSXdNakV2ZGpFaVhTd2lhV1FpT2lKa2FXUTZaWFpoYmpwNmEzQTZNSGd4TWpNME5URXlNelExTVRJek5EVXhNak0wTlRFeU16UTFNVEl6TkRVMk56ZzVJaXdpZEhsd1pTSTZXeUpXWlhKcFptbGhZbXhsUTNKbFpHVnVkR2xoYkNJc0lsTjBZWFIxYzB4cGMzUXlNREl4UTNKbFpHVnVkR2xoYkNKZExDSnBjM04xWlhJaU9pSmthV1E2WlhaaGJqcDBaWE4wWTI5eVpUb3dlRFl5TkRCalpXUm1ZemcwTURVM09XSTNabVJqWkRZNE5tSmtZelkxWVRsaE9HTTBNbVJsWVRZamEyVjVMVEVpTENKcGMzTjFaV1FpT2lJeU1ESXhMVEF6TFRFMVZEQTJPalV6T2pFekxqQXdNRm9pTENKamNtVmtaVzUwYVdGc1UzVmlhbVZqZENJNmV5SnBaQ0k2SW1ScFpEcGxkbUZ1T25wcmNEb3dlREV5TXpRMU1USXpORFV4TWpNME5URXlNelExTVRJek5EVXhNak0wTlRZM09Ea2piR2x6ZENJc0luUjVjR1VpT2lKU1pYWnZZMkYwYVc5dVRHbHpkREl3TWpFaUxDSmxibU52WkdWa1RHbHpkQ0k2SWtnMGMwbEJRVUZCUVVGQlFWOHRNMEZOVVVWQlFVRkVRMjlRVmxCaVVYZG1TMEZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVUZCVDBKMGFIUktWWEYzUWtGQlFVRTlJbjE5TENKcGMzTWlPaUprYVdRNlpYWmhianAwWlhOMFkyOXlaVG93ZURZeU5EQmpaV1JtWXpnME1EVTNPV0kzWm1SalpEWTRObUprWXpZMVlUbGhPR00wTW1SbFlUWWlmUS5GOThqT1I1Q3M5SEVlNGd6NlJSYzBVbm5jLVlrWF9QVVdzMjBlTHJybHFna040ZzdPS05jQWx4cW80QVJQS1Uyb3FXTXE1TldPM0ZqMnJLOGRNWm5EUUEifX0sImlzcyI6ImRpZDpldmFuOnRlc3Rjb3JlOjB4NjI0MGNlZGZjODQwNTc5YjdmZGNkNjg2YmRjNjVhOWE4YzQyZGVhNiJ9.HeV3GYQDGZR21GI9vgC6GBXL1a6UHNUp_jdJMUkNv3ppOK01n5jL_H7mVN08i6H0z1ZBJEQRk2E1MV5IwNAysAA"
        }
    }"###;

    pub const PROOF_REQUEST_SCHEMA_FIVE_PROPERTIES: &str = r###"{
        "verifier": "did:evan:testcore:0x1234512345123451234512345123451234512345",
        "createdAt": "2021-03-16T09:31:16.000Z",
        "nonce": "KOZpGwyu05LH98QuURsJhH9ptlbuQ/mhRIl9DigKSF4=",
        "subProofRequests": [
            {
                "schema": "did:evan:zkp:0x123451234512345123451234512345",
                "revealedAttributes": [
                    1, 2
                ]
            }
        ]
    }"###;

    pub const PROOF_PRESENTATION: &str = r###"
    {"@context":["https://www.w3.org/2018/credentials/v1","https:://schema.org","https://w3id.org/vc-status-list-2021/v1"],"id":"c7c606bd-0820-45ad-980b-84e6e36c311c","type":["VerifiablePresentation"],"verifiableCredential":[{"@context":["https://www.w3.org/2018/credentials/v1","https:://schema.org"],"id":"9311f783-eda0-4f2d-8287-3816868193ef","type":["VerifiableCredential"],"issuer":"did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6","issuanceDate":"2021-03-16T14:38:29.000Z","credentialSubject":{"id":"did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403901","data":{"test_property_string":"value","test_property_string1":"value"}},"credentialSchema":{"id":"did:evan:zkp:0x123451234512345123451234512345","type":"EvanZKPSchema"},"proof":{"type":"BbsBlsSignatureProof2020","created":"2021-03-10T10:00:35.000Z","proofPurpose":"assertionMethod","verificationMethod":"did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6#key-1","nonce":"KOZpGwyu05LH98QuURsJhH9ptlbuQ/mhRIl9DigKSF4=","proof":"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"}}],"proof":{"type":"EcdsaPublicKeySecp256k1","created":"2021-03-16T14:38:29.000Z","proofPurpose":"assertionMethod","verificationMethod":"did:evan:testcore:0x1234512345123451234512345123451234512345#key-1","jws":"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOiIyMDIxLTAzLTE2VDE0OjM4OjI5LjAwMFoiLCJkb2MiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczo6Ly9zY2hlbWEub3JnIiwiaHR0cHM6Ly93M2lkLm9yZy92Yy1zdGF0dXMtbGlzdC0yMDIxL3YxIl0sImlkIjoiYzdjNjA2YmQtMDgyMC00NWFkLTk4MGItODRlNmUzNmMzMTFjIiwidHlwZSI6WyJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbeyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOjovL3NjaGVtYS5vcmciXSwiaWQiOiI5MzExZjc4My1lZGEwLTRmMmQtODI4Ny0zODE2ODY4MTkzZWYiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIl0sImlzc3VlciI6ImRpZDpldmFuOnRlc3Rjb3JlOjB4NjI0MGNlZGZjODQwNTc5YjdmZGNkNjg2YmRjNjVhOWE4YzQyZGVhNiIsImlzc3VhbmNlRGF0ZSI6IjIwMjEtMDMtMTZUMTQ6Mzg6MjkuMDAwWiIsImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmV2YW46dGVzdGNvcmU6MHgwZDg3MjA0YzM5NTdkNzNiNjhhZTI4ZDBhZjk2MWQzYzcyNDAzOTAxIiwiZGF0YSI6eyJ0ZXN0X3Byb3BlcnR5X3N0cmluZyI6InZhbHVlIiwidGVzdF9wcm9wZXJ0eV9zdHJpbmcxIjoidmFsdWUifX0sImNyZWRlbnRpYWxTY2hlbWEiOnsiaWQiOiJkaWQ6ZXZhbjp6a3A6MHgxMjM0NTEyMzQ1MTIzNDUxMjM0NTEyMzQ1MTIzNDUiLCJ0eXBlIjoiRXZhblpLUFNjaGVtYSJ9LCJwcm9vZiI6eyJ0eXBlIjoiQmJzQmxzU2lnbmF0dXJlUHJvb2YyMDIwIiwiY3JlYXRlZCI6IjIwMjEtMDMtMTBUMTA6MDA6MzUuMDAwWiIsInByb29mUHVycG9zZSI6ImFzc2VydGlvbk1ldGhvZCIsInZlcmlmaWNhdGlvbk1ldGhvZCI6ImRpZDpldmFuOnRlc3Rjb3JlOjB4NjI0MGNlZGZjODQwNTc5YjdmZGNkNjg2YmRjNjVhOWE4YzQyZGVhNiNrZXktMSIsIm5vbmNlIjoiS09acEd3eXUwNUxIOThRdVVSc0poSDlwdGxidVEvbWhSSWw5RGlnS1NGND0iLCJwcm9vZiI6IkFBQS92SXhNc1R5Yk5EanU2WHYvYjZCR1c1R1NCdGFCRXBFRytEMDZGZE1QUTZrL1Y4MCtPak93SEhRbzNiUWZRTnh2ZDZQUjByN2ZJTk5PdkwvbkJXc3JOSGs5dmNnMS9LYlVDUU8rNnNzUlhNaEpJRzZ6KzJnckcwT1REb2FhS2FiME9LVUhlVlZDRkkwc0RXTGFIbytjbHJndTV6cUtjRzk5ZmlvN1JLazk2ejVGTmhiUkRYemJTempDckxHYWJCVHNmZ0FBQUhTalYvWCtlMXJGVTZvVHlMR0J4REd1blMxR1FFZVRrek1qbmlKSlhid0NyUktRRDFjUEdUSHhPR25qSG8zc0xKRUFBQUFDTDFCbVpNc1Y1SEdoTkdDSEZzNDVLZlViaWJ5aWczWVlWeXJDeUpac3BkTlMwUm9kdjYzK2Q0ZzQ1Nkt1aDlrbmxHcFFwVlYwV3VVbm1HbFZRRmZhWEt2QXI2MXRwcTRWcTBtYmIyUzNPbnBYdmtNcTBHeE5KTlM5VGtwVGRJa05NMlRCaVdhSnEycVNVZ2hMQ0x6dHJRQUFBZlF4bmhqOXpnclNVWkJrMFJ1OWhDbzlGOFNLS3VwZFE0RGhBNW85TUMxa1pTUTlUSXA4ekxmcGVWZjZvaDBUdUdxUEg0MzcrYXcyZ2ZhYVFiUUw1NmlPQlNQaGpNMWlBQkxIYlF5Zk1LRENjYjlyN0xVM2dtbGZER2VnTXV0Q1FabzNvczJYaVJRS0JMeWtwSmhucnY0TWRqT0NzZW9ic1I2elh5RlNJekV0S2hPN3VOWWhlaXBIcTg0WUlHK2NINU9VdTZTK1FBdlRHNnFxaWNwV2QyaTJEV1djZ2VVc3NhallYenM4RHhETDZzUGhERWtRZ2xVdjBiSnNYaGVLSjRaalJlYW5KZ09lQWNjUDk2blNTSUU4RlZBU2xRMFZ0ajJmdm95K24wZkJiQzR1d1JQRmVucWowa1JTR3NlcFZ6NFREUUp4WC9jbk4rK2RHWGRGQytmOGNlbld3STVQeW1FUFA5TlZjVlFzZ1JMeTU4QW5LRUs3dktvR2wzaHJOVjVQSmc1R2RoSXVpait1Q0NlS0I2NlM2N1d0dko3eUtabWMrNlM3NEhXUUtCUnVYWnNnVFY3Y05BdGthR3VlVWkrczF2dzh2K1dZbGJTV0RsREZIOEZNTmFoZnVwbUgwS25lcFpoM1VPamRuUFV6SWZWcVFVQ204UzI2ZUdDcE56SUV6WUpEWUoyTEFYbjNmS2UwRXY2NlBCRENuUFNjd3BScGlscVhreDZ3UnpxRUwwMmZkNkE2eXF4YnV0akdDUmVrZ0F1aXJSOUNrUXlSVkJuTS9vQThQNWVOdVY5K1hHT3UrZFJ2cGk3MXQ5ZDRzMnd5YVNIbnZhdWY0YlJCTzRSVEpuYmdjYU9NRUhycllDZFM5UVRwWEFzSGJoc1JKL0ZjM3A4eVhiYXE3M1BxREtKaTBVaVBjQlh3QnpZdk5UamJjNCt4RHhYRmIwaFF1RWxrZHVCVkk3MVh1enZMWnBsUzFWNEoxSUYybVcxejVVYm9JSjh3YW1LeVVTUEFLZDh5MGpwSmQ3RnpXYmhOMEpuZ0VwT2Ewd0FSVEIyUHNyc3FVS1FqZUhEbUQwR3ZvbXVpZTlSalVXODRGY3BobTBzV0FPRUVOb2UrVnFrSnBFdW1tVFVyUW82S2E0THRBSXpPU3hNWXNFZEFmcnQzSTNZVzhTVUIzRGlwdmlOZjNOUXkyR0tBWVUwT3lFMkVwQUtWZ3pyWElacnBNdTcwWjk1aDc3T1BHYXlHU1JlZUQvaXVsZzFFcm95d05YeGNmalYzaGpGamt2eUxxSjI3SXlwVkd3RUxXV0UzelZsUUIyay9WS2RqYmFkNk8vWkMvRzllS0k1VmFORWpRTU1jMjZOSlR6dG1kN0tna3JFUFdnWFBuNy91Q2dVaU5WTXE2Zzd1YXQrR1p2cTVGVkNFSThLenFlNy81R2M1OHJ2RzUvbnRYU2pvbG93V0ExWlJpSzRXa1NuNVRDaDhIZEdMUzlLdG9UenpaNnF4SDJSSGdTVThsUStDOWNLeURFNm5FUjlOcXhaelhYaFEvUGxuTXJCWjZ4SDZJUVplU1RoSEdKYitwNXNJeThIeEVIT2lhTTg1bUFtOEZCTjNMS3NTRnkydU5Ed211bEI1aFkwckJsODg1ZkhGTUp2MmtiWWcwK2UveTlTdnZoVzdkbmRQWkpLbU9YdE1wcDRIN0c4ZVA2bFNUYmRYdXZLcVFzenFGaHZBK3JKZy9YMGZ5bUtDak1pb2phWm1VREVIV0JkWFd0cFlsSDgzSncxQlpiZ2hIZ00vdmljYkdlWXV0UE9IN0hZazZDeGNiWjc0NGhoM0grRlRDL0hqaHVZSU9WYXFkSVFHSTRHTmV5VVRFL0JGOHhsYk4xRWZVTHNhejA4Q2VHZ1ZIMlFYVU4wcnRMSU5paDRmOVJ1aFlyMytJeDQ5OVdiemR4cGNZRWErcUZkbWtMYkRscmpobHBtMy84cVVnYnd0MXlNWlRMY0JxS28xYXlJM2Mwdnp2VUYyU0tkRFdER2hxN2dhYTkzcG8yRTROcnMzVHJWM1RZVzgybk1sTjZ3UmJhWjdub0llUzJITG5BRUVGUzBGOVFQc3FCQmdBLzQySE5nbVB2c2N6dE9HQUJUSHZiVThKV3gxZllHK3hGL2lPM3ZOYTZEOTVpekRKcGxhaGVJckJKSFE0VFdtTHJEam5LOVZTY3JOVkRkcCthcGVOcGRxb3g3ckRyM2dpTEpiUm5YQm15aEExQ3JlMWIxbGlaRm1zTlBNT0FDVXFwWjV2QWQ1aXVNeTRVT0Z1Q0F1QktFQnBwL3FxdVE1c1c4UnN0SWFUMmxnamZyeHBlcVFRNjYzeG00bVRwOUxNKzF2OWc1aFVSSE1UUmxuRUFneDJ0SHA4Zmc1OWdvbEZ1NTVWTlZoYWlpN1IwREtsdUVaV0QwVDgwUjJWa1hta3EvbGdWY1l0YmdSYUh5Yk95VDBIMFlTQ1BBNk1ORUJrcktDYi9UZE8rdStla2o2QXpUbU9xWkpkR3FoRjA5NDg4YW9hWmtmWU5UVmpheDVTbE1QeS9mZkZKbE5TRFBVZWc5WDNyMkM4SCtMd3NhNDZNa2RTUmkyRFU3VTNrRnBjY0VDaWhiNUFBU21pejNiWm5kb3JwamVXcTVFNC96a3p0aysrQi91T1VuSkc4RDQ2S1pRVjVreE15OVdNblg4Z21tdEJ6M0N5ck1sZEREL0RUb09YcDZZZzREb1NGMlp0U3JQSHhNSG5Jd1RoWXBlNWVHelB2ZmNsRFY0YUVOMGJGSVJiME44ZnMxUHlUTFI4dXpVaXUrT2R0S2ZyaHdEeFd4MjRhQjhEMTZyYW00VnJGN3k0UVBldnBaRndrYXlsTC9VUVl6Q1F6bkg0QlRoUDBJZyt2NmRNZjlCZTgwbzB0N1lUQkRGZWNhNVp4NDcvYnhvWExvSTFtRnhaeExUYm82UnNLMmZBMDlhMkM3ZTA3WGtUTHVtRGtYQ0NzS2dJMmd4NHJPd1pFbWdEd2p5d0hhUzN5M3ZPU2NPcW8xa2NjNTZLdEpGblVPVDBNTnk0d2RNR2lrbFllbFZTRTYrMXAyajhiYVZkZlZwM2E1d2ZMQXJqMkxZcHFRbXJ3VU9LZDRtSEN3eC96NG9hL0dIY2NKTDhDb3R6M2FsWXlUazk0bnpVRjFZWjFnNkxnUGFVK1dpUnJlMmlDTnl4eVUyb1llU3MyZzVQQUJ4ckJZMUZRc1gvTGN0cE5aVEhMdkZKc2loa1RpWDdpM05NOGFTblJsczl3MG16bDNjaXhsTUtKVmYxcDZ2MDlHSTNzWUpXVy96bjg5RDJucDltRTJCZlRPOXNDR3RhUlBSU1N6WGVHeGljMmRqakh4NVhzUXdzanBDNXZpc0pTV2NLTkNqSkZSR2kxbFRZNnhUV3YrbkYyNDdTUXJsd3MzSVBFZWIyT2tITllhMkt3RFBWMDAydmtmK0hrTlUvT2NQeTArTVBmNjdJZmxNU3RSQWdrYWI1UU16WnV0ekVQN0k5MHhOMjdnUURheXpJeWhUN0dCZEFWTXppNGpPUkM4azAwcTUyNFJJdzZLdFpabkVhOXByUEt3eVJycDBDSG81dTJWMTEzL3FCc3VjRnMvSlZVOXNDOEowZjFwYnk3dWZ3amdCZytEMFcrTTM5b2RibmNFR0xSRklyRS9iYlh6YWtESG1oY0YzWXRZYS9vaHRxMnZsWmRLeCtEUHBYeFd3Q0JEcXgwQTFBMzRISzNoYXl1U0NaOTNzSmdJYVQzTG9BRTVsRGtJSnNhSlpMeFc0OURVT3pIa2duWEIyWUEzMlB1aTQvSXNZc0thSENHeVlLVGZBN0RUanF0WVpDSkcrTnlaUWdhcjEySGd5T2d2ejdsTnlLWHR5TGNuNDNvTjNUN1dVc1hsbmpkRC9zR2c0ekthMyswWTl0Mm5VUGxEajZmRVpndzBZYmxiVW5wYXZWeUFoRU1tWjlhWVp3TkMvaUZCb1VTV1ZCWUhyVm8wTmNNUHNXampFSHQ3amNTRnR3QUR4TWtpd1JhK1BTWGhRZU9yOEE2K1Vib280STdjZE4yTU56dWR1am1YMFVZdEFNWk1oM21XTXZ5Q3BqeWVrMWNObjhqemNPZUZCdk1SdkRqUFZQci9MelZpT1B6dDhFYkJhSHN1YXFhWWhTMjZ2aFh6YlUvZ3dyZEp3RjF1K1VTK1RQekJUbWNFMVFIcmRrb3RTcWx1KzF3WDlNYW5oYVFBLzB5dzVlTUh3Yk1TTnBiOXZvUWRoS2xBWkJWbjE3U3JrdEhUQThxTTIrQUlLOEdSU01wZERBMWVQNXh6V1lteEtNamgvc0NsL3BXa3lucDRoYlpIN2taVUlWalhLOXVxWGpLaWdNNDIwdDhGb1NzT3BPR2I4RXc4ZFRlaGxkVFZuRTdJbmUrK0Y0VG8yZzZqekxpdm5VMkUxRDhFTkIvMWEyZ2J1TDdkOFRHdVFrR2toRDVwNUJyN3ZjM25FbGdMcUEzWFExdG5hSStxYTdGb0xLSkVwQTZrVEowcFBCT3VuYlI3WW9MS0F6b0p2UDd4UG1RTUoyU1c4MW1xbmFweEJMQ3RjT29Jcmh1U0hYeUhlTjlPZHdydWlpK25HUUlLZnpiODlOV2FURWQyci9naDVEYlJWZDZYbmw2bFV6RDhzOGhGaFlCZmVVbW9LekR2cmIvR1dXdE9MTzZsSmRCaFVKZ0kxTm9uVjRseVJTUkNDMXBsMU5YM2VCOHNIOWd1NFJFVlRDWmlSQmVSM2h3cVdLVEJQbFBUdzZUdm05OGg5QkVDWExRak45ZUhpQURRZkQ1bmZCT2QvNGtXWFBWekFKNk1yMjU3VnBISWRCQmx4aWZhd21lRC9SR3NUbVlWT2poQXpEbFl5eDZYSzVQcWNjbGRwZWdYWFE0TFBtQU0vWHZ3dlEwUjdzRGM0YmpTOHI5R25oQVE4cXJzWXlTY1BZcnIxdTJVZC9ZeTlCaU5NcGcvZWNFVjFGa3F3MW93blNVV1pScWV5NHU0YXJ6RW1LVThKcExtaUtxYXlvYzl3WU9DMGMwMUxjSUcydHF1b09CR3crSjRXamVJcWhGR0hxamNHcXNWdUpWUEY3bTJiaDkzSjNaZXQ2SUxVcFd3cTR5NlJVNGEycENmNTJ3NVZnS1EyVE1TYXFDS05vdTNTUFRLaDNFamlPOEhCUGhpRmdZaGtGaC9MQXE2S1JPYUl2b01nMmIzUDJneUZZSXJpNmRDckhjNkg4T01FSWlZT0tGSkpueGY4cE1wVStEOEg2QVpubENmSnNhOUlMMnhtUkgwMEFmSXJ1M0EyYVNiSVBDVTRtdEI3MFVrd1VYSyswTy9OdUk4VjJKQ1FSanV6TmdhYU1lbFpLVU1rVlUxaVNvcFNodmVqaTV5aWVWcGdPamdGMTFsdkRCaVhtdCtibmhNSUNIRld2WmdyTWlBSW9QUG9nNVpKTlhVbEFhc0JjajBsNksra0xHTFFxbGRMeWJGMnhXclVsQVo0WlpQWlZsZGZtb2VlelNnSlpBR2IxelJWaWs3ZUNJVUFINUw4UGJTSmR0V0dhSHRUOUpOSTJCSnBmLzZYY3RTQXdiRW5pRGhTZVVmOE5TWHk4K3ZiVk5hNDZ4VVl2Mzd6RDdDSnFjRTdkdWR1c1F3ZHMxNzlHblQ5WDdDMWhZQUlYRUlMRzk3eHJtRTNSeTRiT25iL05wNUtzWHZUS2ZsMlJleDRCOGl4NmZqZDZmRm0xanFjSTBPQ0ozeHRvSTFhYlpmeC9kUm84N1dlS0F5Rld4aXEvbGJaQTUrUWlRaVYxYkc2UGFSUUh5OUEyVDRpTHh5OG41b1dINWVabGNxcmhqci83bDJrV0FMME9UczJNU21mNEtvaHY0bGVTdHRiMlk5aHd6eEYrcU1Xam5DQW5US1lhWWxDVUhDTFI2eTdpbDNVcUV0TEZMM3BUQS82MnNnNTdWNExaRkEyams0eU8vL3ZaS2lUZUM2c05ocXA0Z2ordGRnUWVaSkpSbTl2TEtJeXl4cFFKTnhqbGdYeDZUK281VEVnZHY4K0dVUVYzWXNuUFZMd29xbE11V05PZmhwOTNuOGZ1cW8wQ3pNRHBZYzlHYU1tcHZDQTV1dVV3dVhWTnYwV3ZtVHVGcmpraHhJYWVjVzNLZGVJL2JYeUdRaUlxaFF3L25vNkxCWVYzbS9BT2FKaTMrMmJuMzFDQmhXSnc4dk9SRDhwVVBnbktYbmRpMlpoWTRQL1BJWGU1emg3WnRVMElUQmVNYnlvT2hLRldSZ1lGV3JnY0MwZmJ5T0cvaG45QW1hUFdRaXlDeHVmN0p3WEs0cGk3aFhvVkI5SDBxa01Fd2lNcWVsdkNERnRsNDEzU1haYmhJUXk2QlhMSitaRmxhVjdQQjFiNkNucVR0eCtwems1UEtNdjVWYVFrRzFJMHk2TXJuMVg1RjJiRVdzSXgzV3gzcWJLOVd2QndBZ0hZUldSamZJWHRzUXQxN1QvWThpd2dKQnovU00zY1hMTjQ4MzZRTGp0QmdQV3M3S0FEd0ZRakNMdlBGQlp4RkpTa2hQOUFRZ01TVm5OMkRiUDYzQ1VuYVNac1lqOEZtSUNJY2tBcEhRanJJMG1POVJJY3pIZjFQYzI1VUxyc3hRWVlXWi8zd0VWZ3YycXVDMS9CWlpUenBweHVDbzFBeXIwUWlXU3p4V0NVeWx4VFAzcER6NHFTdWZ0TjdHREJIRHo0dmRRT1U5WlhjY3plakZVY0lSMmd5LzhYNXZPT0dRdndhOFh1Mmp3dmU5aUxrWVd2VUJiOUM5THYwOFcvaklTMnZERThSQ0lUaEVIWVZyeTNhdHMxOU5CMEVBczU4VmZaMXVvaVIyZ0d4ZkErUFpmRjduWUpqOXNLZkVOanlQaFdCM0hOOFRYN2U2TVVPNDgxN0o0VmNDOTg4cEllZXd5VTBLWXE4d05SN0dTeEI1bkl6LzdJOUpGU291NVB3MEpvOVNzZEQ0TFlyeENyUXcwdTl6cDJjNGl1MFVKdEp3TjZ5TGZyTURiaWJ6RVRnMFprRXZlSWxuZ3BaSlY5WDVRTEdBZ1RTamRWTi91ZzdSMUs2M0lGRUhPQmlsaEJTRUpkMHJDZU9qbWFQdmh1bEFVbmFVOFVOVDQ0QVFwbFQ0WXBnYWJEdWt4WVdDL0ZFODFuMFcycFVCZ3AwcXFWUDk2MGNPU2lNMDRaTGF5ZjhSamZPY0FydGV6WlV1eVRULzQ1OHE0TG9WbU03OUxDUmxpVFU3aFBrOHNTR1dmeVpDZ0VuaDhTZW4wV0hNdDRkVm85VStrWDg5R2Y1bVdsVG9uRHJVdzRKelhKbE16TENadkpxVE16TjVMZ0U1N1BQd0hZdUpTL3h6ZGx2azZ2RGtUNDk2K2YreGxJOFIrOGFKMUxtOTFPUk5WS0RxY0xtdmVibFRISzQxeU53ajlxbzZ2WTJuQVNQYnBhbHRLOEtrL2Vzcmg5UzdPdUFXVFdmNk9oYUwrbnBRN3NhQ016Q3FPQjBrbnZwU2hHR2hFUmVUSmhCZ0VlWFplUnY5UDY0OFByNzBvSkFTdTVKdDZWSDZWUUMwVFY0U1VLS3A4aW1EcTFFWk45UzNxUHlSMEVKTlJZeDlueEpDb0U2VnZlbjBnejd5anhRWG9FQXFGOHdxRk9CSWQwWGFycHJhOTFrZW51cnpUWHg2enhDUEpjbVZucUtYK1IyS28vcFN4R00rYWFjdndpdEsxWXRJdFdoOUtiVUdoSUU4ZVd4bkE2c3JBQjUzdjhhQVM4b1VhdTVVN2x2cjBYMlUrWEZYRnZzRUlBeURFbU43VmljeHl4dUJPa0pVNVMvZ3ZiVk9HNWZhTFRneUZsTW1CU1Q4dDRscXpHVHpQejNIRGY2QkpmNENqVDU3a1ozYnFGUmNtYWV0Nko3cG5aby9BU3kvV2pGWjd5aWE2bW5YU1NheGxXc0xIb0JBT3hJcUVWbHpRSHhJVlZmVTR0NjloOU83MWxOVEFjdFJNWFJYVFB6M3B6aC96NmZmMzF6cHhmUnhBeTVKUG4vNEsxOXd3TnlBYTEvdTk0UnV4TUVEd2owd2NMdHlVSWtjdlZBZmJuWVZDaXFuMURmb3FhbFN5T28yczBEazVha0RyVmUxaVVpRTc4ZWRTYS8zQy8yN205UDh5ZWxCeUlodzZNbXA4Y1NVZzR4aWU1THRURHhiK00zQTQ0bm5zOGN2UWNIT2JxQ3psaUt0OXhBc2h6QWx5NGxuMXZlampURnppWjFQWUVXK040ajluME51UzA5c0NCQlIxWWhwdTJZWEMzS2ZMeWt1aG9kc3JJN0U3TndvZVFuV1dYWTRpd3NjTm9JeFZqaEwrN2dhSStubFhYK0F6a0M0YU4vNHFJazFYU3dJZHVrejA2elBXNXlDRW5nTHpNbnB4QTBHVmN6aklKZWhrR3lleGVJbTh5V0tkaDg3SjdBQmRlOURmYmhxeHFBZ1ROMmJQTTJNS2hCZmY5OTNnZEREa3dDL2pKUVo0ekN2cDc5ekxXSE9TaTVaSitvZzVSZ285TkJXQjJJZmticnVHV1JGM05iWnRhOFAyMnZheDRzVmJ6RXNyTllESmNFcWc5WmdGTGxMOTRtQy8rYk9kTTZBM1MvZ0ZkYnJiWWdlTUwybE84QTV2ZTZHSS9NM1VqU3kxZEZ5WTc5YTVwdDgra2N3MnVSUm9lN1BndmVkUW1GNVJCU2NVMXlUSHRGMXJCWHdQMEwwK0o2TTNTNnlKL2dCZzNML2c1bWNRU2NpN0ZtUWVsTkZldGxSczBRVWpNelUzMVlQQ2dxNFF3SXA4c2ozbWRuOFR4VnJwdVY4bWpTWkpETCtkZFQwdlJIdmpOc3d0ZVlZTG00SzJ3eTNjeFZvRGFOZVRCVzA1V3crY0xhK3N3SjQ1S3hjdjNZSHM2dlkxY0dXQUJHNWxMYXQyNG9wbGMwMFBmNktIZUhUbSsvdG84OU10WXNZODVBUlVwWEZqZ2ZRN1A3UkhSNXl1aWZZZTVEQkJicGo1VTZBckxJNitaUVlPb2pwK1g0RDdIVzRkNGd5QjI4a3o4bHFCQVhFMGc0Sm1Fc0Rka2xXcUJVdUtpVmJIRE9TdmNiSm9kREhIZHVVZDFDZUcraER2RkZaalQ0Z2kzSkJZZm5nRmJFRjNCd1pZb3VabjhvdkEyVVI5SnFFTnlMQ2EwYldmU0c0N1RHOUVwUE53YzhzZGdraE1qVkh6ai9weEQ0Qkc2dXlpZ3hBQWxEcllCYlM2am01S2g1L1k4RlhZWlNxdHhKZVdNMlRZSFlVUHpiL0lLbTFlOW83WnRzZzhQUkRaVytudW5HTllQQ1Fjc0JWRVdrWHN5WDdYU3hQYit0eXVDVVBxUC9qUGpLcHA0NW5PUVRocDZ6cDNET0V6dmFWWjZXNGVoTVhFOTRwRnBTa2VFNzFBY1pCSjVtZHZTbWxXS0FQeTZKb1BJbGlOY3d6YU43UjliblZTMmpuU042WTU5N1RabldoeHNGSXpzbzhpMi84ODV3L0dYMWRWL3VSSjdWNi9FT2tuZzdleHowa2JQUmJ0aThQVVhzaVNSdHFpSmlwQWpRMkFhbEptaHlreHVaeWl1MVQxQ0J0YWJieTZSMzl3T0NVTmxIeVFXZDdKclJoeENMVkZ2WFkwdHErV1R0R09OUW9iNnJCZjB2TjJIamt5WUtYT1dxNnR4d0htVXNKdEtqOXd1ZHQxdVB0MTBHRGlJNlI0ZTVnaTdFcTJpTGhJWXFHOURDbHJidStJZ2M1eHRTVzh4V0tZRzlabHJBTVhmRFVSTysxSlIwR3IrOE9YblhYSHMxY25QWCtseWE1Szl0UU9ob29QbGhPb3BjWENyRGRIa1dOajFmbGxRbDZVMm1lQ21ra3o3TndQRGwwZmFqaFZBQ0E0SGtZeG5qcWVuNVBPc3IvOVhNN0N5Z0crV0djRm9RaGRSWDg3aUcwWTl0WEVKWVUxL3BxU3VmaHF6ZnVvYjMrRS85MjZhOTUrTWJwbUVqV2ZYdXNOUUJ4R21HSjBFUGNhK0g0bVNNeFdhU0N3M3ZzaHYxbU80d2ZXaVIrRi85Z0pOamhWMFJzdUUvRXQ2bVViUlNTR1Jtdms2QngxWFVYcWIyVzlSRnAvUzFuUktZbFFVUmJaNUo5NFcyK1dtT3lXY3cxdktjZkpMMVpqb0ZUMU9VdzZFZHkreXcvL1hkT2hLc3A3R1FpZVcvSEdEdFN5VDgySkRTQTRkbG1mSW1xTU9nWHUrK2JVcXAwUUlXVUVmLy9pTE15cXpXSnhJQit6SGJnb1MwVlVHZHY1bnFqNE40clVyWDZsMEM1bGN1ZWFkTHpIYzV4UWtUSnFWOWdtVXkwcXJSeVdLQmJjQVFxMVN1ZFkzSzlsSE1sV3IrbzNFYXk2d1VGM3VHbkF1VFczWTN0TU91RkI5WTFnOGt3dUtka24rUWlmUEFxaDAwZ3ZaNVRxM1RGTjNCVzZua1hacTBXMXNFWjVxM3RHV1ZmdFlpWHBQTzNuSUdnWkJmQkRrWnBydFJ5TDZ3YjNCSjRMQkNPd21NQjRSLzd2MFc4UkJVUFNMQ1U1QTVSb0pBZVJVM1FCMGF3WkhSZklybTNVREtrczJCbGl6SFY5a3NYV1FDNHZ4MUpDVjUvOTlKMm5YMkdYcHNRcDE3SnpEMnJzRnJnQUZNUVFKZjgrOVltcTc1b2F1TE93T3Awb2pRR21OdjNBWlpkaG9TYzBxWHhKTEhFOC9EbUtHcEFQVmZzSXlueTQxMTBaUG1DUlFaUEFUV2U4M0FEZDgzd2RQRVQ5YlNTK0lZb1dHeDRWM2s2TUNFUDhnY29kb3RZa0hDc1pIbUU4aWFCdlZRRm1oT3RLYTgvWktFbmEzRy9rYlV2bGZpa055ZVpBZnlNZ3VrQW5Kd1djMERyU2xzdmNlN1NCNUhUM3A3TDFPL3ZSZU1mYVljVlRFeitRaGMzcGRPK1pUOFRYQTVhV1B2QUNHY2E3TEtQb2d0OERuemlZNzFjOXNhK1ByK2p5d2lJZTVXV0xFV2JaQ2x6aFFUSHJlNTY4VXdxNkl4anh6ZWo1dFJHVHlMYm1kVXB6UEswVTRodkR5eFNCTFk0c21YdnQ4KzFtSHZONEtTRG82VWV6U3hoeGJCZ0JaRWZjNUdxbkhKekJQcUQrU1YvV1Z5ZytPaEw2bi9LNjZwT0FNOGRheXhtUS9kcENkbEt1aWd1RlN3amtjNWdFUnFxRjhWMHNQY0ZaUEZOSTBTc2pxMjYxcFBVYnhsWXp4SFIxNTcvZVBnVUJSUllNNUEyR1V0RDMvMVVpVVBWSTBqY0hLd1ZOZTlEQmdGM0dIalN3aE5ZSUxJaHpyK0RhYW1kL3VYRk01UG1FRUJtcVhja3MrV0pHcEFpak8xZkw3S1RGNkphTm50SFFiR09oS3owdDJuUi8rdHMxdUxjdXZkK2F5Q290azgwdFpCT09EVDhzSDNhaFVTbTJXZURLOUNJRTVHWFRpcy9aa0RhQnp1YTVTQnFCUWFVY2dvbzNCdG4yV2xOakNzQTQvMHM4Q0hTaDZhRGRVcDdsVkpjOWVDRHFXa0pQT09mVjN4Vk9ad2V5aEVkWFVFclR6aGg2UVo1UXEya3FYcjdhSXBBRklxODRsVW1IRkJ2U1M1VEpsNWViWjY5ZzBIbUl0cnp4SEdXajJmQWg4QWV0MzNjc3ZQV0xNSkU1MmNlOW5mcFdIK0d6K0l1REl4MGd6elpxQk5KRGFuV2pZZUU4bHZIUENDTTYyNWZmVHdiZ1VDd04yNHFQTEVBWTd4R2Q4Z1M5ODVEclNHdUZTZmNYRnMwZlZqdVM0THR0LzVKdzFLQWx0TGJUcVlGaWhzdDEzNHF5SUs1bU1TWWw1L0VRVTVaM3BIRnh1NjZuQ281czNaTkV6WlhBNUFNc2tIeTQvRXg1cW1SMUY4N1BjZkltNks1SFpDSkNOWHdXWU9rc1gvU2pLSkhRdHp3aWxFWVZYeEh4bXZQc2FDQ3RQcW1zQVFlNnkvOTRGTC9BdVhqZzRTL0hIZ2tETmwxbDhlaDRQV1JINHJnQzg0OUtyWWc5OEl1NFZGNmZ5SUxOSHFxSE5rQVoyd3MwQ1RuL2IwMUFMZ2pLSFVQTi8xTFJIMFBpVG1INnZnYnlqRldzSit1M05YV1o4aHVmbFkyZkZOSkhBRzVFWm4rMVFNYXRYUm80QlkzakxrMDhESlZMc3FjMDVsSXhEOHdna3lZaHEzQTVNTzVCeXZxZEl4TldQa1huZnI2RnJ4YitVZjEvdHpBMG5wK01rVXN5eHEwWVBlRmREMVdmZXhObWg2d2N5STRjQ3BPQzBVVFNIVUhvUmEwSDhFUjBhQkowMnlHSStUZzd2c1l6STFQNXZEaHR4dU9ZQU5zVFhxY2FYelpjb2ZBK1F4VFlvak9zVGx2c2pUWE9UbzdwdDJXU2hnKzd5TVlZOWdwcUpmUU5MbVdNRHZCWXRSNS9Wb2g2NFJveUt4Mm9hMXlxaTJwZGZRYzFFTzBSejlMUkx5OHZ2RGZMclhVUGxJWnM1dFFJVUZVWXFLWUJMTFA0eFlKUDZZWE5FMmU1a1RQS2k2anNkQzh3NkNIYmRkUDhCd1JIQkkxLzIxSjFWR2NpUzdpd3R2aGUwS0Q1NlNCV012U21qS25SaVRwVENjWEYxQktBbXFDZ09mWUwzRFExbCtYUjZNdFhSSmk5MTN6aVFhSjJYWFlXNUtaeWdqbk5vdUdjZndjWklldkF5QU55SFFtNUJyS1VxamN2WG1CWStEOHFwVHpMLzB2N2hzVU1FM0Ixd1JuK0Fva0xnMTVRZElhMGttNDVEaE9IRjlhdFhIeG95VU1teGhvWmVieEMwRXNYV2dZR3V4SzhZeU9ONmpGYksxZzVtS2NVN1FvVnNJYzhqWnFncWpIbnBlVFVLeTZCeHZaTjQ5cjBkR296RlV4MnhvMkdZSjBqUmZiekFWNS9JdXFiTHZ3VjNPTFN4NmcwOG5wSnhsa3FZLzN2Y1p5RUJubDdEQjBsYVQrWWNlY25uR25Sb05jWlR3M2o2cnc0MDIwcmpvUDBiczc4VjA3aExPK1Z3ZXZ6ZnFGWHk5czVkeElMTEVqZnNnVXFxM0V5Y0tTdG5WYU5QTjBiVnhPb1ExUHA5WFNTaGZhampMSDlOQ0VCeHkzTlMwUm5kNzJPRmgveUF6dHNKblNpcmMycW1ydW9xUGQ3S01wc2IrdWpOZkZXS05VU2p6TExqbVVFaSs1UW5Nc0FacFBobStBcE5YWEZFdy9hdWEvTVZBQ3FFU3lnVjlGSmRlUENiejZLSjZrSzRySWZSUGFsUUxFUkxUVGJ4bmhHWk5JQ293ZUh0Yld5THJGbnJKZFNnbzJnL1lBQ1ZBWWZTa0JGMms4c2dCMEd5Rk9OOE5WVlREbG5nMm9ialZ4Yk5WV3VDeElranNBS1U3M2tYSDVlSlRsTEZTU3ZxczYwM3ZIQlk3cm52cWk0T3FOTjI0aWdWRlNacEFHeHhrM2tWTFRJeVFXbDY3Skx2R3QvNnpyaWtBbFR1RG9IUmF5RklIYkNnVGRxYVJrV2h3aDhjOEhlSnYyeEVzOVhzVnloUkxNYUFqYWZnZ3hRaW9SeG81b3lIQUxSMmE2K0VTOEx6bGgxRERoV24rUTdPU3VXK2tkVUw3ZWNuNk9XR2pHK056cW9FTVpqQi9udWtjNHliVG1WSktjeHJtZ1hXYldDT0RCWVhVRE9uNU1mblhMMzdtZHM2aDdGN1ppdGlCZVpzSnFIRzg5K1RkY1phcnVKMVVoVzhWd2VvUHRMTTFKYVp0aklaQlJWbjRhNVVDRTNrcnMzODU0N2RNU001cS85U01jUjcwdDdoRi9HYW1aK1BZdXM1blBaWkxIT1JZWHA2T1dVaHhoMkxjME1oeGFzTVJRM1BSdTlIdGlEcjBqNXVXMVVKeDRLQ1lLY1Bya09Ya2RQOTFSTUYxSUFSMXdlODFXc1NGSXZwOTE3ckxiNk1ZUWxENmEzRE5TaXZiemxYdVg5TnpNZGgxQ0VvNzdEUGxhSVkrZWUyUUZYbEFLRDNYdFJwbVNwdFk5cXB5VTQvcnU4WHVuZVZwZnc0eWpxNnJXUTgwQ0VpRXNTOVZLWmtsWCtKd1J6SWdsa1A4Sm8zUklBWkc4Yk1KY1pqYVlzdDVZUGlYbVQ1THUvTnBtNlNTMmpkZ0VaY0JGYW9pMS9mdzZ4MW1mNFpvSlVlUHhPZEp2M2pqYU9USTBucWZqNDZ3MVM1NDJ3WGM0djdmSi80Rzl4TlRMODk5QmJpZjVsR3RldGpWamdONyt5amUwMEt6WXR0R0FnK25RZW9WbHNaMWdyZGZMZkJISXBhU1dYY2hpckZVOTRnc1RUclp3VEFBNUlKZzhDd092WGJWaTIrWWVJTGVHZk9XaHZpRU0rOFhoWG9HSGF0TG1pcGwwNnFKb3pKdzkrZmxzbjBhbkxuSmttUUJ6K2Z4TEdNeHd5a0RMaEpMQW1sM3FQaXpOOXlMcXdaaWVsbm5STDN1aWJjcTZxVGdpRldzNVVxVE9yYXNvRldYZG9Vck9Wc0ZUR1dWSlJ2emxnSFVKUm4yOUVSMjFISE10b3hLaW0rdTVEVThueWRKUWlGTkp0MGE2Rk1JVUxvd1VKbzNTb0swa21PUkFjTFlwclVmYTZnSm5UN2dKQS9zc0dEckJGcG91R0djU0l3Qm10U00wRVNqbyt3TURyejVNMlpyUkVrNW1jMUFBMzVqSmFHUWR2RG4yVWhIL0NaMGp2VlRzOE5PRjJiOHdwWnAzYkJ0cjBqN0xzbXN1eWJ4eisrQkx2Qnd3WmY3N3ExSmNnc0VuMkJ4VnpOd3g0eWxGc2R2SUJuVU1qSFF2cktPUW90WWNTR0Nja1J3QzJWUGtFSC9ZWU1JWTlWSUxXVHR6ZHpTNExpNjBCbjZEaEsyOFM3WXZOUm1VbVZjK3ZaT0djTzhZYUVwU214QnUrdWlyczJ5WTU4YVcrRi95bkdVUDFQTWc1dndsRlB4QUtiajNhbVBWSDVHbGVSLy9wbTltenhabU9iMjR0WlNBY1dydTlsY1dyUDJLN2ZYRUlrL2dHd0RWWUcxMEh3ZFJEZzhaU21TYTNnMmtiakdOT1h1OUtqaTFvQjVTOGY3MmhDbFNMZi92R1RvdlFBSkZpeTduWWp4MFRTMStyMUVvZDkyQUJSWEZtc2FreExwWk1QRzUrZTF4MnQrMjhUdDFRWlZnbDUwRkp3cGdiMzJRdmw3YzNJZ1ZaenprcUloTnVkcWRNb1NjNEhjZXJwaWRrYjJpU1NJN1V6WnRORnlidHlXVWh0OTlYT2M4MGc1YVJaRWRGc2djTU9RSWp1U1FCUDV6R01RMXJYMC9hTGtRK3NFb3VkNzlUMnlFNU8wUG4zaFdwbGZaSGFaRUZlUVNxTVl0WndvOWJHcWRhbGswQ1FUS2NMTjE5VVIvc05aZ1RtN1c4emFhQ1NTdzd6c1l5VkNQZXVTd1JnRG44aU1YK2ZiaFlYc3VMSXgzMjA1ZzQ5Y3ZCSGpVOE1rQzRXbFZXaURNQ1plbW00eDBueVYwL29FWXkveFVkeE12dzJaanpRUEJ0U1hFVUNsNzhhakR3b3FNTThzUlV4ZWt6Wkd2dE5WR04wWWhjWnhGVTdtUC9EejRocmVrT1lkWDJOalJHSEJuaG9kckw1aXN5dzh1Z0EvS0doUXZjcWdoWk1nSnl6dHF5eUFpMFFmbnNlWFNMaGw4bGJlZkVDcDI5QVdjZ2RkYVVVeGtsQmJkRUdOU2oyQ1ZxUG42Nm81L1FJSkRUYjNsZHM1dk4xRWlIVnVTMTFqdElwWExFNzA2VER4eXlKZ0VRdy9sS0FBTXFUbnNuV2NQRExFT05RS2tIUXQ2NVR3UVltc083dk1LR0RiazdJWnpmNVhsWGlnaWRLakl4ekRPT2NGOXlXc3RtV0VqRTlOVkxJNnhwWThBSmx2dVI5TnNGMzhuUjNLejhjZHlZWFFObGVHTzNneFNmUTdqQVVXWndBM0t5ZDhCaTdtanVxTndOcHlKTjAxTUFORGowWUV4ZEZ2ckthbVpCZmV0T09ZNkJ6U05tbmx2NGFQRElGclpUaUpKY1BTaUE4akRPVzZZRGE4aGtzVHBFeEpuS2JtM1JPM3hYVHBtRUFkQllabkZoZlBMQU9wdk9sTEdOcGRXWE5DL1diREwxUDhDaEdHT05VeCtQQXNidk5ZWklRbXBCK0JIZ1Fhck1XUFAzMlBGYmxnWGlxVENwTnVNYm8waUU1TDF4WHFZY3puZU1NNW10eWxxWWJYSFlqMVI5Z1FXeUtlbGdBUXhXQ3BCUXYwRHNPVUlSRUNEbVRCYkx4ZTdPcTJuMTBrdFZSUFJsRjdqZk13UkpNL0h3UUpabnowaXlXWWZMdFh3aktjMjczMDh2L0xLTmR1SUMzdm1nTWNJMjV2QmpSWTQvdkpNM2k3V3dFMXdIdnA5QWZLY2RnSWdTRC82b1FQai82QnRCWVR3MWo2elBTSzhpZ25acVpVZmVSdENTSysrQ3ArRGYrS21ybEdsU1JnTUlZcHhWOW0zM1N5eHNyV1pOWkZvMFliYy9Eb1BVemk2U1MyVXRrTnkvQkdZbWZzR3FLb29tYzFGZ1NTMENTd0Q5bXdIbjlyY0pHaHVKbjVjc2tBNGN3Z0cvUkh0U2ZwRnNHcFY1dWE0QmFZZHJQZFNRYStJOTE5bzl2aWxJNGNPYVNaUWtoZzNET016L21Pejg0eHVrNi8vZGJDaXliZEJpeGN3UkFsajFFQkExTWtsdGRacXFmNjlqVTFkMU5nWjdwalV0TTJLN3hIUnpxRUFWN2pRQmRsUkM3MkNIVm56YjFBVWZDRTZoWkF2NGZVS2RwcmczbDhVYTNrUkVkWXg0TVpLMWx2MnN6UlRQNHArdHExM0lpbFhmY1RLaDREYmVVWm5pWDBvREczUVAvMk1jbHhobXh0RHRRSVhuSHNaSXB6b1NjM2JuYURjcFpkd2pabEFTY3k5R2ZrOFMvM2J4aEFMY2ZYT1lEZmJpYkU5L2UxV2YzdjRnWUpSYW1ZUm9XUnFHQ3FqZi9HSWhKME9kNGR3UGRPK2R2d0l0TnM2djB0QzRxSUdoR1ZKRmw1WFhPbENEUzJGUGhRUTROL2c0VmF0d1JHM1pER0RCL21qVnpyRUxtRWl4WStBSW53UmV6Si9pL2c1SjNKT2l1cHJuOXhUcEQzc211R0dnbjIzTUNFT21BSWxpMTU5WDdhUmdXbjBXamRWa2F6ek5KWGRaaUlHdTBreEdjb3RtYk94MFlrVzhLcDNMUVJENUVFSDIzS2JMY28yRHd0UzNtQmxJcHpGWUhCVHFGVDd2TEFXSHZaWmNsZG53WGV2aEZlQ0tYMHFIaWFPQ3YzK3puWXlEVHljamQzUDhkbXQ1RGppakVPZndhYVQvUjhjSnp0Q3BTNm84a1BlR0hVUWFDRWJvd3FjYlBOdVpMTGUvTmM4cmZKd0o5K29uM1lTRUliQzZHYkgzNVhJaDB6SlZWL2pPY3pXaUFsR0cyQXJ5aU94ZFJHUGRHQ0RJcXQ2K0lYSUREWHI4d0JITVRXdDkrdTlObmgzQjhVWFRnQndxNVZ2TVl3djVIelNpRnpsU09vaW92Rk5YbUxSbjlRREF1cHpaYVh4OUVQc1ZPbUZPcDRsVHcwRjZPd1dnWUEySGJmbXBMOVd4WWQ5ems5d3gwaHVlQVk2UTROR2VDbng4cnVid09YcVpSVmtMYldMcHlrSVkyNTNKVXBWQWxTUDkvVTIrWlZMUGx3WC9zaEZKbUdYeVl1a29DRHVpdk10WGtVcXlIcG1kMTB2dnlpQ241a1lQS09DaWpGVTNRV3hjTUJpTVdxNlBvWmdVenhpaVVjNG1SMThUOXYvc2kwZUV3SWY1RnBUMW05aVY4Ui9HclZrb1JGUmIva2VaV2k0QmpDR3dWNnl6VjQ2NVFzMWt1ODhkdzlBcStESDdVZWxVNC9vWmJVY2FMSjZQc1lTdGZHSXR6VlFQbG0wcFp4cEk1SHAwNUZ2OTBkVGF4L2tOZjhNbEw5MVBqc2NsOG1DOE10d0dRQUkvNjNETllPNFBYUllnZXdQY0RTbXpZTWtYTHpUcko3S2JLOUVpRW9vbHFFTlVQWHRZUHJZZ29DMTBpRCtnOHNJQUQzcWcxSTZSQ1paMDR1d2dMam9PNmtOczlWQ29Fck4vZ0VoSjVFRiszdGYyYVhvMTNveGxnL0xuTkQ3S0NKODJ0WUs1MjdndXIwOSt0T3dIdU1pTGZReEFCVDQ5aUY2dXVmcUlDLzV3bFdaYkUyNlNyZEVDU3laRXhIY0xjR1BHakNFWG42Y0VRK2ttSTRXQzRqeXI5NW5oaVloWkFEcTN3Y3RmVEwxRlVydFNhS0dmTzJQVXlldkxmOUl1YW1rRVJzNmp4a2VMTDJtWm9nKzU0dmpHUGhnbFNmdDdRSU15OXFGc2I2d0dLdE1mTU5IK0RiaTU1ai82TkRVYjhkUTYvMHBJcEpOMFgwdVF6NUJ1SWcwRDcwUUtaWTZmTlp6WTFpK1hmUXZPaStPdTc0elhTZitzSkhwSS9iRVRjalkwdnZUbUtuV040M1N6NERTaDZmTnliZERpdFduT1dzK3JoT1ZtcWljR0pZcGducVFUUG9DTFVxMVV0RGRtNXUwK2hrNFQ2Sm12ay8wSnBWdE5zVW9YYkh1TUJBNHBPS09IeklldmJla3JvSGxyY0ZZMnAvWE5xUUFRNXNyUk1DZTQ3V21qNlZNeXo1ZWF2Q2ZESDRBcXhJOXcvWlQ5SjhGTThXcjZsTEV3Y3VCd2x1Vi96NEg0alNkd293QWtDTDJqS2dEUlVNZFNXK2FRVlpWdFlIRy9naHR4NUtvZ1VRYy9lTzBvbHh1ME1vYzlzTHpoT2JCZlVsUWgvZ09hVnFGNjl0OGQzYjlRY1luc3hrM3pUaGpLN1ZLUW5XdDREUG5ZRE5yanU2QU1xQU9jL3hwbGpiM3d2UjVid28vd0JJVit5ak5WVU0vQUFXazg4SzZnUnkrSmFKMmlNOEpsZnJxN1pvcUtPdmxUMVZwYzkzSDVBb0dzMUtFM2tPOStHSWFoNmk4SFJFQzhYaU1hd010Zit3OUJZcWZvVjNNTXhHMExTRmpSUU1oaUY5TDd6VEZNRGRVNnlDMFpYMXE3a3pHSTVuMUVFRGdWY0JkY1dwTVc2a3dhYnhFdkVNZHk5dFk3Nk5GMTNWc0o2blF5dHhIREt5YVNiSEFqaGRXNllqaXhiYW4yd29JbnF0VUtNVTZmSEpQNlVqc1FHK3lWRml3Vy92TEpZNGxaaFZMZlhzQlI3ZENCZGtycWF3MjNZNkFINjRNcFRmK2F1c2E2WURXMWltTkNpak1EaWRYWkM4YVEwTytGaHVvbGtQYWRSc0dYbHBJRXN1cGJob2tCSGpVUXYrK2tyTGltQUphUHV3U09pdGM0eGdrcWhUYnFFL3REV3JVaFc3QVBMSGNBdlVVb2FoU3ZsQmVaZER6dThCZDVtakh2cElkd2NJVWREd2RNSkMwcmxXWnpnaURIMTB5UGY2aDRhbTErM2VsSXIrb0FCb25iMlRnaW9TWmZQV3hkTDR5blNXUWd3WGtkSFlVcHozeklCdlUyR0oxcnE0ZHE5b1ZNeFdjQitHSllxWjhXRWlSZHFVUmdHSVRnRGNHU0UxMitLOUVkS0xBOUM2ZVV2elptQjBMVWVhRkpZeTJndWxXdnlhRk41dXBMem92OERPWkFESVBSYjlLV1VEM29lTjJrZmRrMHVaWThHZkxrclpJNmloZEQ2T2YyTVNBZHFIVWpqa29wcVNXSzVPaml5a2VyZytqRmRUSkpWaVRBazBTY1VvOHFUVGVKcjZKQnpUS2V3TUxya3k4Sy9UN3RUWUEzTGtCUGV5ek92R1hQV3NpQ1lKeTErbWpHTDZRUm5acGxNL0QrK1U5UVJrTEJNcEF6NmtVV2Jkc3FZZFBBWVlCWWJEeEJBV2pwVzBlQ0x4WkRhYVExTjhhTFJ5djdjOUYzeWI1ZXU4TUFzcWhseTBpWFd2Y0cvQTlQeUdQTzJqLzNYc045b3B4VnRnTEZwYnpxRlYrci80LzhKRUJLYUd2amh4NVNsdWQ5UmZILy9lM3h5RnlSa0RNYnkvRWxwZWkyR0JWSWZJYWxnVWFsYWEvRWVZdTkwWmJ1dHZNQWd1VDJmTGpRVURyWWZLTGFLQWhKeGJSVmdsb2lHUHo0ZHZiZEtaS2JER2FMZEFoWEd3cVZjSFkraDMyTWF3OGI5MWdMdHpLY1NzQmExTlNML1JvSjZIV3V4TGpHTnZqMXZRUGtLdFZ3ek5LNkwvejQzMjRiZzRWOWU0QzJLeXE1a3NlRmFINEN6cFpMNVp1dUptMlVmVW92VjFqcVU5SjhmK1FjaUliNVFMYXhaRnB1RU05NGdlOWhpaU5iY0Q3ZDJ2UWRCcTNqeHVuY1VKdXVoSDB0NEdRZE1yMWh6MUdHZFZQblVJTWMwUmp1ZEVSOGxBZ2JrUmZxa01nMnNzYkJkOGNDNUpQOEJQTEYzM0t5RzFxVXUyZnM5OTRLWExCOXpLNG5ScStxUGdCcEZ4bjNzaWtWek1zUStCOGdMRlZzUDIvdGl3TzlLZ0dZR2Fya1JKU1Fwc1czYjdENzdtcllHcm1WQXZrR2tUVGlRb2FWTUV6OENFRFp6V1JaSTE3MjhPdHpWekpWdnM2S25ERHZXQ1phOTlkSm9GM3RiQUZRMkROR21HVWQ2NGZ5dWtQaW9Wdks0VVZYZUpETmEzWmhhU0Z0Rk5mSlYzeDFqNGN0ZUI2M1lCazJzRTg0QXNRZEZSeW5SS1ZhT3BqUERVL3pGZVdqd3gzT2FKb2lKMDFtODIwcjVCOGZnbTRUVzIwS0lHdWFSdTNFcWRkZDN3M2g0NUR2VzlleGhwRDFNcGszOVBEb3BTNTd3K2tsRitxbEdyT2RLTk01M0FwMS9wdHkyczZHMGpxa0FwOUE1Wm1rT2U5aGUxd3d0N3Rjckh0UlZkcXR0YkRjQ2dnZWpTMFZtb010dW95LzNVL01WejVwb1c4eVRXTnpHQnVjVkdYNXBQTVNEb2g4dzRwd2ZreVZmYkQ5cDg0SkV1WUdBREREOUw2aHZLTWRhZXE2QTY3bXE2TEtwU1B4S25iT2ZzM0t5dm1zSU1aVi9xeVArY0hiUnNLcWJxc2RtK1BMRnl1ZmFJUjFQKzB2aWU5aUd1NWNLbkpCRzVRVmNpc2dxQlNBTDVHZEZLeFF3MndVZlE0UFdlNk9tNDBlQmkzMFIzcG5FdTNSbzBQbHJ0OWVDRTNGeS9OK1lBVmlwWGRXd0tkSGF4bFV3cnR3em1SbWtta2hVZTJvLzFXL0hoRGxCVnBnTUJNWDdFRUd1SDlwWTZ6VzJUbU1uVDM3eGFya1llRDIxdFUrbmFhUzBwZVJoeTltMUxWMDg4ZVZOR204RjRWd29qL2gyQlBZNFVZRk1ReWI4anRWbUhmT2IvMGZXWVZWVWNJMEM0b0IxZHFKS0phSG94aHFsY1Myei9UU2o3c1p3U3NXTjlZY3hzdWNvUkFXRENjYzJGbVIyNmQ0TG9LaXg3NXU2R1Z0UExpN2tnazc1TWFGdmp2NThRaCtBSDFLUVB5Mk90dmhJL2JPOGVQeHpxNmI0RytmRUUzRlh3dUtOVnF5SkJNWEl3NWZWdU5Ia2VEMHR3OGdiWlVEbzRIY2F1czBYTWlqdmVaVC9oa1lMejdVdTV2ZlFQY3lwdTRwbmpvek9oaERGaHhyS3Bvb0d3VnFOdXk0M3FJdFY0Nk1mRFgrQVZZM2xxZTAxVGExY3VZdmVFeFk4UzF4a0Z4SkRMZU05M2xKRXNVWXVjODNiczJUVks2UmkrSEQ5anZzelY5NlBKdHNGNXVrZmc5M1FCbnVHL0QwcHRvdmM3YVp2RjBGaWtUdUdsYk9KYStwZEtQaUpBVisvTDZOTjh0ekk5SldiTU1hN290NVpiTXErVmdveW96TytReDljN29SSndrTGxMdGNEeGJvbHdqcWxYYkRCdVR0VzZYS2xrMklMNEhhWVgrcUUwUDNtN2xCYWdDRGQ2NE01dSs2SW5LQXJ0b3htVmpkNENWMmFjNDF5MHEzSStRS1FnellXZFBabDgxNm9TUDVPa1BrTDNmdGtJd3lXRkM0T2Q5ZG5PL01RSzBqK1JGQnhmWFhLZlVPN0FBWUxvZ0laUncrQ3JTc3VuZlh2aUl6VVNIdCswYVpuQlh0M1U4QlpHVHRaenRSUUo5emhacTA5OXAxOVFKT1V1dDdGdzJRdXA4aVozeEpMU3MrVkp5aTNwcmdlZ29jM0thY0VjY1Z5TkVpZ204QmdhYWdIRHdndDNMcURiVmNlOExDejVLN1ZuQWNHaU03V2prZ004M0s3dExsOXpLa1BXbjUvLzRIME04SldaMUdhT0t3Q1BHM2l6QncrYUVNNENuOVdjRS9YcnlmUlZwS0VhQnN1djJBSm1WZ0pVWHZPRUxjSmkwb3JxRCtxbFNHRi9tRm84VURNNWMrYitCQWdCMHc2NHYxY3NSdHhtYlU4N2VLK05QZXhDU1l2aVlzTEZoeHhVOFByTXVZT1JsbklCN0RnM2lROWRYWk9sSVJVNFp6UU1zTXRmSWdRNitMbDNiN0dWSEp3SzE5OWNjZjh2Zit6TEw0RDFUSG96dnVwNFVUSkNBQnVacDVmL0xaZHZOb0p4UUQzbjdnc1NHVkRTaDQveWdqY05pb2JLRFg0Z2FSUFFsckliNXpFNVBrNnBwUTE0Q2gvbkYzU1ZmbGluMWxWUVRwRHF4QmE2S0tMS0NqRkdRVWVRSkR6Z3RDMEdUcktUc3BaZG1vYUNCNDdMUmRTK2xocWsyTG1rQU1zeEk1aUFYa2h4MDJHVnZZT2ZXU2VFcEdOWG5nUXhDUzJqU2xNekZ4dFJUZzUrZkJvZmxUQlV6TDZuakhmTVk2NzAxUkkzaHdxYVVPRFlad3NrdHhXWXVWR2JUajl4VDg3aTVuVWpKcGRicHBZNHZKRnNtbGhNcFVBLzJLRTkyS3NtajRuYTN1U1haTDZSQmJ6Ukh0Q3I5K1F0M2dlWHU4MjBxNUY3eFdzaTJ3SndMdldnRkFkQWJPSmpMMm9iQXIydDdtOWdGVU5FWmpIcGlTYWFLNk5lOUFvSTAyMisyZjByaWQxc2s1TWVobE83SDFmT1FtUVZaTkJoYW5USEtxeTZTOEdsUzlWdFNEaGJEcXFPcDRqbmtsM1NYL1lhcjh2VHNIN016V3h4S1RheVNzcUFXMTRHRVptSjJnd1QwNms3RFh6YXBXZFg4TFAvK0dPUHZFLzJLSHRyMFJ3QXZJQ1I2OVdFZVA2M0F2RDJVOU5YRkxlRE54RTFPV2tMenVWRUVYTER3NTYxeW5Gb0s5cFMwcExWbGZ3VnlJY0tSTWVpNW5qWm1MTmIrUlRuVXljNFU5WEtnNHFmSFZ1VFhDcitRL0ZFbVEvVmtUSktvZmgwd2psUGhBdzNzVUw0NTJjN014b2Vnb1B6QnZSZW83akw2WDFUOHJDMjlpUzBVMGFmVjZtN0ZUc2s0UUpTWGtYU2RKekR5dm1ZeS9kcUFyV0Q1WVJhZmZJR1BUTzVlbGEvZkR0Y0RTdXllb0hHV2NXdEhjM3ZvL2RmbVFJaXAzOXpiUmVodll6bFROL1FVTTgyQWE4aHZHNXBOb21uck13amZvSjc5V2FoWXlxUWtMM3A2c3JVN25yNzBRbE43UjlPMHlWZGtsT1FKcmFldUJCQkNTZDF0VjZRTUtxUzFsb0ZBamcwR1dwOVhldy9PbXlsbXJQT2tDcmNIQ0w2dmRseXMyZTlOaVZjSXlCTGZZeUt0VEdaNndtL04vSUNOMnJWMUZrUndBMFRGRjRzUVNpV2N6L2l6REdyMy9zb3FkZy96eDk2UWZ3SUk2ZFBaVEFVdFpOcFdLOFlNTFArZGlFdGpTZERoZ1llU0h5NVJwWUtpYVNVL3d2WEdjV2xCdGlYeFhpby9GTFNRWFVZMlppNUViOEFoczZzNTM5WkdaeS9ENHh1Y1hXdjRRcHAweHZnV1hxS1ZNbEUwd1Q3VTBFQWs2NVZkZmY1UlIxVUdZOHk2MUV1VFc5SE8yNGMycU0vcTRoQlEvYTUwcmlVT3dQV0F1WU5uMktPNEVSbFlHdDJqeVBzQ0N6YmFWOTRTTVlzcGlsdng2YkFiTjJSRWJ3YUFKM2FvU3hLSlBsTmNyMFlwM0Q0N3kvcXpnOFlzZ2Z3NmtkSll6MnpsTlJxY1R5MnRISzVzMkRTMGVCY3hmM1hqdVFtYlBobm1XVVVuQUsvYXlYOEwvbmdwaURXSThwWTNjM1Q0VWgyU3FQZ0Q5Q21STWN5NFBSeXBlQzlGa29vSHUzMTlJU1FpWFd1SlZnNDJBSEM1NHNLL3lFckJEcUxCYmx5ZmlYekhUc1ZhSnZnRGpwNzVtSmNwR2RoemxHS0dnMkkzOUc5OWhwUktPdVNBMVJ1UFl2TUFhYmNOTFB3U2VRUGdMTUdMT3ZYTUFuemllcW01d0drTTFncStVajhZdUxOMEdyRjVlNHVEdWcxSjRKckRHZmdCc3pRczUzTVRQU0N5UlNpL2NwcGFDTUI1YUl6eEwzWFJMU1dzS2VmMTgxc05ad3lDUi9KYmg5aWs2d2pKaXpCOUpHZ2xocTZlZ3BFRTgzZ0FJMDBOQmt4VEtsSXZ2dVhrbU9MMXBZeEc3Tk80MEpObnYxOTJabGlNRHFBNHQwSjNHTitaMmxld1o4SmFmZlFDQWhrditVQksxSWpkR2dENGdBcTZxV3hzWHNiMTdMVi8xdlpuSnZPNjBJMG1sc0o2a0xlb2ltYXlnTkJCTzVOR0tOanNBSXd5WENub1dsT2Y2VmlIMng2VEJkMGdqbThkdXBBYndMd3RyNGJrcGdlYjc5T1NOZTMvRWNwcUlSNEtpUFNLVWR4TVpKUHBFR2NUcXQvaXJ6VWJGWjNjZUI4M2MwTG8wbHVERnJNWWdnd2RlWEQ4QWVhako3RlVSODZqZkRpYndDV2Q4bjRGT0pvSEFxcS9DM1E5bHVmbFFHMHBQb2ttTHlCenEyemZNa3R2RUVjSEZJeGVCQUdZODRDZnd0NTBlSEEzWUQxd0dCT3RoUDBGaUI3S2xuazViNnlacHAzekhBQjlPOWp2K3B1MFZjQllMeDByTngzUW5oYlhxOEdVT2t0b2k2NVI3ZGdqNFdkVHFNMFFhVEpoTm84QWVqK3pVeVRzMDRBc3pHRUhrVlJmVkRuSy9ucVN4bkkvOGpNaFBvbGlNMWxtSUZuUVZ3YzZCd3kyaUxQY09naTQ1WDZ3VVA5YmNlcFlZbW9vRVNkS2Y0NWNTVnFrQjZkMit3cUVNVjVvS1RXU0JTdEhYYW10QlZkdXQ3cFl6c0NESDRhS09KZzdyelVXNllWTWpKZ3RwbWVQVGJmc3hpM1pmWFVnZHZWbzEzQTlqdS9XeWM3cm5EbHZYZUkwdHNzQ2owT1B0TVgvN252bG03RUEvVW1nTkh5dzYweWpjVUJXZEJKMDJMOXA5V1NTZG44cmFGemRmM1ZzMHJscGF4ejhUUS9mcW50QTNQNnRMb2d1T3RndDFnY2VhZlZPVk80anJjcHQyS3dkb2dZbElDcjhGSFlvejZuQnpvM2ZpcjBBWkRMdjRmUHB6Z043S0MyZUpZTC9LblBCRnBMK2V2bm9nbE5HTm9ROTc3bXp5ZzFJN2hxN0dUdit4a3M1R1h3T0gxSm1LUUJseTFENXd0V1Q4REV2eEdZTlJFSk5TczNURG9ISzFEa0ZpR3phcFIyaEpPckNSZk8vaW1jRXNZUXVwcFZ2dnFCVUl0RzNnNk00dEtPeTlMbUhGQS80MzJsUGtXYnhnaXVlQ0dKalpNdnRLTGdEQ09obGUxRm9MRnFRVHpoU1ZQdE1hMlRKcWdqdWJBOU9EbmtpUjQvQWVBaytDQzdWVFpGZXpDdnlkdlBwUEJoQXEyaW9UNk4wS3dMZDBGRnF0NlNpVlpQSDl5cTRrUzd1TjlGdW1WSzBVd04vdXA0VStjWGdzMGk0Uk1ZQVVuWEhwUVhLRldBTkJOcmdDT3JPdXFlTWpXRUNua3NLejdIK05nNWpPaDhpK2sxVFR4bVJjYkRNdjFZY2QwM01NK1ZZZW9pdWRZdkh0eEtMWjg4cU1sTWlPaDBFQkF2aGFSNzZzSWJmWW9oRXk1WWl4ZmdpYy9RbWplYVFmNEpCeUk5MFJQSUJxZ2JVcUgzd2lYWkpPSlhMZ05pa1FFdGRFZUNxRnZRazFQcE9kTkNZNFQxYnAxbVJycml1UGVTazBBQnZqYkRXTWx2dHI1dmNOUk1jcUFPSG5mRVBZc3d0amNXMlI3WEtIVWRIYTcvUU5FeTd1Ulhvd1FsVTNUQUlIbUlnUkl2aFQ4aGNOZUZpM2ttU2FvN1ZpVXBZKzBweUR1emJuZjJ3dEJRUVUveTl1YWRXMlpVNzRXdHAzVW1vR3g3S0t1NC9yNEFZcEdwWjdVM28wMUR5MDM5VkFjS1oxQVdoRHJZaW4zcmo2cEN1Z2d0ZXBGN2U0aDcxQm9jQmpMMG1qaWFYYU1vdGRFcERJeXRkWVo5eDZ1em1XUjNDMXVCTFc3ZlZUVzVDN09mL0dZbTBvekdYaDFkdXlXU1NmbVBraG1VQm9NQldhQWJ0NjExaFVJU2lsc0Jra0JVeEZiYVNLSlh5aTJ0TlRkellOUU1HQ3dPUkowbEVWRW0zbHIzVmpYS2NKNVpZZndQeUxzVmk4ZlNmRzQ5MDNFc2M0VUVIVTRUeUtldmVlOWI0VXBsenRnRGNjcTlRYWpwbWdvZFFvam14V0E1RmFNbHZTWVA5V2U0Y2pwZGdSMFYxK1dxZzdLc20yVmZvc2pmWnA1eHk0Qysvam5yaVpaYzZHM1VGSUdJUUpzUzF5eVdHMnZrcnI5a2ZQSXNJTm55QnZ3RXEvUE00UlZMVkpNQkRoODBxZU9uT0g1emVnT3ZGcVhjOWF1QXlZS1RNTENVVnZ2VWhpbGFycTZIL205RWNSWC94c3VYaENxWUt4ZXVncms2ZmRWOFdSdG91ZC9HbnRpS2FXUUZwRTR5UkpSSG9iUnIzd3dzMnBKUGNMMjZjU2RhRS9wL3F5WDY0ajBJSXc3TWl5c1NBTzdhc2RSd0RWYXFXQ3Q1VlROMk1DZDlqbjlqSWZDSkxkVm90RWVpRmlNMHFORko4VWpqNzNncGNJaDdHOEdmZ096RTJ1TFVNTTVYc2x6aDh1KzY5azhxOXpBL0xtOTFhUzB4NUVnUEtRTzJlWW93VTBQTzF3dDFSNjE2UGNSUmVoUWJaLytWblppVTJJUlZJWi9PQ0ROenM4N1FxQ0dEOGZoUnd4Wk0vWkVMdTJkdk5FNldLazYrcWZDMFU1d0dMbWc4VHlxTksvRDJxV0VpTUpOdDQ5d3FNVjdnL2dEOSt6RkUvblZLd3VXZlY2K3JVc1hDQ085THlWM25JVlUwQUJEazZzbkpLU1dOZVRIUzd1OFY3SmZleWFpbW44eW1IUUFZTHkvbFZ4Q2cvbDRNQTlvUkFic3djd1o1TlI0Wk4zU1dyWGsyTHcxbm1pTlRud3lxQmxuN2VXMDYrZVluTWNINXBpZEg0ZlJjSEp2blNZZ3J5QXptdzdRWEZIUUdaQkNaU0l5RzNXMUlyN0h4ZCs5WFNtWjJyYk9NMXUzb25ueUJtc051OGJEd2xxNWprNkQwN3hVZFZVSkdhbE1CL0V2L2VDUUl4MmhsYWpTYTRnZHpJWmFpTlAvVDlTWlpXK3BCZW03OHV6VXZROTRHRWNlTFpVaFhkVmlXbHBtMEdhWEl2WnJTd3lRYUF3RmtUOFphb1pya0taWFVXUzlhU1N0Rm02bFdUdk1CazVPa1lyc0dkQWRaa1BSZ1k3aWJFZi8xdEVJZ3dHMndMaDhVckh3VG9zVUl5eVE1YzlZSzBNclVUZ001NkN2L1dWNk1lY3R1bXJac1ZSQVZGOGUyYXFtK1R5VTc2RENrWXVDOEtJbit3bFB0Z1lYUWNwS2JnbmdSYXZrYVZuVzBVZHVZTno3YTd5UUVFZG1JM0pDYkk0MWROQjdPbmhzdTBLekFVY2ZvazZzQy9HOVprTEVFdnlzRWcxYmJzRlZvODh6YmRsOUFBMndhbW52YURQUVJPNjZhNkx4Z3lkWEVLYm5hTFZuSEpIaWRsK2lKL3dSUkNPbEZBVkFXMkRBQUFBQWdBQUFBRlZoaTdGWjhTNXJHOEdTSzlZRDlKOGhyNWRKWk45REdtR05XenpLR2FsOWdBQUFBSlFQSEtxZDhRbHVxZGpRcGFzY0dqMmllSjdmQ25sS2RXbC90akNYZkJ0NEE9PSJ9fV19LCJpc3MiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDEyMzQ1MTIzNDUxMjM0NTEyMzQ1MTIzNDUxMjM0NTEyMzQ1MTIzNDUifQ.uryGpv29Z9cproNznkDOniabWca-3aAhFemJxKfHGKE74bBoe5Oiikk8V-kc0X67bb-srvIHJQ_-xvDo7HZh1gA"}}"###;

    pub const BLAAAA_BLINDING: &str = "T7AnWPspRhzu8cBR3ewp2mm18iOAYLIXk1k81uIVTaA=";

    pub const BLAAAA: &str = r###"
    {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https:://schema.org",
            "https://w3id.org/vc-status-list-2021/v1"
        ],
        "id": "f1659f6d-45cf-4021-b4b7-fcd8cca27556",
        "type": [
            "VerifiableCredential"
        ],
        "issuer": "did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6",
        "credentialSubject": {
            "id": "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403901",
            "data": {
                "test_property_string3": "value",
                "test_property_string": "value",
                "test_property_string4": "value",
                "test_property_string2": "value",
                "test_property_string1": "value"
            }
        },
        "credentialSchema": {
            "id": "did:evan:zkp:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6",
            "type": "EvanZKPSchema"
        },
        "credentialStatus": {
            "id": "did:evan:zkp:0x1234512345123451234512345123456789#0",
            "type": "RevocationList2021Status",
            "revocationListIndex": "0",
            "revocationListCredential": "did:evan:zkp:0x1234512345123451234512345123456789"
        },
        "proof": {
            "type": "BbsBlsSignature2020",
            "created": "2021-03-16T14:55:42.000Z",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6#key-1",
            "requiredRevealStatements": [
                1
            ],
            "blindSignature": "gilsq3gbasMlP1RDj8m5xaU8obp9WGKKkyHm+p7YpxAlvugbnwM02vXG7zAgZK1jHXuHeshHdVHKXrJjk8wZb9n2smVew9s6HGLIy+P9xjIDknkm2Ussf5grIUiUKBR8T6rnFeFgbQN9yBibwz1Clg=="
        }
    }
    "###;
}
