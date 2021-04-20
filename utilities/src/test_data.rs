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
        "credentialMessageCount": 5,
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
        "@context":[
           "https://www.w3.org/2018/credentials/v1",
           "https:://schema.org",
           "https://w3id.org/vc-status-list-2021/v1"
        ],
        "id":"94450c72-5dc4-4e46-8df0-106819064656",
        "type":[
           "VerifiableCredential"
        ],
        "issuer":"did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6",
        "credentialSubject":{
           "id":"did:evan:testcore:0x67ce8b01b3b75a9ba4a1462139a1edaa0d2f539f",
           "data":{
              "test_property_string1":"value",
              "test_property_string":"value",
              "test_property_string4":"value",
              "test_property_string2":"value",
              "test_property_string3":"value"
           }
        },
        "issuanceDate": "2021-04-20T08:35:56+0000",
        "credentialSchema":{
           "id":"did:evan:zkp:0xd641c26161e769cef4b41760211972b274a8f37f135a34083e4e48b3f1035eda",
           "type":"EvanZKPSchema"
        },
        "credentialStatus":{
           "id":"did:evan:zkp:0xcac3f4186e273083820c8c59f3c52efb713a755de255d0eb997b4990253ea388#0",
           "type":"RevocationList2021Status",
           "revocationListIndex": "0",
           "revocationListCredential":"did:evan:zkp:0xcac3f4186e273083820c8c59f3c52efb713a755de255d0eb997b4990253ea388"
        },
        "proof":{
           "type":"BbsBlsSignature2020",
           "created":"2021-04-13T12:53:18.000Z",
           "proofPurpose":"assertionMethod",
           "verificationMethod":"did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6#key-1",
           "credentialMessageCount": 6,
           "requiredRevealStatements":[
              1
           ],
           "blindSignature":"oE+ETDgwAaCqmtqBhuKgft2CiCO92+hgG3uNr+GmVgRy9HLN/6SLktVURqw7AzlvbRiQqKoa65eVk++gdvY4Dj34MIOnNFMRAqQB2S0y1MkfvhFdtncP5mN7zR3/XSHf0otOUPxR6pLle8QcGBCykQ=="
        }
     }"###;

    pub const FINISHED_CREDENTIAL: &str = r###"{
        "@context":[
           "https://www.w3.org/2018/credentials/v1",
           "https:://schema.org",
           "https://w3id.org/vc-status-list-2021/v1"
        ],
        "id":"94450c72-5dc4-4e46-8df0-106819064656",
        "type":[
           "VerifiableCredential"
        ],
        "issuer":"did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6",
        "credentialSubject":{
           "id":"did:evan:testcore:0x67ce8b01b3b75a9ba4a1462139a1edaa0d2f539f",
           "data":{
              "test_property_string4":"value",
              "test_property_string":"value",
              "test_property_string2":"value",
              "test_property_string1":"value",
              "test_property_string3":"value"
           }
        },
        "credentialSchema":{
           "id":"did:evan:zkp:0xd641c26161e769cef4b41760211972b274a8f37f135a34083e4e48b3f1035eda",
           "type":"EvanZKPSchema"
        },
        "credentialStatus":{
           "id":"did:evan:zkp:0xcac3f4186e273083820c8c59f3c52efb713a755de255d0eb997b4990253ea388#0",
           "type":"RevocationList2021Status",
           "revocationListIndex": "1",
           "revocationListCredential":"did:evan:zkp:0xcac3f4186e273083820c8c59f3c52efb713a755de255d0eb997b4990253ea388"
        },
        "proof":{
           "type":"BbsBlsSignature2020",
           "created":"2021-04-13T12:53:18.000Z",
           "proofPurpose":"assertionMethod",
           "verificationMethod":"did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6#key-1",
           "credentialMessageCount": 6,
           "requiredRevealStatements":[
              1
           ],
           "signature":"oE+ETDgwAaCqmtqBhuKgft2CiCO92+hgG3uNr+GmVgRy9HLN/6SLktVURqw7AzlvbRiQqKoa65eVk++gdvY4Dj34MIOnNFMRAqQB2S0y1MliczPHpGAAlQkz6IzrPhwjfq9ZO9FlXdd4OwbfHRaJtA=="
        }
     }"###;

    pub const UNSIGNED_CREDENTIAL: &str = r###"{
        "@context":[
           "https://www.w3.org/2018/credentials/v1",
           "https:://schema.org",
           "https://w3id.org/vc-status-list-2021/v1"
        ],
        "id":"94450c72-5dc4-4e46-8df0-106819064656",
        "type":[
           "VerifiableCredential"
        ],
        "issuer":"did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6",
        "credentialSubject":{
           "id":"did:evan:testcore:0x67ce8b01b3b75a9ba4a1462139a1edaa0d2f539f",
           "data":{
              "test_property_string4":"value",
              "test_property_string":"value",
              "test_property_string2":"value",
              "test_property_string1":"value",
              "test_property_string3":"value"
           }
        },
        "issuanceDate": "2021-04-20T08:35:56+0000",
        "credentialSchema":{
           "id":"did:evan:zkp:0xd641c26161e769cef4b41760211972b274a8f37f135a34083e4e48b3f1035eda",
           "type":"EvanZKPSchema"
        },
        "credentialStatus":{
           "id":"did:evan:zkp:0xcac3f4186e273083820c8c59f3c52efb713a755de255d0eb997b4990253ea388#0",
           "type":"RevocationList2021Status",
           "revocationListIndex": "1",
           "revocationListCredential":"did:evan:zkp:0xcac3f4186e273083820c8c59f3c52efb713a755de255d0eb997b4990253ea388"
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

    pub const SIGNATURE_BLINDING: &str = "QrUiae3o8K6luBtu6+D6Q6wkCurVE3NEkr9CwwUF1yM=";

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

    pub const SUBJECT_DID: &str = "did:evan:testcore:0x67ce8b01b3b75a9ba4a1462139a1edaa0d2f539f";
    pub const SCHEMA_DID: &str = "did:evan:schema:0x1ace8b01be3bca9ba4a1462130a1e0ad0d2f539f";
    pub const PROOF_REQUEST_SCHEMA_FIVE_PROPERTIES: &str = r###"{
        "verifier":"did:evan:testcore:0x1234512345123451234512345123451234512345",
        "createdAt":"2021-04-13T12:53:19.000Z",
        "nonce":"XWgrfaNTKs1owMRpmKNj8+CuRZJBC5BRCIErRv+DPUs=",
        "subProofRequests":[
           {
              "schema":"did:evan:zkp:0xd641c26161e769cef4b41760211972b274a8f37f135a34083e4e48b3f1035eda",
              "revealedAttributes":[
                 1
              ]
           }
        ]
     }"###;

    pub const PROOF_PRESENTATION: &str = r###"
    {
        "@context":[
           "https://www.w3.org/2018/credentials/v1",
           "https://schema.org",
           "https://w3id.org/vc-status-list-2021/v1"
        ],
        "id":"c437f647-3416-4bc7-9b4e-dee14bfff2bc",
        "type":[
           "VerifiablePresentation"
        ],
        "verifiableCredential":[
           {
              "@context":[
                 "https://www.w3.org/2018/credentials/v1",
                 "https:://schema.org",
                 "https://w3id.org/vc-status-list-2021/v1"
              ],
              "id":"94450c72-5dc4-4e46-8df0-106819064656",
              "type":[
                 "VerifiableCredential"
              ],
              "issuer":"did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6",
              "issuanceDate":"2021-04-13T12:53:19.000Z",
              "credentialSubject":{
                 "id":"did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403901",
                 "data":{
                    "test_property_string2":"value",
                    "test_property_string1":"value",
                    "test_property_string":"value",
                    "test_property_string3":"value",
                    "test_property_string4":"value"
                 }
              },
              "credentialSchema":{
                 "id":"did:evan:zkp:0xd641c26161e769cef4b41760211972b274a8f37f135a34083e4e48b3f1035eda",
                 "type":"EvanZKPSchema"
              },
              "credentialStatus":{
                 "id":"did:evan:zkp:0xcac3f4186e273083820c8c59f3c52efb713a755de255d0eb997b4990253ea388#0",
                 "type":"RevocationList2021Status",
                 "revocationListIndex": "0",
                 "revocationListCredential":"did:evan:zkp:0xcac3f4186e273083820c8c59f3c52efb713a755de255d0eb997b4990253ea388"
              },
              "proof":{
                 "type":"BbsBlsSignatureProof2020",
                 "created":"2021-04-13T12:53:18.000Z",
                 "proofPurpose":"assertionMethod",
                 "credentialMessageCount": 6,
                 "verificationMethod":"did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6#key-1",
                 "nonce":"XWgrfaNTKs1owMRpmKNj8+CuRZJBC5BRCIErRv+DPUs=",
                 "proof":"AAACHKQyOOUe2WlFaUzgFxCE3tRxqGnxSfLAi1RXebnMTH43riF6lBZCLoY+urlTEP0rQ4B278gwpMNNDeS+DT9GSBTi8Pqvx0y3Xu3p1Tev6FVK9OKqpgXbe0OF4XXgfKCaT6r3P6fuGoIWkM292peKRUtt7vzpvqurLepdG8mjxHW/zxBSVvVHptd/zawVM1ekgQAAAHSCUWt42jV9ESvRp9dSwxUTm6U2tBhByoxhFblRbU6VtkmyGczGppORwqOm/PdTG8wAAAACCf+Hut4+/oDUun/DR3JOd9mY7CuxSfEbMN+AcarGI9QbHeQmNkq7HhVrLX9n1AIjn+E+IU71Ob2rGMkg8AsBl5h6hmG0K/RNmReylya50r8fympJQ3uRf3R1hnya7D9M+JSj9afEPnDuNW1fNzxFnQAAAAcQqAlkMkN9oRbAcYqJ4L66/gfuUBxx5glGjSgMf2gpNTjP1JQlXgGnnOkLE0DOPuOgCkPwhRL1TaX6FbAmylOlTX3syXMH7OaW1sWduANqgiIzGsuLdblEk/jmJSHlwukXDW1lfCNm2IKGur61DK9+abzqNwhflR9DOBA+qRTVhmVjvpa+tAWzvBHaEzT6GgDJrZKiA+RAwVtvP9Qv5877WEd0x3QiezkMnp5inE3Vx+xSBnCzxOKJ/xWRgvUIuAwarGLS1KXzOfOKEWlXEP/bkC3Lq3i71MttbwGu33GGqwAAAAEAAAABVYYuxWfEuaxvBkivWA/SfIa+XSWTfQxphjVs8yhmpfY="
              }
           }
        ],
        "proof":{
            "type":"EcdsaPublicKeySecp256k1",
            "created":"2021-04-14T13:38:50.000Z",
            "proofPurpose":"assertionMethod",
            "verificationMethod":"did:evan:testcore:0x1234512345123451234512345123451234512345#key-1",
            "jws":"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOiIyMDIxLTA0LTE0VDEzOjM4OjUwLjAwMFoiLCJkb2MiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3NjaGVtYS5vcmciLCJodHRwczovL3czaWQub3JnL3ZjLXN0YXR1cy1saXN0LTIwMjEvdjEiXSwiaWQiOiJjNDM3ZjY0Ny0zNDE2LTRiYzctOWI0ZS1kZWUxNGJmZmYyYmMiLCJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iXSwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlt7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Oi8vc2NoZW1hLm9yZyIsImh0dHBzOi8vdzNpZC5vcmcvdmMtc3RhdHVzLWxpc3QtMjAyMS92MSJdLCJpZCI6Ijk0NDUwYzcyLTVkYzQtNGU0Ni04ZGYwLTEwNjgxOTA2NDY1NiIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiXSwiaXNzdWVyIjoiZGlkOmV2YW46dGVzdGNvcmU6MHg2MjQwY2VkZmM4NDA1NzliN2ZkY2Q2ODZiZGM2NWE5YThjNDJkZWE2IiwiaXNzdWFuY2VEYXRlIjoiMjAyMS0wNC0xM1QxMjo1MzoxOS4wMDBaIiwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDBkODcyMDRjMzk1N2Q3M2I2OGFlMjhkMGFmOTYxZDNjNzI0MDM5MDEiLCJkYXRhIjp7InRlc3RfcHJvcGVydHlfc3RyaW5nMiI6InZhbHVlIiwidGVzdF9wcm9wZXJ0eV9zdHJpbmcxIjoidmFsdWUiLCJ0ZXN0X3Byb3BlcnR5X3N0cmluZyI6InZhbHVlIiwidGVzdF9wcm9wZXJ0eV9zdHJpbmczIjoidmFsdWUiLCJ0ZXN0X3Byb3BlcnR5X3N0cmluZzQiOiJ2YWx1ZSJ9fSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6ImRpZDpldmFuOnprcDoweGQ2NDFjMjYxNjFlNzY5Y2VmNGI0MTc2MDIxMTk3MmIyNzRhOGYzN2YxMzVhMzQwODNlNGU0OGIzZjEwMzVlZGEiLCJ0eXBlIjoiRXZhblpLUFNjaGVtYSJ9LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiZGlkOmV2YW46emtwOjB4Y2FjM2Y0MTg2ZTI3MzA4MzgyMGM4YzU5ZjNjNTJlZmI3MTNhNzU1ZGUyNTVkMGViOTk3YjQ5OTAyNTNlYTM4OCMwIiwidHlwZSI6IlJldm9jYXRpb25MaXN0MjAyMVN0YXR1cyIsInJldm9jYXRpb25MaXN0SW5kZXgiOiIwIiwicmV2b2NhdGlvbkxpc3RDcmVkZW50aWFsIjoiZGlkOmV2YW46emtwOjB4Y2FjM2Y0MTg2ZTI3MzA4MzgyMGM4YzU5ZjNjNTJlZmI3MTNhNzU1ZGUyNTVkMGViOTk3YjQ5OTAyNTNlYTM4OCJ9LCJwcm9vZiI6eyJ0eXBlIjoiQmJzQmxzU2lnbmF0dXJlUHJvb2YyMDIwIiwiY3JlYXRlZCI6IjIwMjEtMDQtMTNUMTI6NTM6MTguMDAwWiIsInByb29mUHVycG9zZSI6ImFzc2VydGlvbk1ldGhvZCIsImNyZWRlbnRpYWxNZXNzYWdlQ291bnQiOjYsInZlcmlmaWNhdGlvbk1ldGhvZCI6ImRpZDpldmFuOnRlc3Rjb3JlOjB4NjI0MGNlZGZjODQwNTc5YjdmZGNkNjg2YmRjNjVhOWE4YzQyZGVhNiNrZXktMSIsIm5vbmNlIjoiWFdncmZhTlRLczFvd01ScG1LTmo4K0N1UlpKQkM1QlJDSUVyUnYrRFBVcz0iLCJwcm9vZiI6IkFBQUNIS1F5T09VZTJXbEZhVXpnRnhDRTN0UnhxR254U2ZMQWkxUlhlYm5NVEg0M3JpRjZsQlpDTG9ZK3VybFRFUDByUTRCMjc4Z3dwTU5ORGVTK0RUOUdTQlRpOFBxdngweTNYdTNwMVRldjZGVks5T0txcGdYYmUwT0Y0WFhnZktDYVQ2cjNQNmZ1R29JV2tNMjkycGVLUlV0dDd2enB2cXVyTGVwZEc4bWp4SFcvenhCU1Z2VkhwdGQvemF3Vk0xZWtnUUFBQUhTQ1VXdDQyalY5RVN2UnA5ZFN3eFVUbTZVMnRCaEJ5b3hoRmJsUmJVNlZ0a215R2N6R3BwT1J3cU9tL1BkVEc4d0FBQUFDQ2YrSHV0NCsvb0RVdW4vRFIzSk9kOW1ZN0N1eFNmRWJNTitBY2FyR0k5UWJIZVFtTmtxN0hoVnJMWDluMUFJam4rRStJVTcxT2IyckdNa2c4QXNCbDVoNmhtRzBLL1JObVJleWx5YTUwcjhmeW1wSlEzdVJmM1IxaG55YTdEOU0rSlNqOWFmRVBuRHVOVzFmTnp4Rm5RQUFBQWNRcUFsa01rTjlvUmJBY1lxSjRMNjYvZ2Z1VUJ4eDVnbEdqU2dNZjJncE5UalAxSlFsWGdHbm5Pa0xFMERPUHVPZ0NrUHdoUkwxVGFYNkZiQW15bE9sVFgzc3lYTUg3T2FXMXNXZHVBTnFnaUl6R3N1TGRibEVrL2ptSlNIbHd1a1hEVzFsZkNObTJJS0d1cjYxREs5K2FienFOd2hmbFI5RE9CQStxUlRWaG1WanZwYSt0QVd6dkJIYUV6VDZHZ0RKclpLaUErUkF3VnR2UDlRdjU4NzdXRWQweDNRaWV6a01ucDVpbkUzVngreFNCbkN6eE9LSi94V1JndlVJdUF3YXJHTFMxS1h6T2ZPS0VXbFhFUC9ia0MzTHEzaTcxTXR0YndHdTMzR0dxd0FBQUFFQUFBQUJWWVl1eFdmRXVheHZCa2l2V0EvU2ZJYStYU1dUZlF4cGhqVnM4eWhtcGZZPSJ9fV19LCJpc3MiOiJkaWQ6ZXZhbjp0ZXN0Y29yZToweDBkODcyMDRjMzk1N2Q3M2I2OGFlMjhkMGFmOTYxZDNjNzI0MDM5MDYifQ.hOQj37BsG5uHqEnCygMeRDZUsH-Ra13wcvPqnHRV6mwU6C4k3LrH9ZjxyJXyGzsv8z1hHhzmdFVDPNzkhNNd6QE"
        }
     }"###;

    pub const PROOF_PRESENTATION_INVALID_SIGNATURE_AND_WITHOUT_JWS: &str = r###"{
        "@context":[
            "https://www.w3.org/2018/credentials/v1",
            "https:://schema.org",
            "https://w3id.org/vc-status-list-2021/v1"
         ],
         "id":"c437f647-3416-4bc7-9b4e-dee14bfff2bc",
         "type":[
            "VerifiablePresentation"
         ],
         "verifiableCredential":[
            {
               "@context":[
                  "https://www.w3.org/2018/credentials/v1",
                  "https:://schema.org",
                  "https://w3id.org/vc-status-list-2021/v1"
               ],
               "id":"94450c72-5dc4-4e46-8df0-106819064656",
               "type":[
                  "VerifiableCredential"
               ],
               "issuer":"did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6",
               "issuanceDate":"2021-04-13T12:53:19.000Z",
               "credentialSubject":{
                  "id":"did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403901",
                  "data":{
                     "test_property_string2":"value",
                     "test_property_string1":"value",
                     "test_property_string":"value",
                     "test_property_string3":"value",
                     "test_property_string4":"value"
                  }
               },
               "credentialSchema":{
                  "id":"did:evan:zkp:0xd641c26161e769cef4b41760211972b274a8f37f135a34083e4e48b3f1035eda",
                  "type":"EvanZKPSchema"
               },
               "credentialStatus":{
                  "id":"did:evan:zkp:0xcac3f4186e273083820c8c59f3c52efb713a755de255d0eb997b4990253ea388#0",
                  "type":"RevocationList2021Status",
                  "revocationListIndex": "0",
                  "revocationListCredential":"did:evan:zkp:0xcac3f4186e273083820c8c59f3c52efb713a755de255d0eb997b4990253ea388"
               },
               "proof":{
                  "type":"BbsBlsSignatureProof2020",
                  "created":"2021-04-13T12:53:18.000Z",
                  "proofPurpose":"assertionMethod",
                  "credentialMessageCount": 6,
                  "verificationMethod":"did:evan:testcore:0x6240cedfc840579b7fdcd686bdc65a9a8c42dea6#key-1",
                  "nonce":"XWgrfaNTKs1owMRpmKNj8+CuRZJBC5BRCIErRv+DPUs=",
                  "proof":"BBACHKQyOOUe2WlFaUzgFxCE3tRxqGnxSfLAi1RXebnMTH43riF6lBZCLoY+urlTEP0rQ4B278gwpMNNDeS+DT9GSBTi8Pqvx0y3Xu3p1Tev6FVK9OKqpgXbe0OF4XXgfKCaT6r3P6fuGoIWkM292peKRUtt7vzpvqurLepdG8mjxHW/zxBSVvVHptd/zawVM1ekgQAAAHSCUWt42jV9ESvRp9dSwxUTm6U2tBhByoxhFblRbU6VtkmyGczGppORwqOm/PdTG8wAAAACCf+Hut4+/oDUun/DR3JOd9mY7CuxSfEbMN+AcarGI9QbHeQmNkq7HhVrLX9n1AIjn+E+IU71Ob2rGMkg8AsBl5h6hmG0K/RNmReylya50r8fympJQ3uRf3R1hnya7D9M+JSj9afEPnDuNW1fNzxFnQAAAAcQqAlkMkN9oRbAcYqJ4L66/gfuUBxx5glGjSgMf2gpNTjP1JQlXgGnnOkLE0DOPuOgCkPwhRL1TaX6FbAmylOlTX3syXMH7OaW1sWduANqgiIzGsuLdblEk/jmJSHlwukXDW1lfCNm2IKGur61DK9+abzqNwhflR9DOBA+qRTVhmVjvpa+tAWzvBHaEzT6GgDJrZKiA+RAwVtvP9Qv5877WEd0x3QiezkMnp5inE3Vx+xSBnCzxOKJ/xWRgvUIuAwarGLS1KXzOfOKEWlXEP/bkC3Lq3i71MttbwGu33GGqwAAAAEAAAABVYYuxWfEuaxvBkivWA/SfIa+XSWTfQxphjVs8yhmpfY="
               }
            }
         ]
    }"###;
}
