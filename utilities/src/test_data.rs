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
    #[allow(dead_code)]
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

    pub const EXAMPLE_CREDENTIAL_SCHEMA: &str = r###"
    {
        "id": "did:evan:zkp:0x123451234512345123451234512345",
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

    pub const SUBJECT_DID: &str = "did:evan:testcore:0x67ce8b01b3b75a9ba4a1462139a1edaa0d2f539f";
    pub const SCHEMA_DID: &str = "did:evan:schema:0x1ace8b01be3bca9ba4a1462130a1e0ad0d2f539f";
}
