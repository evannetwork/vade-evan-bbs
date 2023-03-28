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
        pub const ISSUER_DID: &str = "did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g";

        pub const HOLDER_DID: &str = "did:evan:holder";

        // if different from HOLDER_DID
        pub const SUBJECT_DID: &str = "did:evan:subject";

        pub const VERIFIER_DID: &str = "did:evan:verifier";

        #[allow(dead_code)]
        pub const ISSUER_PRIVATE_KEY: &str =
            "30d446cc76b19c6eacad89237d021eb2c85144b61d63cb852aee09179f460920";

        #[allow(dead_code)]
        pub const ISSUER_PUBLIC_KEY_DID: &str =
            "did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g#bbs-key-1";

        #[allow(dead_code)]
        pub const SIGNER_1_ADDRESS: &str = "0xcd5e1dbb5552c2baa1943e6b5f66d22107e9c05c";

        #[allow(dead_code)]
        pub const SIGNER_1_DID: &str =
            "did:evan:testcore:0x0d87204c3957d73b68ae28d0af961d3c72403906";

        #[allow(dead_code)]
        pub const SIGNER_1_PRIVATE_KEY: &str =
            "dfcdcb6d5d09411ae9cbe1b0fd9751ba8803dd4b276d5bf9488ae4ede2669106";
    }
}

#[allow(dead_code)]
pub mod vc_zkp {
    pub const EXAMPLE_CREDENTIAL_PROPOSAL: &str = r###"
    {
        "issuer": "did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g",
        "subject": "did:evan:subject",
        "type": "EvanCredentialProposal",
        "schema": "did:evan:EiBmiHCHLMbGVn9hllRM5qQOsshvETToEALBAtFqP3PUIg"
    }
    "###;
    pub const EXAMPLE_CREDENTIAL_OFFERING: &str = r###"
    {
        "issuer": "did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g",
        "subject": "did:evan:subject",
        "type": "EvanBbsCredentialOffering",
        "schema": "did:evan:EiBmiHCHLMbGVn9hllRM5qQOsshvETToEALBAtFqP3PUIg",
        "credentialMessageCount": 5,
        "nonce": "WzM0LDIxNSwyNDEsODgsMTg2LDExMiwyOSwxNTksNjUsMjE1LDI0MiwxNjQsMTksOCwyMDEsNzgsNTUsMTA4LDE1NCwxMTksMTg0LDIyNCwyMjUsNDAsNDgsMTgwLDY5LDE3OCwxNDgsNSw1OSwxMTFd"
    }
    "###;
}

#[allow(dead_code)]
pub mod bbs_coherent_context_test_data {
    // maybe delete later
    pub const CREDENTIAL_REQUEST: &str = r###"{
        "subject": "did:evan:subject",
        "schema": "did:evan:EiAn35ScK8_GsBE9GwMFC5BwvjZXkxEWIfmi6hAoCzvA0w",
        "type": "EvanBbsCredentialRequest",
        "blindSignatureContext": "qAXNB/irKoyqP5xQngZzmfSXzoRCrBjCNX4YlNEwJzghSUqretcaqbmfwvv+3q9SKNWHT8+KE89hN0O3h2xayXfaODIUHxe+cC90Xp27DEeu8PZqUSYlgiaJAl2bGC9Ckg8P5FbnMLQCcDkwhKK31VdbUU3X+4ECyyG4fAs7xusAAAACUOz2LiGg49dV71cNn1NgUKZW5ABf8EuK6WNzNDM2P+k/fs0c26b0DxJBbHfsWZ0Wj+ILKuckRPku7prlCd+oZg==",
        "credentialValues": {
            "test_property_string2": "value",
            "test_property_string": "value",
            "test_property_string4": "value",
            "test_property_string3": "value",
            "test_property_string1": "value"
        }
    }"###;

    pub const UNFINISHED_CREDENTIAL: &str = r###"{
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://schema.org/",
            "https://w3id.org/vc-revocation-list-2020/v1"
        ],
        "id": "uuid:94450c72-5dc4-4e46-8df0-106819064656",
        "type": [
            "VerifiableCredential"
        ],
        "issuer": "did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g",
        "issuanceDate": "2021-04-20T08:35:56+0000",
        "credentialSubject": {
            "id": "did:evan:subject",
            "data": {
                "test_property_string1": "value",
                "test_property_string4": "value",
                "test_property_string3": "value",
                "test_property_string2": "value",
                "test_property_string": "value"
            }
        },
        "credentialSchema": {
            "id": "did:evan:EiAn35ScK8_GsBE9GwMFC5BwvjZXkxEWIfmi6hAoCzvA0w",
            "type": "EvanZKPSchema"
        },
        "credentialStatus": {
            "id": "did:evan:revocation123#0",
            "type": "RevocationList2021Status",
            "revocationListIndex": "0",
            "revocationListCredential": "did:evan:revocation123"
        },
        "proof": {
            "type": "BbsBlsSignature2020",
            "created": "2023-03-22T15:42:23.000Z",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g#bbs-key-1",
            "credentialMessageCount": 17,
            "requiredRevealStatements": [
                1
            ],
            "blindSignature": "jDurIXkOk4jJkIeEhmwQpxKdr6/KA6ZN0/o5AR4N2apXbUDnyucvkiMoi6rbei9JWnpcGd9hdwG/WKgVReW4puUxSJ0tmmY4dW1zw/z2om8gGQTfmlVEkVTAn7tddmndzNs7JXKuflYKZZi+WFimWw=="
        }
    }"###;

    pub const FINISHED_CREDENTIAL: &str = r###"{
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://schema.org/",
            "https://w3id.org/vc-revocation-list-2020/v1"
        ],
        "id": "uuid:94450c72-5dc4-4e46-8df0-106819064656",
        "type": [
            "VerifiableCredential"
        ],
        "issuer": "did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g",
        "issuanceDate": "2021-04-20T08:35:56+0000",
        "credentialSubject": {
            "id": "did:evan:subject",
            "data": {
                "test_property_string4": "value",
                "test_property_string2": "value",
                "test_property_string3": "value",
                "test_property_string1": "value",
                "test_property_string": "value"
            }
        },
        "credentialSchema": {
            "id": "did:evan:EiAn35ScK8_GsBE9GwMFC5BwvjZXkxEWIfmi6hAoCzvA0w",
            "type": "EvanZKPSchema"
        },
        "credentialStatus": {
            "id": "did:evan:revocation123#0",
            "type": "RevocationList2021Status",
            "revocationListIndex": "0",
            "revocationListCredential": "did:evan:revocation123"
        },
        "proof": {
            "type": "BbsBlsSignature2020",
            "created": "2023-03-22T15:42:23.000Z",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g#bbs-key-1",
            "credentialMessageCount": 17,
            "requiredRevealStatements": [
                1
            ],
            "signature": "jDurIXkOk4jJkIeEhmwQpxKdr6/KA6ZN0/o5AR4N2apXbUDnyucvkiMoi6rbei9JWnpcGd9hdwG/WKgVReW4puUxSJ0tmmY4dW1zw/z2om9anETJeJPs8kMQU8igzgy6SxbiN6n0SLrI5i2f1coQLg=="
        }
    }"###;

    pub const UNSIGNED_CREDENTIAL: &str = r###"{
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://schema.org/",
            "https://w3id.org/vc-revocation-list-2020/v1"
        ],
        "id": "uuid:94450c72-5dc4-4e46-8df0-106819064656",
        "type": [
            "VerifiableCredential"
        ],
        "issuer": "did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g",
        "issuanceDate": "2021-04-20T08:35:56+0000",
        "credentialSubject": {
            "id": "did:evan:subject",
            "data": {
                "test_property_string3": "value",
                "test_property_string1": "value",
                "test_property_string2": "value",
                "test_property_string": "value",
                "test_property_string4": "value"
            }
        },
        "credentialSchema": {
            "id": "did:evan:EiAn35ScK8_GsBE9GwMFC5BwvjZXkxEWIfmi6hAoCzvA0w",
            "type": "EvanZKPSchema"
        },
        "credentialStatus": {
            "id": "did:evan:revocation123#0",
            "type": "RevocationList2021Status",
            "revocationListIndex": "0",
            "revocationListCredential": "did:evan:revocation123"
        }
    }"###;

    pub const NQUADS: [&'static str; 5] = [
        "test_property_string: value",
        "test_property_string1: value",
        "test_property_string2: value",
        "test_property_string3: value",
        "test_property_string4: value",
    ];

    pub const SECRET_KEY: &str = "RbegbY4xbTQFrJwfWzzSX5G2zptM7qz9j3CyIANVUzA=";

    pub const PUB_KEY: &str = "iK6YmizCUKlQmc5duGkfpewOoP2/qQcfJXoxQ9PbQTMzMQmDI1Mit6yTXUHCkbi2A3gHwf/3IaCVkqkVwrBvpotydSLLuKKeU1Sb3i+O6sYul+H3jsa6v8a+E/IFsBWk";

    pub const MASTER_SECRET: &str = "XSAzKjR1cNdvtew13KqfynP2tUEuJ+VkKLHVnrnB0Ig=";

    // pub const SIGNATURE_BLINDING: &str = "RAu1jffxFGDGppIMmfDE3XSBs3oyHmi5CbPvYjKGiSo=";
    pub const SIGNATURE_BLINDING: &str = "OoM/6d4+qGDuT7QNQ1ei3H47pxI3RcpkvoCU4X1xadM=";

    pub const EXAMPLE_REVOCATION_LIST_DID: &str = "did:evan:revocation123";

    pub const REVOCATION_LIST_CREDENTIAL: &str = r###"{
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/vc-revocation-list-2020/v1"
        ],
        "id": "did:evan:revocation123",
        "type": [
            "VerifiableCredential",
            "RevocationList2020Credential"
        ],
        "issuer": "did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g#bbs-key-1",
        "issued": "2023-02-07T14:25:09.000Z",
        "credentialSubject": {
            "id": "did:evan:revocation123#list",
            "type": "RevocationList2020",
            "encodedList": "H4sIAAAAAAAA_-3AMQEAAADCoPVPbQwfKAAAAAAAAAAAAAAAAAAAAOBthtJUqwBAAAA="
        },
        "proof": {
            "type": "EcdsaPublicKeySecp256k1",
            "created": "2023-02-07T14:25:09.000Z",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g#bbs-key-1",
            "jws": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOiIyMDIzLTAyLTA3VDE0OjI1OjA5LjAwMFoiLCJkb2MiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3czaWQub3JnL3ZjLXJldm9jYXRpb24tbGlzdC0yMDIwL3YxIl0sImlkIjoiZGlkOmV2YW46cmV2b2NhdGlvbjEyMyIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJSZXZvY2F0aW9uTGlzdDIwMjBDcmVkZW50aWFsIl0sImlzc3VlciI6ImRpZDpldmFuOkVpRG1Sa0tzT2FleTh0UHpjNlJ5UXJZa01OanBxWFhWVGo5Z2d5MEViaVhTNGcjYmJzLWtleS0xIiwiaXNzdWVkIjoiMjAyMy0wMi0wN1QxNDoyNTowOS4wMDBaIiwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6ZXZhbjpyZXZvY2F0aW9uMTIzI2xpc3QiLCJ0eXBlIjoiUmV2b2NhdGlvbkxpc3QyMDIwIiwiZW5jb2RlZExpc3QiOiJINHNJQUFBQUFBQUFfLTNBTVFFQUFBRENvUFZQYlF3ZktBQUFBQUFBQUFBQUFBQUFBQUFBQU9CdGh0SlVxd0JBQUFBPSJ9fSwiaXNzIjoiZGlkOmV2YW46RWlEbVJrS3NPYWV5OHRQemM2UnlRcllrTU5qcHFYWFZUajlnZ3kwRWJpWFM0ZyJ9.--mIFp9kIQA7_wD_IlEBd6F2IRMcXaiS-j65CE7tFSpYu2_4hpbUXAKWwftPHTMdCDcSFjmGamAz3o89A7H8UgE"
        }
    }"###;

    pub const REVOCATION_LIST_CREDENTIAL_REVOKED_ID_1: &str = r###"{
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/vc-revocation-list-2020/v1"
        ],
        "id": "did:evan:revocation123",
        "type": [
            "VerifiableCredential",
            "RevocationList2020Credential"
        ],
        "issuer": "did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g#bbs-key-1",
        "issued": "2023-02-07T14:22:27.000Z",
        "credentialSubject": {
            "id": "did:evan:revocation123#list",
            "type": "RevocationList2020",
            "encodedList": "H4sIAAAAAAAA_-3AMQEAAAABMPqXFsOzNQAAAAAAAAAAAAAAAAAAAMDbADn7xTYAQAAA"
        },
        "proof": {
            "type": "EcdsaPublicKeySecp256k1",
            "created": "2023-02-07T14:22:27.000Z",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g#bbs-key-1",
            "jws": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOiIyMDIzLTAyLTA3VDE0OjIyOjI3LjAwMFoiLCJkb2MiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3czaWQub3JnL3ZjLXJldm9jYXRpb24tbGlzdC0yMDIwL3YxIl0sImlkIjoiZGlkOmV2YW46cmV2b2NhdGlvbjEyMyIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJSZXZvY2F0aW9uTGlzdDIwMjBDcmVkZW50aWFsIl0sImlzc3VlciI6ImRpZDpldmFuOkVpRG1Sa0tzT2FleTh0UHpjNlJ5UXJZa01OanBxWFhWVGo5Z2d5MEViaVhTNGcjYmJzLWtleS0xIiwiaXNzdWVkIjoiMjAyMy0wMi0wN1QxNDoyMjoyNy4wMDBaIiwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6ZXZhbjpyZXZvY2F0aW9uMTIzI2xpc3QiLCJ0eXBlIjoiUmV2b2NhdGlvbkxpc3QyMDIwIiwiZW5jb2RlZExpc3QiOiJINHNJQUFBQUFBQUFfLTNBTVFFQUFBQUJNUHFYRnNPek5RQUFBQUFBQUFBQUFBQUFBQUFBQU1EYkFEbjd4VFlBUUFBQSJ9LCJwcm9vZiI6eyJ0eXBlIjoiRWNkc2FQdWJsaWNLZXlTZWNwMjU2azEiLCJjcmVhdGVkIjoiMjAyMy0wMi0wN1QxNDoyMjoyNy4wMDBaIiwicHJvb2ZQdXJwb3NlIjoiYXNzZXJ0aW9uTWV0aG9kIiwidmVyaWZpY2F0aW9uTWV0aG9kIjoiZGlkOmV2YW46RWlEbVJrS3NPYWV5OHRQemM2UnlRcllrTU5qcHFYWFZUajlnZ3kwRWJpWFM0ZyNiYnMta2V5LTEiLCJqd3MiOiJleUowZVhBaU9pSktWMVFpTENKaGJHY2lPaUpGVXpJMU5rc3RVaUo5LmV5SnBZWFFpT2lJeU1ESXpMVEF5TFRBM1ZERTBPakl5T2pJM0xqQXdNRm9pTENKa2IyTWlPbnNpUUdOdmJuUmxlSFFpT2xzaWFIUjBjSE02THk5M2QzY3Vkek11YjNKbkx6SXdNVGd2WTNKbFpHVnVkR2xoYkhNdmRqRWlMQ0pvZEhSd2N6b3ZMM2N6YVdRdWIzSm5MM1pqTFhKbGRtOWpZWFJwYjI0dGJHbHpkQzB5TURJd0wzWXhJbDBzSW1sa0lqb2laR2xrT21WMllXNDZjbVYyYjJOaGRHbHZiakV5TXlJc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0pTWlhadlkyRjBhVzl1VEdsemRESXdNakJEY21Wa1pXNTBhV0ZzSWwwc0ltbHpjM1ZsY2lJNkltUnBaRHBsZG1GdU9rVnBSRzFTYTB0elQyRmxlVGgwVUhwak5sSjVVWEpaYTAxT2FuQnhXRmhXVkdvNVoyZDVNRVZpYVZoVE5HY2pZbUp6TFd0bGVTMHhJaXdpYVhOemRXVmtJam9pTWpBeU15MHdNaTB3TjFReE5Eb3lNam95Tnk0d01EQmFJaXdpWTNKbFpHVnVkR2xoYkZOMVltcGxZM1FpT25zaWFXUWlPaUprYVdRNlpYWmhianB5WlhadlkyRjBhVzl1TVRJekkyeHBjM1FpTENKMGVYQmxJam9pVW1WMmIyTmhkR2x2Ymt4cGMzUXlNREl3SWl3aVpXNWpiMlJsWkV4cGMzUWlPaUpJTkhOSlFVRkJRVUZCUVVGZkxUTkJUVkZGUVVGQlJFTnZVRlpRWWxGM1prdEJRVUZCUVVGQlFVRkJRVUZCUVVGQlFVRkJRVTlDZEdoMFNsVnhkMEpCUVVGQlBTSjlmU3dpYVhOeklqb2laR2xrT21WMllXNDZSV2xFYlZKclMzTlBZV1Y1T0hSUWVtTTJVbmxSY2xsclRVNXFjSEZZV0ZaVWFqbG5aM2t3UldKcFdGTTBaeUo5LmRwQjROb2k0NkRGYWViMy13SG5rY3VJbi1FbUtma3QtT18zc3Vkek03QXhoeEQzZmdTVkVKSTBjckZHaE1KY3N4V3hKWlgyMF9vUUkxbnZsQ0VGUHlBQSJ9fSwiaXNzIjoiZGlkOmV2YW46RWlEbVJrS3NPYWV5OHRQemM2UnlRcllrTU5qcHFYWFZUajlnZ3kwRWJpWFM0ZyJ9.Z-tNdtzhn38Xfue94lQqpWxSUnTb_sLntkXg8QTYL6dwAbQ8BR6VsNrf4raD198kryuHkSNnTi3Izh2JfipdPAA"
        }
    }"###;

    pub const SUBJECT_DID: &str = "did:evan:subject";
    pub const SCHEMA_DID: &str = "did:evan:EiAn35ScK8_GsBE9GwMFC5BwvjZXkxEWIfmi6hAoCzvA0w";
    pub const SCHEMA: &str = r###"{
        "id": "did:evan:EiAn35ScK8_GsBE9GwMFC5BwvjZXkxEWIfmi6hAoCzvA0w",
        "name": "'sample.test.schema.unique85986",
        "type": "EvanVCSchema",
        "proof": {
          "jws": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOiIyMDIzLTAzLTIxVDEzOjU0OjAxLjAwMFoiLCJkb2MiOnsiaWQiOiJkaWQ6ZXZhbjpFaUFuMzVTY0s4X0dzQkU5R3dNRkM1Qnd2alpYa3hFV0lmbWk2aEFvQ3p2QTB3IiwidHlwZSI6IkV2YW5WQ1NjaGVtYSIsIm5hbWUiOiInc2FtcGxlLnRlc3Quc2NoZW1hLnVuaXF1ZTg1OTg2IiwiYXV0aG9yIjoiZGlkOmV2YW46RWlDdThiUkhoMmxTM0lMaHc3OWNiVFowc1pkS2tvN3hfTU82d0dHRlJYcUc1ZyIsImNyZWF0ZWRBdCI6IjIwMjMtMDMtMjFUMTM6NTQ6MDEuMDAwWiIsImRlc2NyaXB0aW9uIjoiZGVzYyIsInByb3BlcnRpZXMiOnsidGVzdF9wcm9wZXJ0eV9zdHJpbmcxIjp7InR5cGUiOiJzdHJpbmcifSwidGVzdF9wcm9wZXJ0eV9zdHJpbmc0Ijp7InR5cGUiOiJzdHJpbmcifSwidGVzdF9wcm9wZXJ0eV9zdHJpbmciOnsidHlwZSI6InN0cmluZyJ9LCJ0ZXN0X3Byb3BlcnR5X3N0cmluZzMiOnsidHlwZSI6InN0cmluZyJ9LCJ0ZXN0X3Byb3BlcnR5X3N0cmluZzIiOnsidHlwZSI6InN0cmluZyJ9fSwicmVxdWlyZWQiOlsidGVzdF9wcm9wZXJ0eV9zdHJpbmciXSwiYWRkaXRpb25hbFByb3BlcnRpZXMiOmZhbHNlfSwiaXNzIjoiZGlkOmV2YW46RWlDdThiUkhoMmxTM0lMaHc3OWNiVFowc1pkS2tvN3hfTU82d0dHRlJYcUc1ZyJ9.cl_1Eya0KiXIfpb2AsEv-YJsJB76GJm44lIBoERKCHZ09ASVx6eFamUWObKz3rYAXFXDYL7MirSYaoIstdDYnBw",
          "type": "EcdsaPublicKeySecp256k1",
          "created": "2023-03-21T13:54:01.000Z",
          "proofPurpose": "assertionMethod",
          "verificationMethod": "did:evan:EiCu8bRHh2lS3ILhw79cbTZ0sZdKko7x_MO6wGGFRXqG5g#key1"
        },
        "author": "did:evan:EiCu8bRHh2lS3ILhw79cbTZ0sZdKko7x_MO6wGGFRXqG5g",
        "required": [
          "test_property_string"
        ],
        "createdAt": "2023-03-21T13:54:01.000Z",
        "properties": {
          "test_property_string": {
            "type": "string"
          },
          "test_property_string1": {
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
        "description": "desc",
        "additionalProperties": false
      }"###;
    pub const PROOF_REQUEST_SCHEMA_FIVE_PROPERTIES: &str = r###"{
        "verifier": "did:evan:verifier",
        "createdAt": "2023-03-22T15:42:23.000Z",
        "nonce": "XxApxRDBXaF0QCXHh7zMS7Ms2ELVcBUc0TdhfaAzH8o=",
        "type": "BBS",
        "subProofRequests": [
            {
                "schema": "did:evan:EiAn35ScK8_GsBE9GwMFC5BwvjZXkxEWIfmi6hAoCzvA0w",
                "revealedAttributes": [
                    1,
                    3
                ]
            }
        ]
    }"###;

    pub const PROOF_REQUEST_SCHEMA_FIVE_PROPERTIES_WITHOUT_VERIFIER: &str = r###"{
        "createdAt": "2023-03-22T15:42:23.000Z",
        "nonce": "XxApxRDBXaF0QCXHh7zMS7Ms2ELVcBUc0TdhfaAzH8o=",
        "type": "BBS",
        "subProofRequests": [
            {
                "schema": "did:evan:EiAn35ScK8_GsBE9GwMFC5BwvjZXkxEWIfmi6hAoCzvA0w",
                "revealedAttributes": [
                    1,
                    3
                ]
            }
        ]
    }"###;

    pub const PROOF_PRESENTATION: &str = r###"{
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://schema.org/",
            "https://w3id.org/vc-revocation-list-2020/v1"
        ],
        "id": "743875ce-8ec0-4b6a-a67d-33a64392a5d3",
        "type": [
            "VerifiablePresentation"
        ],
        "verifiableCredential": [
            {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://schema.org/",
                    "https://w3id.org/vc-revocation-list-2020/v1"
                ],
                "id": "uuid:94450c72-5dc4-4e46-8df0-106819064656",
                "type": [
                    "VerifiableCredential"
                ],
                "issuer": "did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g",
                "issuanceDate": "2023-03-22T15:42:23.000Z",
                "credentialSubject": {
                    "id": "did:evan:holder",
                    "data": {
                        "test_property_string4": "value",
                        "test_property_string": "value",
                        "test_property_string2": "value",
                        "test_property_string3": "value",
                        "test_property_string1": "value"
                    }
                },
                "credentialSchema": {
                    "id": "did:evan:EiAn35ScK8_GsBE9GwMFC5BwvjZXkxEWIfmi6hAoCzvA0w",
                    "type": "EvanZKPSchema"
                },
                "credentialStatus": {
                    "id": "did:evan:revocation123#0",
                    "type": "RevocationList2021Status",
                    "revocationListIndex": "0",
                    "revocationListCredential": "did:evan:revocation123"
                },
                "proof": {
                    "type": "BbsBlsSignatureProof2020",
                    "created": "2023-03-22T15:42:23.000Z",
                    "proofPurpose": "assertionMethod",
                    "credentialMessageCount": 17,
                    "verificationMethod": "did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g#bbs-key-1",
                    "nonce": "XxApxRDBXaF0QCXHh7zMS7Ms2ELVcBUc0TdhfaAzH8o=",
                    "proof": "AAADXI6EsraZ9L1R3QGF4kupzwSjdMldq7ICW5pviwfmCYMYSCV/PR7ejUV8fsKVsllyBatqtkMbx0exBJrzzTYaRDDD1bFe3b/oUv6QU/ETjwyt1RFD3hOHVnPPwJeLIPHTMI8I4ABPkVKpMM/I+q5qRabzqR/6qEuGN/yMnxegGIYQmAJQ0e5fv7MRpi217H1xWgAAAHSZaY5vupCG683QLXQiukwsysMcLkPUt09lxSHZX6LY1P5tZ2OoLkC2eO2CkkbQqOYAAAACbOVRKtN/CxvlLQjiDwdBMokw/ZvNfyuBvOK9AL5rNAZwdwdUPQkOiHVFd+OCwRnzC/pkbW5giLcv+F0x2uPCU4NUkXS4UKstieJnM0w1Wtx70yaQ5tqvIx4H39KWVF9uESuRh02xoqEuyd+aDvy1MAAAABFoJlSiKrMKjOMABsFzzcNzlwS/7MJHlG+7qYTsxwxNvQGIO8GrRj4OXrh0f3oR66n5ADM4T51Ax5ttxEjdbpGUVdp6uubwAtUdGprYaTCmwBJbsg475gOxGX4eWdnihJQNbEGJWd+O9H1uJUS9AV+v4NwIut7RLLwotizlqFJEoV8MH506fF+FwTgEWm4m7uRv3BCfS7qgjLsEuUNKhplhaXE+WbNym4eT954vDAiIqgHKOWKk/T8GBortrQ5JJ/I+Y69hVomfloLImDTmSIn8PiZjlSZd5ktIIUTbvovjRgWyRJsw3tUwAhhoBHhAFs1A628oKICsluR9Kd/my+VdI17/yEZa62vWXh+f1i3HxcIzVhCL36uzH62Qky6UBhcxgHZ/RqIpbK/yp0bv2Ccy2Xf147Z+dIuspdxt1DsVcA/LJ4cwEFOmRAniuroG+2Ik1qkJajS4VpbILRZNHlEBYBOq6YCp7AmCtL1XcCYaD3/EfC1XtKltO4hBwZKhybQKyEoeYC0UyrBjauupsfATXTWenBTwqC45tq0sbevrRAUrR+Nau+wHaqYG4x9nYIFP/ybREwxIZry6tECxM/idOZ4/HJR0ruGwLNfbJ8Q3efzRuWzIw8LuYqxEnVCQXvZbsbVusEGXCRrHw8uwfIlk5KAzU+94R3a/zxY1UIkzmGX0l9RjK3tISuOmgnnQI9/730FbM4fXM5eRHsysWCJzAAAAAgAAAAFptm93jejWBvUgqSkOd+aEaUo/SXvgz/DDfXOR/HBHbgAAAAMuTNCnyK9M/tpuzIOLzTcaj+0pyTv2gJmQD0uw11i2Fg=="
                }
            }
        ],
        "proof": {
            "type": "EcdsaPublicKeySecp256k1",
            "created": "2023-03-22T15:42:23.000Z",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:evan:verifier#key-1",
            "jws": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOiIyMDIzLTAzLTIyVDE1OjQyOjIzLjAwMFoiLCJkb2MiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3NjaGVtYS5vcmcvIiwiaHR0cHM6Ly93M2lkLm9yZy92Yy1yZXZvY2F0aW9uLWxpc3QtMjAyMC92MSJdLCJpZCI6Ijc0Mzg3NWNlLThlYzAtNGI2YS1hNjdkLTMzYTY0MzkyYTVkMyIsInR5cGUiOlsiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJdLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6W3siQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3NjaGVtYS5vcmcvIiwiaHR0cHM6Ly93M2lkLm9yZy92Yy1yZXZvY2F0aW9uLWxpc3QtMjAyMC92MSJdLCJpZCI6InV1aWQ6OTQ0NTBjNzItNWRjNC00ZTQ2LThkZjAtMTA2ODE5MDY0NjU2IiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJkaWQ6ZXZhbjpFaURtUmtLc09hZXk4dFB6YzZSeVFyWWtNTmpwcVhYVlRqOWdneTBFYmlYUzRnIiwiaXNzdWFuY2VEYXRlIjoiMjAyMy0wMy0yMlQxNTo0MjoyMy4wMDBaIiwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6ZXZhbjpob2xkZXIiLCJkYXRhIjp7InRlc3RfcHJvcGVydHlfc3RyaW5nMSI6InZhbHVlIiwidGVzdF9wcm9wZXJ0eV9zdHJpbmc0IjoidmFsdWUiLCJ0ZXN0X3Byb3BlcnR5X3N0cmluZzIiOiJ2YWx1ZSIsInRlc3RfcHJvcGVydHlfc3RyaW5nMyI6InZhbHVlIiwidGVzdF9wcm9wZXJ0eV9zdHJpbmciOiJ2YWx1ZSJ9fSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6ImRpZDpldmFuOkVpQW4zNVNjSzhfR3NCRTlHd01GQzVCd3ZqWlhreEVXSWZtaTZoQW9DenZBMHciLCJ0eXBlIjoiRXZhblpLUFNjaGVtYSJ9LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiZGlkOmV2YW46cmV2b2NhdGlvbjEyMyMwIiwidHlwZSI6IlJldm9jYXRpb25MaXN0MjAyMVN0YXR1cyIsInJldm9jYXRpb25MaXN0SW5kZXgiOiIwIiwicmV2b2NhdGlvbkxpc3RDcmVkZW50aWFsIjoiZGlkOmV2YW46cmV2b2NhdGlvbjEyMyJ9LCJwcm9vZiI6eyJ0eXBlIjoiQmJzQmxzU2lnbmF0dXJlUHJvb2YyMDIwIiwiY3JlYXRlZCI6IjIwMjMtMDMtMjJUMTU6NDI6MjMuMDAwWiIsInByb29mUHVycG9zZSI6ImFzc2VydGlvbk1ldGhvZCIsImNyZWRlbnRpYWxNZXNzYWdlQ291bnQiOjE3LCJ2ZXJpZmljYXRpb25NZXRob2QiOiJkaWQ6ZXZhbjpFaURtUmtLc09hZXk4dFB6YzZSeVFyWWtNTmpwcVhYVlRqOWdneTBFYmlYUzRnI2Jicy1rZXktMSIsIm5vbmNlIjoiWHhBcHhSREJYYUYwUUNYSGg3ek1TN01zMkVMVmNCVWMwVGRoZmFBekg4bz0iLCJwcm9vZiI6IkFBQURYSTZFc3JhWjlMMVIzUUdGNGt1cHp3U2pkTWxkcTdJQ1c1cHZpd2ZtQ1lNWVNDVi9QUjdlalVWOGZzS1ZzbGx5QmF0cXRrTWJ4MGV4QkpyenpUWWFSREREMWJGZTNiL29VdjZRVS9FVGp3eXQxUkZEM2hPSFZuUFB3SmVMSVBIVE1JOEk0QUJQa1ZLcE1NL0krcTVxUmFienFSLzZxRXVHTi95TW54ZWdHSVlRbUFKUTBlNWZ2N01ScGkyMTdIMXhXZ0FBQUhTWmFZNXZ1cENHNjgzUUxYUWl1a3dzeXNNY0xrUFV0MDlseFNIWlg2TFkxUDV0WjJPb0xrQzJlTzJDa2tiUXFPWUFBQUFDYk9WUkt0Ti9DeHZsTFFqaUR3ZEJNb2t3L1p2TmZ5dUJ2T0s5QUw1ck5BWndkd2RVUFFrT2lIVkZkK09Dd1JuekMvcGtiVzVnaUxjditGMHgydVBDVTROVWtYUzRVS3N0aWVKbk0wdzFXdHg3MHlhUTV0cXZJeDRIMzlLV1ZGOXVFU3VSaDAyeG9xRXV5ZCthRHZ5MU1BQUFBQkZvSmxTaUtyTUtqT01BQnNGenpjTnpsd1MvN01KSGxHKzdxWVRzeHd4TnZRR0lPOEdyUmo0T1hyaDBmM29SNjZuNUFETTRUNTFBeDV0dHhFamRicEdVVmRwNnV1YndBdFVkR3ByWWFUQ213Qkpic2c0NzVnT3hHWDRlV2RuaWhKUU5iRUdKV2QrTzlIMXVKVVM5QVYrdjROd0l1dDdSTEx3b3RpemxxRkpFb1Y4TUg1MDZmRitGd1RnRVdtNG03dVJ2M0JDZlM3cWdqTHNFdVVOS2hwbGhhWEUrV2JOeW00ZVQ5NTR2REFpSXFnSEtPV0trL1Q4R0JvcnRyUTVKSi9JK1k2OWhWb21mbG9MSW1EVG1TSW44UGlaamxTWmQ1a3RJSVVUYnZvdmpSZ1d5UkpzdzN0VXdBaGhvQkhoQUZzMUE2MjhvS0lDc2x1UjlLZC9teStWZEkxNy95RVphNjJ2V1hoK2YxaTNIeGNJelZoQ0wzNnV6SDYyUWt5NlVCaGN4Z0haL1JxSXBiSy95cDBidjJDY3kyWGYxNDdaK2RJdXNwZHh0MURzVmNBL0xKNGN3RUZPbVJBbml1cm9HKzJJazFxa0phalM0VnBiSUxSWk5IbEVCWUJPcTZZQ3A3QW1DdEwxWGNDWWFEMy9FZkMxWHRLbHRPNGhCd1pLaHliUUt5RW9lWUMwVXlyQmphdXVwc2ZBVFhUV2VuQlR3cUM0NXRxMHNiZXZyUkFVclIrTmF1K3dIYXFZRzR4OW5ZSUZQL3liUkV3eElacnk2dEVDeE0vaWRPWjQvSEpSMHJ1R3dMTmZiSjhRM2VmelJ1V3pJdzhMdVlxeEVuVkNRWHZaYnNiVnVzRUdYQ1JySHc4dXdmSWxrNUtBelUrOTRSM2EvenhZMVVJa3ptR1gwbDlSakszdElTdU9tZ25uUUk5LzczMEZiTTRmWE01ZVJIc3lzV0NKekFBQUFBZ0FBQUFGcHRtOTNqZWpXQnZVZ3FTa09kK2FFYVVvL1NYdmd6L0REZlhPUi9IQkhiZ0FBQUFNdVROQ255SzlNL3RwdXpJT0x6VGNhaiswcHlUdjJnSm1RRDB1dzExaTJGZz09In19XX0sImlzcyI6ImRpZDpldmFuOnZlcmlmaWVyIn0.XtSvdmnlbdWV81IZ15-WTebVgzl-KkovwMy1K3-ZW71egRFFkwX2Hz1yGzvjQZQQ3nR0prfs6TLYSVCfBfTAUgA"
        }
    }"###;

    pub const PROOF_PRESENTATION_INVALID_SIGNATURE_AND_WITHOUT_JWS: &str = r###"{
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://schema.org/",
            "https://w3id.org/vc-revocation-list-2020/v1"
        ],
        "id": "743875ce-8ec0-4b6a-a67d-33a64392a5d3",
        "type": [
            "VerifiablePresentation"
        ],
        "verifiableCredential": [
            {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://schema.org/",
                    "https://w3id.org/vc-revocation-list-2020/v1"
                ],
                "id": "uuid:94450c72-5dc4-4e46-8df0-106819064656",
                "type": [
                    "VerifiableCredential"
                ],
                "issuer": "did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g",
                "issuanceDate": "2023-03-22T15:42:23.000Z",
                "credentialSubject": {
                    "id": "did:evan:holder",
                    "data": {
                        "test_property_string4": "value",
                        "test_property_string": "value",
                        "test_property_string2": "value",
                        "test_property_string3": "value",
                        "test_property_string1": "value"
                    }
                },
                "credentialSchema": {
                    "id": "did:evan:EiAn35ScK8_GsBE9GwMFC5BwvjZXkxEWIfmi6hAoCzvA0w",
                    "type": "EvanZKPSchema"
                },
                "credentialStatus": {
                    "id": "did:evan:revocation123#0",
                    "type": "RevocationList2021Status",
                    "revocationListIndex": "0",
                    "revocationListCredential": "did:evan:revocation123"
                },
                "proof": {
                    "type": "BbsBlsSignatureProof2020",
                    "created": "2023-03-22T15:42:23.000Z",
                    "proofPurpose": "assertionMethod",
                    "credentialMessageCount": 17,
                    "verificationMethod": "did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g#bbs-key-1",
                    "nonce": "XxApxRDBXaF0QCXHh7zMS7Ms2ELVcBUc0TdhfaAzH8o=",
                    "proof": "BBBCHKtugFHiaXgjrnI+pyfT6f3J5fGUQDJh0JfDsbH0kurhMMdVUkB3gIUCFLksvRm1Ca8o+LkqLH4/lEcVGOd1aldGNsAw5IyEPmeWReYDPLSJroqSPdecEk8bLYbRR/SDno7FWUMUYOovWi/3jAyo7lrNlf4rKJW+2FRgvlf8HzWwaZhk1dB5uynsRIrwnDjqjwAAAHSEMZIcRYIj+fsVov2nt40lhyumTCdK0rlqDjIs1MHAJqNoWhrxqIFp5w6iZfYTlzoAAAACIWxKnfGSrrDg26fcm01ky3Wr1hCJ8I9PuuQ7SBpbaYhNprKueXJeMlIMCa1ocLiaWwurNikj4sfhtp3FnihEjYMUnP6MpwrZNKWYEVWID8y06YSaQDvC1bc3wfmB4GB0t9aIjl9ubYrKxgL3d4gtVwAAAAdc8Zq55QJ5MRHapXd4g3eC1jaLBYWe+SBP19phXorOQSTu1qcWuiIEE6A8mwW9pMeTDOyFoaJwooD8HNLgh0hIFEHHx9ou0YHql7KCbtN0XrxMNJLhU/EABWp8XJJFxKkH2uYXy5/T6wbuO5TQSuDrl7foiuETyEAfDDKD+zgVPmt5MUIgzWASShvaNZ7cQ22Oct8/w4vyQJpA38/3oMvJN/tp72vz2z1D7Qu9f4K73peEY3OnhYo0EW2jqjhJER8ngeHozTH85yX29uDI6T0zi8dMJEq80ijBlgLwCf9TqgAAAAEAAAABVYYuxWfEuaxvBkivWA/SfIa+XSWTfQxphjVs8yhmpfY="
                }
            }
        ]
    }"###;
}
