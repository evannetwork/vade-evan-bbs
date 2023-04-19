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
        "issuer":"did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g",
        "type":"EvanCredentialProposal",
        "schema":"did:evan:EiBmiHCHLMbGVn9hllRM5qQOsshvETToEALBAtFqP3PUIg"
     }
    "###;
    pub const EXAMPLE_CREDENTIAL_OFFERING: &str = r###"
    {
        "issuer":"did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g",
        "nonce":"VprTtI2gGnaPU7Bi9ug5U5k8qpZF3y6loo/8ZpetOEk=",
        "credentialMessageCount":6
    }
    "###;
}

#[allow(dead_code)]
pub mod bbs_coherent_context_test_data {
    pub const UNFINISHED_CREDENTIAL: &str = r###"{
        "@context":[
           "https://www.w3.org/2018/credentials/v1",
           "https:://schema.org/",
           "https://w3id.org/vc-revocation-list-2020/v1"
        ],
        "id":"94450c72-5dc4-4e46-8df0-106819064656",
        "type":[
           "VerifiableCredential"
        ],
        "issuer":"did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g",
        "issuanceDate":"2021-04-20T08:35:56+0000",
        "credentialSubject":{
           "data":{
              "test_property_string3":"value",
              "test_property_string":"value",
              "test_property_string4":"value",
              "test_property_string1":"value",
              "test_property_string2":"value"
           }
        },
        "credentialSchema":{
           "id":"did:evan:EiBmiHCHLMbGVn9hllRM5qQOsshvETToEALBAtFqP3PUIg",
           "type":"EvanZKPSchema"
        },
        "credentialStatus":{
           "id":"did:evan:revocation123#0",
           "type":"RevocationList2020Status",
           "revocationListIndex":"0",
           "revocationListCredential":"did:evan:revocation123"
        },
        "proof":{
           "type":"BbsBlsSignature2020",
           "created":"2023-04-18T14:41:49.000Z",
           "proofPurpose":"assertionMethod",
           "verificationMethod":"did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g#bbs-key-1",
           "credentialMessageCount":6,
           "requiredRevealStatements":[
              1
           ],
           "blindSignature":"oBDc9KsSI6mahTKlwwACnrZZwEBsrAFr9eIhBzjEPAcQdYwwjmlBom6rypNXqKpiSOb4vvKVzy296h6Vs1ABrcVahmcQanrwooCusIbbW41vzaprf85TzMWwmA1drchsdmX1Ov+zidFz0sI1/7EDQQ=="
        }
     }"###;

    pub const FINISHED_CREDENTIAL: &str = r###"{
        "@context":[
           "https://www.w3.org/2018/credentials/v1",
           "https:://schema.org/",
           "https://w3id.org/vc-revocation-list-2020/v1"
        ],
        "id":"94450c72-5dc4-4e46-8df0-106819064656",
        "type":[
           "VerifiableCredential"
        ],
        "issuer":"did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g",
        "issuanceDate":"2021-04-20T08:35:56+0000",
        "credentialSubject":{
           "data":{
              "test_property_string1":"value",
              "test_property_string4":"value",
              "test_property_string":"value",
              "test_property_string2":"value",
              "test_property_string3":"value"
           }
        },
        "credentialSchema":{
           "id":"did:evan:EiBmiHCHLMbGVn9hllRM5qQOsshvETToEALBAtFqP3PUIg",
           "type":"EvanZKPSchema"
        },
        "credentialStatus":{
           "id":"did:evan:revocation123#0",
           "type":"RevocationList2020Status",
           "revocationListIndex":"0",
           "revocationListCredential":"did:evan:revocation123"
        },
        "proof":{
           "type":"BbsBlsSignature2020",
           "created":"2023-04-18T14:41:49.000Z",
           "proofPurpose":"assertionMethod",
           "verificationMethod":"did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g#bbs-key-1",
           "credentialMessageCount":6,
           "requiredRevealStatements":[
              1
           ],
           "signature":"oBDc9KsSI6mahTKlwwACnrZZwEBsrAFr9eIhBzjEPAcQdYwwjmlBom6rypNXqKpiSOb4vvKVzy296h6Vs1ABrcVahmcQanrwooCusIbbW41tB7JwYC9XnDQSUYGvFNn0TEtmXr+qRf1VuFrin7PUiA=="
        }
     }"###;

    pub const UNSIGNED_CREDENTIAL: &str = r###"{
        "@context":[
           "https://www.w3.org/2018/credentials/v1",
           "https:://schema.org/",
           "https://w3id.org/vc-revocation-list-2020/v1"
        ],
        "id":"94450c72-5dc4-4e46-8df0-106819064656",
        "type":[
           "VerifiableCredential"
        ],
        "issuer":"did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g",
        "issuanceDate":"2021-04-20T08:35:56+0000",
        "credentialSubject":{
           "data":{
              "test_property_string3":"value",
              "test_property_string":"value",
              "test_property_string4":"value",
              "test_property_string1":"value",
              "test_property_string2":"value"
           }
        },
        "credentialSchema":{
           "id":"did:evan:EiBmiHCHLMbGVn9hllRM5qQOsshvETToEALBAtFqP3PUIg",
           "type":"EvanZKPSchema"
        },
        "credentialStatus":{
           "id":"did:evan:revocation123#0",
           "type":"RevocationList2020Status",
           "revocationListIndex":"0",
           "revocationListCredential":"did:evan:revocation123"
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

    pub const SIGNATURE_BLINDING: &str = "cSevWAn+gRehm5F8WwjpjSmjFSa/9Rgq4eWYq6AC0Ug=";

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
    pub const SCHEMA_DID: &str = "did:evan:EiBmiHCHLMbGVn9hllRM5qQOsshvETToEALBAtFqP3PUIg";
    pub const SCHEMA: &str = r###"{
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
            {
                "@vocab": "https://www.w3.org/ns/did#"
            }
        ],
        "id": "did:evan:EiBmiHCHLMbGVn9hllRM5qQOsshvETToEALBAtFqP3PUIg",
        "type": "EvanVCSchema",
        "name": "sample.test.schema.unique385895114662",
        "author": "did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g",
        "createdAt": "2023-02-07T08:17:05.000Z",
        "description": "Test sample schema",
        "properties": {
            "test_property_string3": {
                "type": "string"
            },
            "test_property_string2": {
                "type": "string"
            },
            "test_property_string": {
                "type": "string"
            },
            "test_property_string4": {
                "type": "string"
            },
            "test_property_string1": {
                "type": "string"
            }
        },
        "required": [
            "test_property_string"
        ],
        "additionalProperties": false,
        "proof": {
            "type": "EcdsaPublicKeySecp256k1",
            "created": "2023-02-07T08:17:05.000Z",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g#key1",
            "jws": "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOiIyMDIzLTAyLTA3VDA4OjE3OjA1LjAwMFoiLCJkb2MiOnsiaWQiOiJkaWQ6ZXZhbjpFaUJtaUhDSExNYkdWbjlobGxSTTVxUU9zc2h2RVRUb0VBTEJBdEZxUDNQVUlnIiwidHlwZSI6IkV2YW5WQ1NjaGVtYSIsIm5hbWUiOiJzYW1wbGUudGVzdC5zY2hlbWEudW5pcXVlMzg1ODk1MTE0NjYyIiwiYXV0aG9yIjoiZGlkOmV2YW46RWlEbVJrS3NPYWV5OHRQemM2UnlRcllrTU5qcHFYWFZUajlnZ3kwRWJpWFM0ZyIsImNyZWF0ZWRBdCI6IjIwMjMtMDItMDdUMDg6MTc6MDUuMDAwWiIsImRlc2NyaXB0aW9uIjoiVGVzdCBzYW1wbGUgc2NoZW1hIiwicHJvcGVydGllcyI6eyJ0ZXN0X3Byb3BlcnR5X3N0cmluZzMiOnsidHlwZSI6InN0cmluZyJ9LCJ0ZXN0X3Byb3BlcnR5X3N0cmluZzIiOnsidHlwZSI6InN0cmluZyJ9LCJ0ZXN0X3Byb3BlcnR5X3N0cmluZyI6eyJ0eXBlIjoic3RyaW5nIn0sInRlc3RfcHJvcGVydHlfc3RyaW5nNCI6eyJ0eXBlIjoic3RyaW5nIn0sInRlc3RfcHJvcGVydHlfc3RyaW5nMSI6eyJ0eXBlIjoic3RyaW5nIn19LCJyZXF1aXJlZCI6WyJ0ZXN0X3Byb3BlcnR5X3N0cmluZyJdLCJhZGRpdGlvbmFsUHJvcGVydGllcyI6ZmFsc2V9LCJpc3MiOiJkaWQ6ZXZhbjpFaURtUmtLc09hZXk4dFB6YzZSeVFyWWtNTmpwcVhYVlRqOWdneTBFYmlYUzRnIn0.2D-cW8eoB-kEBWvlIpiV7POre4tbgi_knPbhq8BQZ409nuRNZUMpva9gJVpaR3bZqTAtJ63Tx-8HCs4emSlirxs"
        },
        "verificationMethod": [
            {
                "id": "#signingKey",
                "controller": "did:evan:EiBmiHCHLMbGVn9hllRM5qQOsshvETToEALBAtFqP3PUIg",
                "type": "Secp256k1VerificationKey2018",
                "publicKeyJwk": {
                    "kty": "EC",
                    "x": "3QSU-mD5tDdnoEua0fmMko5EFDTEmcmp7CX04KQmLQ0",
                    "y": "AzuPhzPh4YI28mVbioVFgc3Bk1Cw0cHOIjkKfdkVpjI",
                    "crv": "secp256k1"
                }
            }
        ],
        "authentication": [
            "#signingKey"
        ],
        "assertionMethod": [
            "#signingKey"
        ],
        "capabilityInvocation": [
            "#signingKey"
        ],
        "capabilityDelegation": [
            "#signingKey"
        ],
        "keyAgreement": [
            "#signingKey"
        ]
    }"###;
    pub const PROOF_REQUEST_SCHEMA_FIVE_PROPERTIES: &str = r###"{
        "verifier":"did:evan:verifier",
        "createdAt":"2023-04-18T15:17:43.000Z",
        "nonce":"C8Kh32WU+QBx/pbh/ijccjlia+bUV+XuGWW6adzeH8w=",
        "type":"BBS",
        "subProofRequests":[
           {
              "schema":"did:evan:EiBmiHCHLMbGVn9hllRM5qQOsshvETToEALBAtFqP3PUIg",
              "revealedAttributes":[
                 1
              ]
           }
        ]
     }"###;

    pub const PROOF_REQUEST: &str = r###"{
        "verifier":"did:evan:verifier",
        "createdAt":"2023-04-18T15:17:43.000Z",
        "nonce":"C8Kh32WU+QBx/pbh/ijccjlia+bUV+XuGWW6adzeH8w=",
        "type":"BBS",
        "subProofRequests":[
           {
              "schema":"did:evan:EiBmiHCHLMbGVn9hllRM5qQOsshvETToEALBAtFqP3PUIg",
              "revealedAttributes":[
                 1,3
              ]
           }
        ]
     }"###;
    pub const PROOF_REQUEST_SCHEMA_FIVE_PROPERTIES_WITHOUT_VERIFIER: &str = r###"{
        "verifier":"did:evan:verifier",
        "createdAt":"2023-04-18T15:17:43.000Z",
        "nonce":"C8Kh32WU+QBx/pbh/ijccjlia+bUV+XuGWW6adzeH8w=",
        "type":"BBS",
        "subProofRequests":[
           {
              "schema":"did:evan:EiBmiHCHLMbGVn9hllRM5qQOsshvETToEALBAtFqP3PUIg",
              "revealedAttributes":[
                 1
              ]
           }
        ]
     }"###;

    pub const PROOF_PRESENTATION: &str = r###"{
        "@context":[
           "https://www.w3.org/2018/credentials/v1",
           "https://schema.org/",
           "https://w3id.org/vc-revocation-list-2020/v1"
        ],
        "id":"8a6e584f-a864-486c-a4eb-7414ff904a9f",
        "type":[
           "VerifiablePresentation"
        ],
        "verifiableCredential":[
           {
              "@context":[
                 "https://www.w3.org/2018/credentials/v1",
                 "https:://schema.org/",
                 "https://w3id.org/vc-revocation-list-2020/v1"
              ],
              "id":"94450c72-5dc4-4e46-8df0-106819064656",
              "type":[
                 "VerifiableCredential"
              ],
              "issuer":"did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g",
              "issuanceDate":"2023-04-18T15:17:43.000Z",
              "credentialSubject":{
                 "data":{
                    "test_property_string":"value",
                    "test_property_string2":"value",
                    "test_property_string1":"value",
                    "test_property_string4":"value",
                    "test_property_string3":"value"
                 }
              },
              "credentialSchema":{
                 "id":"did:evan:EiBmiHCHLMbGVn9hllRM5qQOsshvETToEALBAtFqP3PUIg",
                 "type":"EvanZKPSchema"
              },
              "credentialStatus":{
                 "id":"did:evan:revocation123#0",
                 "type":"RevocationList2020Status",
                 "revocationListIndex":"0",
                 "revocationListCredential":"did:evan:revocation123"
              },
              "proof":{
                 "type":"BbsBlsSignatureProof2020",
                 "created":"2023-04-18T15:17:43.000Z",
                 "proofPurpose":"assertionMethod",
                 "credentialMessageCount":6,
                 "verificationMethod":"did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g#bbs-key-1",
                 "nonce":"C8Kh32WU+QBx/pbh/ijccjlia+bUV+XuGWW6adzeH8w=",
                 "proof":"AAAB/LAVRadCadzIijgO7RFraoMu+uM0oGjDbNBrfqDHZ/VFOfa6zueu5axOSDNyA6ERy4FmYZpczHSAtjV8QwLX7Kkyxd8hcoJ54B5obRTdFkWW00EoW2iQxxTKqu9FU6e4iImiHKUaVDVKNUFubHRFlwQNFAObtUY6q0HiXeXPWExEbVYJm3MFJLR6tDLq54J7CQAAAHSQChhhqnxZg12ezvSr5qpPLrzBUulraVbuSnIk/wu8ksYSgo1NI/tkK93hH8aAJNsAAAACQrob70xftb3kj/3X5tRs2KPwmkbTenbhqCjzDQeY3iYbdJ4xmIfqqDGiM7wH/WCTV167QterCzAly8EcpgqIWIBwarcTx08zG5dFtcgOXpHeMgdbNX4cIqrSFTcPxawgYrRjOui16iKGHtRAZvRlewAAAAZadVGFpt3+MNfLacEqtuK+Oo0ah/cB5ayGGkLvHshH6ikYqJSkPXGtvFVc2tA9dkU5HaVqVWrQZYyjLk+8FfAeLjZK6B7awGp/uuwhpDD2BKwyDSi0Ze0JuQk/x6R6tgxLUCqFlIb7P9SNoy8gQbmD9QKgTjHIEs/4AAxMZ+oi+yPenywZ/qEUwOYeO40TNmKzXU6Oxa2f5IFAYL5XZm5GTvNJUejaxmf0YjzedCWg0iUivVzawiu5rZMb2Rl4MNkAAAACAAAAAVWGLsVnxLmsbwZIr1gP0nyGvl0lk30MaYY1bPMoZqX2AAAAAycnUcuUjJ2u1JC9iC4voWQN3t3I5Gr6GZCWvIiMgsJz"
              }
           }
        ],
        "proof":{
           "type":"EcdsaPublicKeySecp256k1",
           "created":"2023-04-18T15:17:43.000Z",
           "proofPurpose":"assertionMethod",
           "verificationMethod":"did:evan:verifier#key-1",
           "jws":"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOiIyMDIzLTA0LTE4VDE1OjE3OjQzLjAwMFoiLCJkb2MiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3NjaGVtYS5vcmcvIiwiaHR0cHM6Ly93M2lkLm9yZy92Yy1yZXZvY2F0aW9uLWxpc3QtMjAyMC92MSJdLCJpZCI6IjhhNmU1ODRmLWE4NjQtNDg2Yy1hNGViLTc0MTRmZjkwNGE5ZiIsInR5cGUiOlsiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJdLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6W3siQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczo6Ly9zY2hlbWEub3JnLyIsImh0dHBzOi8vdzNpZC5vcmcvdmMtcmV2b2NhdGlvbi1saXN0LTIwMjAvdjEiXSwiaWQiOiI5NDQ1MGM3Mi01ZGM0LTRlNDYtOGRmMC0xMDY4MTkwNjQ2NTYiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIl0sImlzc3VlciI6ImRpZDpldmFuOkVpRG1Sa0tzT2FleTh0UHpjNlJ5UXJZa01OanBxWFhWVGo5Z2d5MEViaVhTNGciLCJpc3N1YW5jZURhdGUiOiIyMDIzLTA0LTE4VDE1OjE3OjQzLjAwMFoiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJkYXRhIjp7InRlc3RfcHJvcGVydHlfc3RyaW5nMSI6InZhbHVlIiwidGVzdF9wcm9wZXJ0eV9zdHJpbmcyIjoidmFsdWUiLCJ0ZXN0X3Byb3BlcnR5X3N0cmluZzMiOiJ2YWx1ZSIsInRlc3RfcHJvcGVydHlfc3RyaW5nNCI6InZhbHVlIiwidGVzdF9wcm9wZXJ0eV9zdHJpbmciOiJ2YWx1ZSJ9fSwiY3JlZGVudGlhbFNjaGVtYSI6eyJpZCI6ImRpZDpldmFuOkVpQm1pSENITE1iR1ZuOWhsbFJNNXFRT3NzaHZFVFRvRUFMQkF0RnFQM1BVSWciLCJ0eXBlIjoiRXZhblpLUFNjaGVtYSJ9LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiZGlkOmV2YW46cmV2b2NhdGlvbjEyMyMwIiwidHlwZSI6IlJldm9jYXRpb25MaXN0MjAyMFN0YXR1cyIsInJldm9jYXRpb25MaXN0SW5kZXgiOiIwIiwicmV2b2NhdGlvbkxpc3RDcmVkZW50aWFsIjoiZGlkOmV2YW46cmV2b2NhdGlvbjEyMyJ9LCJwcm9vZiI6eyJ0eXBlIjoiQmJzQmxzU2lnbmF0dXJlUHJvb2YyMDIwIiwiY3JlYXRlZCI6IjIwMjMtMDQtMThUMTU6MTc6NDMuMDAwWiIsInByb29mUHVycG9zZSI6ImFzc2VydGlvbk1ldGhvZCIsImNyZWRlbnRpYWxNZXNzYWdlQ291bnQiOjYsInZlcmlmaWNhdGlvbk1ldGhvZCI6ImRpZDpldmFuOkVpRG1Sa0tzT2FleTh0UHpjNlJ5UXJZa01OanBxWFhWVGo5Z2d5MEViaVhTNGcjYmJzLWtleS0xIiwibm9uY2UiOiJDOEtoMzJXVStRQngvcGJoL2lqY2NqbGlhK2JVVitYdUdXVzZhZHplSDh3PSIsInByb29mIjoiQUFBQi9MQVZSYWRDYWR6SWlqZ083UkZyYW9NdSt1TTBvR2pEYk5CcmZxREhaL1ZGT2ZhNnp1ZXU1YXhPU0ROeUE2RVJ5NEZtWVpwY3pIU0F0alY4UXdMWDdLa3l4ZDhoY29KNTRCNW9iUlRkRmtXVzAwRW9XMmlReHhUS3F1OUZVNmU0aUltaUhLVWFWRFZLTlVGdWJIUkZsd1FORkFPYnRVWTZxMEhpWGVYUFdFeEViVllKbTNNRkpMUjZ0RExxNTRKN0NRQUFBSFNRQ2hoaHFueFpnMTJlenZTcjVxcFBMcnpCVXVscmFWYnVTbklrL3d1OGtzWVNnbzFOSS90a0s5M2hIOGFBSk5zQUFBQUNRcm9iNzB4ZnRiM2tqLzNYNXRSczJLUHdta2JUZW5iaHFDanpEUWVZM2lZYmRKNHhtSWZxcURHaU03d0gvV0NUVjE2N1F0ZXJDekFseThFY3BncUlXSUJ3YXJjVHgwOHpHNWRGdGNnT1hwSGVNZ2RiTlg0Y0lxclNGVGNQeGF3Z1lyUmpPdWkxNmlLR0h0UkFadlJsZXdBQUFBWmFkVkdGcHQzK01OZkxhY0VxdHVLK09vMGFoL2NCNWF5R0drTHZIc2hINmlrWXFKU2tQWEd0dkZWYzJ0QTlka1U1SGFWcVZXclFaWXlqTGsrOEZmQWVMalpLNkI3YXdHcC91dXdocEREMkJLd3lEU2kwWmUwSnVRay94NlI2dGd4TFVDcUZsSWI3UDlTTm95OGdRYm1EOVFLZ1RqSElFcy80QUF4TVorb2kreVBlbnl3Wi9xRVV3T1llTzQwVE5tS3pYVTZPeGEyZjVJRkFZTDVYWm01R1R2TkpVZWpheG1mMFlqemVkQ1dnMGlVaXZWemF3aXU1clpNYjJSbDRNTmtBQUFBQ0FBQUFBVldHTHNWbnhMbXNid1pJcjFnUDBueUd2bDBsazMwTWFZWTFiUE1vWnFYMkFBQUFBeWNuVWN1VWpKMnUxSkM5aUM0dm9XUU4zdDNJNUdyNkdaQ1d2SWlNZ3NKeiJ9fV19LCJpc3MiOiJkaWQ6ZXZhbjp2ZXJpZmllciJ9.ySm_sSppc1sqUlfquEsxql5NgsiYEilfFPyOEUQM12ZYL7CR51x2CQP_cGGUet-N7W4i7WNCDjHnj8MDF7cvZgE"
        }
     }"###;

    pub const PROOF_PRESENTATION_INVALID_SIGNATURE_AND_WITHOUT_JWS: &str = r###"{
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://schema.org/",
            "https://w3id.org/vc-revocation-list-2020/v1"
        ],
        "id": "6d6bfa18-8cfe-40ec-9775-a0878e6f305a",
        "type": [
            "VerifiablePresentation"
        ],
        "verifiableCredential": [
            {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https:://schema.org/",
                    "https://w3id.org/vc-revocation-list-2020/v1"
                ],
                "id": "94450c72-5dc4-4e46-8df0-106819064656",
                "type": [
                    "VerifiableCredential"
                ],
                "issuer": "did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g",
                "issuanceDate": "2023-02-07T16:24:52.000Z",
                "credentialSubject": {
                    "data": {
                        "test_property_string4": "value",
                        "test_property_string2": "value",
                        "test_property_string1": "value",
                        "test_property_string": "value",
                        "test_property_string3": "value"
                    }
                },
                "credentialSchema": {
                    "id": "did:evan:EiBmiHCHLMbGVn9hllRM5qQOsshvETToEALBAtFqP3PUIg",
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
                    "created": "2023-02-07T16:24:52.000Z",
                    "proofPurpose": "assertionMethod",
                    "credentialMessageCount": 6,
                    "verificationMethod": "did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g#bbs-key-1",
                    "nonce": "VSTclwR8ed93y+vUkQIwVtHVmr8tm7y3EUEXn2fktAQ=",
                    "proof": "BBBCHKtugFHiaXgjrnI+pyfT6f3J5fGUQDJh0JfDsbH0kurhMMdVUkB3gIUCFLksvRm1Ca8o+LkqLH4/lEcVGOd1aldGNsAw5IyEPmeWReYDPLSJroqSPdecEk8bLYbRR/SDno7FWUMUYOovWi/3jAyo7lrNlf4rKJW+2FRgvlf8HzWwaZhk1dB5uynsRIrwnDjqjwAAAHSEMZIcRYIj+fsVov2nt40lhyumTCdK0rlqDjIs1MHAJqNoWhrxqIFp5w6iZfYTlzoAAAACIWxKnfGSrrDg26fcm01ky3Wr1hCJ8I9PuuQ7SBpbaYhNprKueXJeMlIMCa1ocLiaWwurNikj4sfhtp3FnihEjYMUnP6MpwrZNKWYEVWID8y06YSaQDvC1bc3wfmB4GB0t9aIjl9ubYrKxgL3d4gtVwAAAAdc8Zq55QJ5MRHapXd4g3eC1jaLBYWe+SBP19phXorOQSTu1qcWuiIEE6A8mwW9pMeTDOyFoaJwooD8HNLgh0hIFEHHx9ou0YHql7KCbtN0XrxMNJLhU/EABWp8XJJFxKkH2uYXy5/T6wbuO5TQSuDrl7foiuETyEAfDDKD+zgVPmt5MUIgzWASShvaNZ7cQ22Oct8/w4vyQJpA38/3oMvJN/tp72vz2z1D7Qu9f4K73peEY3OnhYo0EW2jqjhJER8ngeHozTH85yX29uDI6T0zi8dMJEq80ijBlgLwCf9TqgAAAAEAAAABVYYuxWfEuaxvBkivWA/SfIa+XSWTfQxphjVs8yhmpfY="
                }
            }
        ]
    }"###;
}
