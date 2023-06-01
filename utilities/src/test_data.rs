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
        "schema": "did:evan:EiBmiHCHLMbGVn9hllRM5qQOsshvETToEALBAtFqP3PUIg"
    }
    "###;
}

#[allow(dead_code)]
pub mod bbs_coherent_context_test_data {
    pub const UNFINISHED_CREDENTIAL: &str = r###"{
      "@context":[
         "https://www.w3.org/2018/credentials/v1",
         "https://schema.org/",
         "https://w3id.org/vc-revocation-list-2020/v1"
      ],
      "id":"uuid:c2872087-3fe6-4aeb-932d-a528709b0f0a",
      "type":[
         "VerifiableCredential"
      ],
      "issuer":"did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g",
      "issuanceDate":"2023-05-02T12:56:07.000Z",
      "credentialSubject":{
         "data":{
            "test_property_string1":"value",
            "test_property_string4":"value",
            "test_property_string3":"value",
            "test_property_string2":"value",
            "test_property_string":"value"
         }
      },
      "credentialSchema":{
         "id":"did:evan:EiBmiHCHLMbGVn9hllRM5qQOsshvETToEALBAtFqP3PUIg",
         "type":"EvanVCSchema"
      },
      "credentialStatus":{
         "id":"did:evan:revocation123#0",
         "type":"RevocationList2021Status",
         "revocationListIndex":"0",
         "revocationListCredential":"did:evan:revocation123"
      },
      "proof":{
         "type":"BbsBlsSignature2020",
         "created":"2023-05-02T12:56:07.000Z",
         "proofPurpose":"assertionMethod",
         "verificationMethod":"did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g#bbs-key-1",
         "credentialMessageCount":17,
         "requiredRevealStatements":[
            1
         ],
         "blindSignature":"i96noCN2UoXK/7iId5K2xSl5nGA7v+Mot+NVxGLLFfjvW/YYrQKWyY9frmH/VYcHUmBvXjIRx3hz41nPZ6JOX14PXPgCczFvs6HOxEBGWnNUrN+5fMi6zs95oxrzQdeY9lEhHmUQmNZEiS7dNi6Svw=="
      }
   }"###;

    pub const FINISHED_CREDENTIAL: &str = r###"{
      "@context":[
         "https://www.w3.org/2018/credentials/v1",
         "https://schema.org/",
         "https://w3id.org/vc-revocation-list-2020/v1"
      ],
      "id":"uuid:c2872087-3fe6-4aeb-932d-a528709b0f0a",
      "type":[
         "VerifiableCredential"
      ],
      "issuer":"did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g",
      "issuanceDate":"2023-05-02T12:56:07.000Z",
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
         "type":"EvanVCSchema"
      },
      "credentialStatus":{
         "id":"did:evan:revocation123#0",
         "type":"RevocationList2021Status",
         "revocationListIndex":"0",
         "revocationListCredential":"did:evan:revocation123"
      },
      "proof":{
         "type":"BbsBlsSignature2020",
         "created":"2023-05-02T12:56:07.000Z",
         "proofPurpose":"assertionMethod",
         "verificationMethod":"did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g#bbs-key-1",
         "credentialMessageCount":17,
         "requiredRevealStatements":[
            1
         ],
         "signature":"i96noCN2UoXK/7iId5K2xSl5nGA7v+Mot+NVxGLLFfjvW/YYrQKWyY9frmH/VYcHUmBvXjIRx3hz41nPZ6JOX14PXPgCczFvs6HOxEBGWnM7kdy88X2Tn/wQQY3zgzuwInkiR1d6Gbm9AfkmAnLufg=="
      }
   }"###;

    pub const UNSIGNED_CREDENTIAL: &str = r###"{
        "@context":[
           "https://www.w3.org/2018/credentials/v1",
           "https://schema.org/",
           "https://w3id.org/vc-revocation-list-2020/v1"
        ],
        "id":"uuid:94450c72-5dc4-4e46-8df0-106819064656",
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

    pub const SIGNATURE_BLINDING: &str = "WtKkVp5SVhlf0HZ7CeM8HH/lpSvyZ9zieHjKR8xEW8A=";

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

    pub const SCHEMA_DID: &str = "did:evan:EiBmiHCHLMbGVn9hllRM5qQOsshvETToEALBAtFqP3PUIg";
    pub const SCHEMA: &str = r###"{

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
      "createdAt":"2023-05-02T12:56:07.000Z",
      "nonce":"Ren4koCh6lIDeeVODbesrd/nZj5rvf5Uj1orC+MyxKY=",
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
      "createdAt":"2023-05-02T12:56:07.000Z",
      "nonce":"Ren4koCh6lIDeeVODbesrd/nZj5rvf5Uj1orC+MyxKY=",
      "type":"BBS",
      "subProofRequests":[
         {
            "schema":"did:evan:EiBmiHCHLMbGVn9hllRM5qQOsshvETToEALBAtFqP3PUIg",
            "revealedAttributes":[
               10,11
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
        "id":"eef83094-8ac1-498e-857e-9ee616166874",
        "type":[
           "VerifiablePresentation"
        ],
        "verifiableCredential":[
           {
              "@context":[
                 "https://www.w3.org/2018/credentials/v1",
                 "https://schema.org/",
                 "https://w3id.org/vc-revocation-list-2020/v1"
              ],
              "id":"uuid:bacd08f9-70c1-400a-b02b-8c25266801fc",
              "type":[
                 "VerifiableCredential"
              ],
              "issuer":"did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g",
              "issuanceDate":"2023-05-11T09:08:30.000Z",
              "credentialSubject":{
                 "data":{
                    "test_property_string3":"value",
                    "test_property_string":"value",
                    "test_property_string2":"value",
                    "test_property_string1":"value",
                    "test_property_string4":"value"
                 }
              },
              "credentialSchema":{
                 "id":"did:evan:EiBmiHCHLMbGVn9hllRM5qQOsshvETToEALBAtFqP3PUIg",
                 "type":"EvanVCSchema"
              },
              "credentialStatus":{
                 "id":"did:evan:revocation123#0",
                 "type":"RevocationList2021Status",
                 "revocationListIndex":"0",
                 "revocationListCredential":"did:evan:revocation123"
              },
              "proof":{
                 "type":"BbsBlsSignatureProof2020",
                 "created":"2023-05-11T09:08:30.000Z",
                 "proofPurpose":"assertionMethod",
                 "credentialMessageCount":17,
                 "verificationMethod":"did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g#bbs-key-1",
                 "requiredRevealStatements":[
                    1
                 ],
                 "nonce":"SOl8UwURM8e25OmQdWnuRbjN9odp3VLvIkjoQLKkqKM=",
                 "proof":"AAADPK/vJrC2jKwaR66pJRln5YEVlBb2ahgk69m+AjWvgMoJIoZcQFJ7q1lt/f5Zyd2YjpAPsyVtD/IUUKJP5AT/o0IENYvowNxwWQpJBmKkg1rh2hZ0wTiW4PDanV68LzPbtIZo52vQov6p1lRV3mPs6xM/fv3aK1hmo1vdwGldMEVy3i7HkXQZh8EVfznigyuenAAAAHSHog3MayRRDrIlHShgZ0rWVazCyy6gJRSI1EyfG2GkeX9lzxnK0/3+4Uh+S+q/+yoAAAACMXz1UD6KLjj0AG0WLS1vIH8pLdOxMHZnZJVJLPtz2yQVZrpu7Vlm9rOrORtUyreXZnVRrJv0U1a5JJtquAJNdpB5AEeUI+Sw7CV/uwlGTwJpVeC7uH0wJvqSNSqK4QxteTpthgYhtOBYYxZakfgL/AAAABAMc/8nNHJ1oqLAP5jeSAWQVU7nRYhmzNvP18rRvqJHCEEkfh0p4oUAoytCjY7dNuYgqt3eN3DdyB2dE82hmddFAjWwjcOBXIbkTaAb7EuFpVyqTmZmhI4f0pGEipZaaypTJKqZAJz7yS5b+pPLHYPws4P9k6BW8QJQiR92p+rztFejcbyVbbbDQfKBq0D3/zeOqnjbfrPpD4GN8qpTJfcgAijXwdhUS8FNPvOw03NhQY9AcSxyourl+iU1uKVbW91cKsiqQyoOVBDppSi59YXcQ2yt41YnfgO1cPTFSgC3FV55OfqGZdAv5J5FuMvMrliiT/BYo/xQkVCysKA03voCB/rpUYhPrEIszGzMz6DaCudSewf36+esRSRY4x4zYmRipJ2tGszZ69L3ymqXrf9sGuyHCX1BXsB3rHo1LSiALzva6XwU5zQjLwypRLh/LLhZcXk+yPgCNfozXXnLvcuILG2GrewSMqfN2pvJF2PoJm4HiriJuM+ToQgDHB82esk8+lz41ehjSY7hJUqHU57oYKvy1w5mjGlIDLRamiwQvgUWwggKdFgN1+PiVhcxVc7HCf1C+ZJ/rzzXMpV70iOXTBu4P2NWLrvu3fjJMrmGNtJkIx1vfF7nAD4z7KUSooEam0PtPvPPUC+f8eg1QDCRbTL+SbcdEVkNExbNfE2SoAAAAAMAAAABFN4XaxUBPChiGzTnZ97Rwp65wHsUo6dM7lQbtDOyNcQAAAAKSL9XmufOj5Sei+rHLru0gEkw73SjwF2aX8iuixs+quEAAAALcNid9ZwC9vrKXg7JI4keNSSF+mgyW8Kz+QgFt255TsM="
              }
           }
        ],
        "proof":{
           "type":"EcdsaPublicKeySecp256k1",
           "created":"2023-05-11T09:08:30.000Z",
           "proofPurpose":"assertionMethod",
           "verificationMethod":"did:evan:verifier#key-1",
           "jws":"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOiIyMDIzLTA1LTExVDA5OjA4OjMwLjAwMFoiLCJkb2MiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3NjaGVtYS5vcmcvIiwiaHR0cHM6Ly93M2lkLm9yZy92Yy1yZXZvY2F0aW9uLWxpc3QtMjAyMC92MSJdLCJpZCI6ImVlZjgzMDk0LThhYzEtNDk4ZS04NTdlLTllZTYxNjE2Njg3NCIsInR5cGUiOlsiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJdLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6W3siQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3NjaGVtYS5vcmcvIiwiaHR0cHM6Ly93M2lkLm9yZy92Yy1yZXZvY2F0aW9uLWxpc3QtMjAyMC92MSJdLCJpZCI6InV1aWQ6YmFjZDA4ZjktNzBjMS00MDBhLWIwMmItOGMyNTI2NjgwMWZjIiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJkaWQ6ZXZhbjpFaURtUmtLc09hZXk4dFB6YzZSeVFyWWtNTmpwcVhYVlRqOWdneTBFYmlYUzRnIiwiaXNzdWFuY2VEYXRlIjoiMjAyMy0wNS0xMVQwOTowODozMC4wMDBaIiwiY3JlZGVudGlhbFN1YmplY3QiOnsiZGF0YSI6eyJ0ZXN0X3Byb3BlcnR5X3N0cmluZzQiOiJ2YWx1ZSIsInRlc3RfcHJvcGVydHlfc3RyaW5nMyI6InZhbHVlIiwidGVzdF9wcm9wZXJ0eV9zdHJpbmciOiJ2YWx1ZSIsInRlc3RfcHJvcGVydHlfc3RyaW5nMiI6InZhbHVlIiwidGVzdF9wcm9wZXJ0eV9zdHJpbmcxIjoidmFsdWUifX0sImNyZWRlbnRpYWxTY2hlbWEiOnsiaWQiOiJkaWQ6ZXZhbjpFaUJtaUhDSExNYkdWbjlobGxSTTVxUU9zc2h2RVRUb0VBTEJBdEZxUDNQVUlnIiwidHlwZSI6IkV2YW5WQ1NjaGVtYSJ9LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiZGlkOmV2YW46cmV2b2NhdGlvbjEyMyMwIiwidHlwZSI6IlJldm9jYXRpb25MaXN0MjAyMVN0YXR1cyIsInJldm9jYXRpb25MaXN0SW5kZXgiOiIwIiwicmV2b2NhdGlvbkxpc3RDcmVkZW50aWFsIjoiZGlkOmV2YW46cmV2b2NhdGlvbjEyMyJ9LCJwcm9vZiI6eyJ0eXBlIjoiQmJzQmxzU2lnbmF0dXJlUHJvb2YyMDIwIiwiY3JlYXRlZCI6IjIwMjMtMDUtMTFUMDk6MDg6MzAuMDAwWiIsInByb29mUHVycG9zZSI6ImFzc2VydGlvbk1ldGhvZCIsImNyZWRlbnRpYWxNZXNzYWdlQ291bnQiOjE3LCJ2ZXJpZmljYXRpb25NZXRob2QiOiJkaWQ6ZXZhbjpFaURtUmtLc09hZXk4dFB6YzZSeVFyWWtNTmpwcVhYVlRqOWdneTBFYmlYUzRnI2Jicy1rZXktMSIsInJlcXVpcmVkUmV2ZWFsU3RhdGVtZW50cyI6WzFdLCJub25jZSI6IlNPbDhVd1VSTThlMjVPbVFkV251UmJqTjlvZHAzVkx2SWtqb1FMS2txS009IiwicHJvb2YiOiJBQUFEUEsvdkpyQzJqS3dhUjY2cEpSbG41WUVWbEJiMmFoZ2s2OW0rQWpXdmdNb0pJb1pjUUZKN3ExbHQvZjVaeWQyWWpwQVBzeVZ0RC9JVVVLSlA1QVQvbzBJRU5Zdm93Tnh3V1FwSkJtS2tnMXJoMmhaMHdUaVc0UERhblY2OEx6UGJ0SVpvNTJ2UW92NnAxbFJWM21QczZ4TS9mdjNhSzFobW8xdmR3R2xkTUVWeTNpN0hrWFFaaDhFVmZ6bmlneXVlbkFBQUFIU0hvZzNNYXlSUkRySWxIU2hnWjByV1ZhekN5eTZnSlJTSTFFeWZHMkdrZVg5bHp4bkswLzMrNFVoK1MrcS8reW9BQUFBQ01YejFVRDZLTGpqMEFHMFdMUzF2SUg4cExkT3hNSFpuWkpWSkxQdHoyeVFWWnJwdTdWbG05ck9yT1J0VXlyZVhablZSckp2MFUxYTVKSnRxdUFKTmRwQjVBRWVVSStTdzdDVi91d2xHVHdKcFZlQzd1SDB3SnZxU05TcUs0UXh0ZVRwdGhnWWh0T0JZWXhaYWtmZ0wvQUFBQUJBTWMvOG5OSEoxb3FMQVA1amVTQVdRVlU3blJZaG16TnZQMThyUnZxSkhDRUVrZmgwcDRvVUFveXRDalk3ZE51WWdxdDNlTjNEZHlCMmRFODJobWRkRkFqV3dqY09CWElia1RhQWI3RXVGcFZ5cVRtWm1oSTRmMHBHRWlwWmFheXBUSktxWkFKejd5UzViK3BQTEhZUHdzNFA5azZCVzhRSlFpUjkycCtyenRGZWpjYnlWYmJiRFFmS0JxMEQzL3plT3FuamJmclBwRDRHTjhxcFRKZmNnQWlqWHdkaFVTOEZOUHZPdzAzTmhRWTlBY1N4eW91cmwraVUxdUtWYlc5MWNLc2lxUXlvT1ZCRHBwU2k1OVlYY1EyeXQ0MVluZmdPMWNQVEZTZ0MzRlY1NU9mcUdaZEF2NUo1RnVNdk1ybGlpVC9CWW8veFFrVkN5c0tBMDN2b0NCL3JwVVloUHJFSXN6R3pNejZEYUN1ZFNld2YzNitlc1JTUlk0eDR6WW1SaXBKMnRHc3paNjlMM3ltcVhyZjlzR3V5SENYMUJYc0IzckhvMUxTaUFMenZhNlh3VTV6UWpMd3lwUkxoL0xMaFpjWGsreVBnQ05mb3pYWG5MdmN1SUxHMkdyZXdTTXFmTjJwdkpGMlBvSm00SGlyaUp1TStUb1FnREhCODJlc2s4K2x6NDFlaGpTWTdoSlVxSFU1N29ZS3Z5MXc1bWpHbElETFJhbWl3UXZnVVd3Z2dLZEZnTjErUGlWaGN4VmM3SENmMUMrWkovcnp6WE1wVjcwaU9YVEJ1NFAyTldMcnZ1M2ZqSk1ybUdOdEprSXgxdmZGN25BRDR6N0tVU29vRWFtMFB0UHZQUFVDK2Y4ZWcxUURDUmJUTCtTYmNkRVZrTkV4Yk5mRTJTb0FBQUFBTUFBQUFCRk40WGF4VUJQQ2hpR3pUblo5N1J3cDY1d0hzVW82ZE03bFFidERPeU5jUUFBQUFLU0w5WG11Zk9qNVNlaStySExydTBnRWt3NzNTandGMmFYOGl1aXhzK3F1RUFBQUFMY05pZDlad0M5dnJLWGc3Skk0a2VOU1NGK21neVc4S3orUWdGdDI1NVRzTT0ifX1dfSwiaXNzIjoiZGlkOmV2YW46dmVyaWZpZXIifQ.DZ_7YdG2ONbNZx7vuxD2BOGshj_RAuvitcW2xDMCYn5UNVbs72ZiWkUBM6MdTVF9vTF9IjbXrISWgJOmeaejIwA"
        }
     }"###;

    pub const PROOF_PRESENTATION_INVALID_SIGNATURE_AND_WITHOUT_JWS: &str = r###"{
        "@context":[
           "https://www.w3.org/2018/credentials/v1",
           "https://schema.org/",
           "https://w3id.org/vc-revocation-list-2020/v1"
        ],
        "id":"eef83094-8ac1-498e-857e-9ee616166874",
        "type":[
           "VerifiablePresentation"
        ],
        "verifiableCredential":[
           {
              "@context":[
                 "https://www.w3.org/2018/credentials/v1",
                 "https://schema.org/",
                 "https://w3id.org/vc-revocation-list-2020/v1"
              ],
              "id":"uuid:bacd08f9-70c1-400a-b02b-8c25266801fc",
              "type":[
                 "VerifiableCredential"
              ],
              "issuer":"did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g",
              "issuanceDate":"2023-05-11T09:08:30.000Z",
              "credentialSubject":{
                 "data":{
                    "test_property_string3":"value",
                    "test_property_string":"value",
                    "test_property_string2":"value",
                    "test_property_string1":"value",
                    "test_property_string4":"value"
                 }
              },
              "credentialSchema":{
                 "id":"did:evan:EiBmiHCHLMbGVn9hllRM5qQOsshvETToEALBAtFqP3PUIg",
                 "type":"EvanVCSchema"
              },
              "credentialStatus":{
                 "id":"did:evan:revocation123#0",
                 "type":"RevocationList2021Status",
                 "revocationListIndex":"0",
                 "revocationListCredential":"did:evan:revocation123"
              },
              "proof":{
                 "type":"BbsBlsSignatureProof2020",
                 "created":"2023-05-11T09:08:30.000Z",
                 "proofPurpose":"assertionMethod",
                 "credentialMessageCount":17,
                 "verificationMethod":"did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g#bbs-key-1",
                 "requiredRevealStatements":[
                    1
                 ],
                 "nonce":"SOl8UwURM8e25OmQdWnuRbjN9odp3VLvIkjoQLKkqKM=",
                 "proof": "BBBCHKtugFHiaXgjrnI+pyfT6f3J5fGUQDJh0JfDsbH0kurhMMdVUkB3gIUCFLksvRm1Ca8o+LkqLH4/lEcVGOd1aldGNsAw5IyEPmeWReYDPLSJroqSPdecEk8bLYbRR/SDno7FWUMUYOovWi/3jAyo7lrNlf4rKJW+2FRgvlf8HzWwaZhk1dB5uynsRIrwnDjqjwAAAHSEMZIcRYIj+fsVov2nt40lhyumTCdK0rlqDjIs1MHAJqNoWhrxqIFp5w6iZfYTlzoAAAACIWxKnfGSrrDg26fcm01ky3Wr1hCJ8I9PuuQ7SBpbaYhNprKueXJeMlIMCa1ocLiaWwurNikj4sfhtp3FnihEjYMUnP6MpwrZNKWYEVWID8y06YSaQDvC1bc3wfmB4GB0t9aIjl9ubYrKxgL3d4gtVwAAAAdc8Zq55QJ5MRHapXd4g3eC1jaLBYWe+SBP19phXorOQSTu1qcWuiIEE6A8mwW9pMeTDOyFoaJwooD8HNLgh0hIFEHHx9ou0YHql7KCbtN0XrxMNJLhU/EABWp8XJJFxKkH2uYXy5/T6wbuO5TQSuDrl7foiuETyEAfDDKD+zgVPmt5MUIgzWASShvaNZ7cQ22Oct8/w4vyQJpA38/3oMvJN/tp72vz2z1D7Qu9f4K73peEY3OnhYo0EW2jqjhJER8ngeHozTH85yX29uDI6T0zi8dMJEq80ijBlgLwCf9TqgAAAAEAAAABVYYuxWfEuaxvBkivWA/SfIa+XSWTfQxphjVs8yhmpfY="
                }
           }
        ]
     }"###;
}
