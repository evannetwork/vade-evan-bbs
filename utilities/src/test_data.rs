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
      "id":"5920976a-e591-476e-be19-82968545e9e9",
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
            "id":"uuid:c2872087-3fe6-4aeb-932d-a528709b0f0a",
            "type":[
               "VerifiableCredential"
            ],
            "issuer":"did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g",
            "issuanceDate":"2023-05-02T12:56:07.000Z",
            "credentialSubject":{
               "data":{
                  "test_property_string3":"value",
                  "test_property_string1":"value",
                  "test_property_string":"value",
                  "test_property_string4":"value",
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
               "type":"BbsBlsSignatureProof2020",
               "created":"2023-05-02T12:56:07.000Z",
               "proofPurpose":"assertionMethod",
               "credentialMessageCount":17,
               "requiredRevealStatements":[1],
               "verificationMethod":"did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g#bbs-key-1",
               "nonce":"Ren4koCh6lIDeeVODbesrd/nZj5rvf5Uj1orC+MyxKY=",
               "proof":"AAADXLaKsJIrzhIoepOUbLoxiYkbVTV5lZFh4qZTVSpegJZjZxPX+tZ5RpRcJIXiJ7HmCo4OHOc5gLDNE8WynpIN+0wKMCm60+XIBc5vTLVoZZStfk8ICC6ernkvbQ64+VicVIMY54eDSE8VJV1J7PkwkdkKDExP47eeRydqQ85Uu7Fj9IQOH2LZPDxHs7QCWTxOyAAAAHSxTgvZ0wvfNaMkwpjGBpUOq5a6egscEj9iNUeWJC6tS7C8Y0SYogr04nFHCFWTzR4AAAACPcNTHZ7tCo3Ee+FwPyIVtuFi6I+t2B5DIHE6FC5aypFj0jpEkhgnbnxyouAZoXbJD12JMAy/yBx3bysu2/gMJ5BWWpj+uO8vm2rcRyaaxoePUy9bR5KmNkQzqFgmasjmZOelK4V+osfHujjcWQWiFgAAABFf9o85jgob5/x6171ivxwowxysBCFVoqnBR+N6JVlf2nEe3ykO2kFIvDNwyKgh0iXZGdhVaYTue6eJQ0QZzwQ6VMia51FfdiGXf4Hwtd14C/E0olhscpvFxJPNIbKftjEoggIg3eMXVMXDD/Ka29uzYJ3IbL+j3i/8KzyId1O/kjsWULxZ0gv19ylIw/S5n4jOc0RE1V5WYn/MflO3TXixX/5OrLWQ4fZoEmG8G8VtVnwCax4/zOMDHKiDb3hesa1w+wAXDrrf7iUHAIWWP/G0OU0aFbehLKmKjvUbTHyy/gwfYxcOHrihq9Lf8mSXazjgZOuHvSBYb+XdmwTioH+hKpXw7CwuaK296Okd9deyw5FJb2glRqshJb5trX3QV3pbK9GfBDL8FS3KMgZKM+GOg6X1TYOFC6W0w1pjb4dA8GNzNDcBrStSdUm0zUtso68kBabLHxIcxF7oms8tBW6qF/F6zQ9mQAFgE8Iw+q5cn4V9/YJFhq0vKICyl4IKdPdYyjmNeB86vmXi3XPg3FMI1Bt0SYgWOxdgwA47PSpdFl4ZwzlPCug7dv1MPP9QnqcSyAjiHKTkh4DT4KHWGZT2SGDRxi3pw1tfbep1Vd/VAGj7yRitiPR+hvVFRiYPizRyoY2frsWEe50E2AZz0WdGWSQEiFQ3KGmVlYHhei9KBmZ0NdTQjqU22/mjntBTZd6Tt10BVVJVdfzUtT3InwUfAAAAAgAAAApbW8IfIW09a9avCC6ldA6iaqjfsZj0JqD6wKVOZZoXBgAAAAsFnuYa41LQpFmhhhn4u2raXdWzPs1CJF+1sQhsXO0KIA=="
            }
         }
      ],
      "proof":{
         "type":"EcdsaPublicKeySecp256k1",
         "created":"2023-05-02T12:56:07.000Z",
         "proofPurpose":"assertionMethod",
         "verificationMethod":"did:evan:verifier#key-1",
         "jws":"eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NkstUiJ9.eyJpYXQiOiIyMDIzLTA1LTAyVDEyOjU2OjA3LjAwMFoiLCJkb2MiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3NjaGVtYS5vcmcvIiwiaHR0cHM6Ly93M2lkLm9yZy92Yy1yZXZvY2F0aW9uLWxpc3QtMjAyMC92MSJdLCJpZCI6IjU5MjA5NzZhLWU1OTEtNDc2ZS1iZTE5LTgyOTY4NTQ1ZTllOSIsInR5cGUiOlsiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJdLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6W3siQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3NjaGVtYS5vcmcvIiwiaHR0cHM6Ly93M2lkLm9yZy92Yy1yZXZvY2F0aW9uLWxpc3QtMjAyMC92MSJdLCJpZCI6InV1aWQ6YzI4NzIwODctM2ZlNi00YWViLTkzMmQtYTUyODcwOWIwZjBhIiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJkaWQ6ZXZhbjpFaURtUmtLc09hZXk4dFB6YzZSeVFyWWtNTmpwcVhYVlRqOWdneTBFYmlYUzRnIiwiaXNzdWFuY2VEYXRlIjoiMjAyMy0wNS0wMlQxMjo1NjowNy4wMDBaIiwiY3JlZGVudGlhbFN1YmplY3QiOnsiZGF0YSI6eyJ0ZXN0X3Byb3BlcnR5X3N0cmluZzMiOiJ2YWx1ZSIsInRlc3RfcHJvcGVydHlfc3RyaW5nIjoidmFsdWUiLCJ0ZXN0X3Byb3BlcnR5X3N0cmluZzQiOiJ2YWx1ZSIsInRlc3RfcHJvcGVydHlfc3RyaW5nMSI6InZhbHVlIiwidGVzdF9wcm9wZXJ0eV9zdHJpbmcyIjoidmFsdWUifX0sImNyZWRlbnRpYWxTY2hlbWEiOnsiaWQiOiJkaWQ6ZXZhbjpFaUJtaUhDSExNYkdWbjlobGxSTTVxUU9zc2h2RVRUb0VBTEJBdEZxUDNQVUlnIiwidHlwZSI6IkV2YW5WQ1NjaGVtYSJ9LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiZGlkOmV2YW46cmV2b2NhdGlvbjEyMyMwIiwidHlwZSI6IlJldm9jYXRpb25MaXN0MjAyMVN0YXR1cyIsInJldm9jYXRpb25MaXN0SW5kZXgiOiIwIiwicmV2b2NhdGlvbkxpc3RDcmVkZW50aWFsIjoiZGlkOmV2YW46cmV2b2NhdGlvbjEyMyJ9LCJwcm9vZiI6eyJ0eXBlIjoiQmJzQmxzU2lnbmF0dXJlUHJvb2YyMDIwIiwiY3JlYXRlZCI6IjIwMjMtMDUtMDJUMTI6NTY6MDcuMDAwWiIsInByb29mUHVycG9zZSI6ImFzc2VydGlvbk1ldGhvZCIsImNyZWRlbnRpYWxNZXNzYWdlQ291bnQiOjE3LCJ2ZXJpZmljYXRpb25NZXRob2QiOiJkaWQ6ZXZhbjpFaURtUmtLc09hZXk4dFB6YzZSeVFyWWtNTmpwcVhYVlRqOWdneTBFYmlYUzRnI2Jicy1rZXktMSIsIm5vbmNlIjoiUmVuNGtvQ2g2bElEZWVWT0RiZXNyZC9uWmo1cnZmNVVqMW9yQytNeXhLWT0iLCJwcm9vZiI6IkFBQURYTGFLc0pJcnpoSW9lcE9VYkxveGlZa2JWVFY1bFpGaDRxWlRWU3BlZ0paalp4UFgrdFo1UnBSY0pJWGlKN0htQ280T0hPYzVnTERORThXeW5wSU4rMHdLTUNtNjArWElCYzV2VExWb1paU3RmazhJQ0M2ZXJua3ZiUTY0K1ZpY1ZJTVk1NGVEU0U4VkpWMUo3UGt3a2RrS0RFeFA0N2VlUnlkcVE4NVV1N0ZqOUlRT0gyTFpQRHhIczdRQ1dUeE95QUFBQUhTeFRndlowd3ZmTmFNa3dwakdCcFVPcTVhNmVnc2NFajlpTlVlV0pDNnRTN0M4WTBTWW9ncjA0bkZIQ0ZXVHpSNEFBQUFDUGNOVEhaN3RDbzNFZStGd1B5SVZ0dUZpNkkrdDJCNURJSEU2RkM1YXlwRmowanBFa2hnbmJueHlvdUFab1hiSkQxMkpNQXkveUJ4M2J5c3UyL2dNSjVCV1dwait1Tzh2bTJyY1J5YWF4b2VQVXk5YlI1S21Oa1F6cUZnbWFzam1aT2VsSzRWK29zZkh1ampjV1FXaUZnQUFBQkZmOW84NWpnb2I1L3g2MTcxaXZ4d293eHlzQkNGVm9xbkJSK042SlZsZjJuRWUzeWtPMmtGSXZETnd5S2doMGlYWkdkaFZhWVR1ZTZlSlEwUVp6d1E2Vk1pYTUxRmZkaUdYZjRId3RkMTRDL0Uwb2xoc2NwdkZ4SlBOSWJLZnRqRW9nZ0lnM2VNWFZNWEREL0thMjl1ellKM0liTCtqM2kvOEt6eUlkMU8va2pzV1VMeFowZ3YxOXlsSXcvUzVuNGpPYzBSRTFWNVdZbi9NZmxPM1RYaXhYLzVPckxXUTRmWm9FbUc4RzhWdFZud0NheDQvek9NREhLaURiM2hlc2Exdyt3QVhEcnJmN2lVSEFJV1dQL0cwT1UwYUZiZWhMS21LanZVYlRIeXkvZ3dmWXhjT0hyaWhxOUxmOG1TWGF6amdaT3VIdlNCWWIrWGRtd1Rpb0graEtwWHc3Q3d1YUsyOTZPa2Q5ZGV5dzVGSmIyZ2xScXNoSmI1dHJYM1FWM3BiSzlHZkJETDhGUzNLTWdaS00rR09nNlgxVFlPRkM2VzB3MXBqYjRkQThHTnpORGNCclN0U2RVbTB6VXRzbzY4a0JhYkxIeEljeEY3b21zOHRCVzZxRi9GNnpROW1RQUZnRThJdytxNWNuNFY5L1lKRmhxMHZLSUN5bDRJS2RQZFl5am1OZUI4NnZtWGkzWFBnM0ZNSTFCdDBTWWdXT3hkZ3dBNDdQU3BkRmw0Wnd6bFBDdWc3ZHYxTVBQOVFucWNTeUFqaUhLVGtoNERUNEtIV0daVDJTR0RSeGkzcHcxdGZiZXAxVmQvVkFHajd5Uml0aVBSK2h2VkZSaVlQaXpSeW9ZMmZyc1dFZTUwRTJBWnowV2RHV1NRRWlGUTNLR21WbFlIaGVpOUtCbVowTmRUUWpxVTIyL21qbnRCVFpkNlR0MTBCVlZKVmRmelV0VDNJbndVZkFBQUFBZ0FBQUFwYlc4SWZJVzA5YTlhdkNDNmxkQTZpYXFqZnNaajBKcUQ2d0tWT1pab1hCZ0FBQUFzRm51WWE0MUxRcEZtaGhobjR1MnJhWGRXelBzMUNKRisxc1Foc1hPMEtJQT09In19XX0sImlzcyI6ImRpZDpldmFuOnZlcmlmaWVyIn0.3pC8nIGxB9NrENJq7gdMv7edE7fyihDy-5FptUg0kcFrCjgSryj74q7V0oh30bIRRr6PXdpURda4Dh_Pp4peMgA"
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
                    "requiredRevealStatements":[1],
                    "verificationMethod": "did:evan:EiDmRkKsOaey8tPzc6RyQrYkMNjpqXXVTj9ggy0EbiXS4g#bbs-key-1",
                    "nonce": "XxApxRDBXaF0QCXHh7zMS7Ms2ELVcBUc0TdhfaAzH8o=",
                    "proof": "BBBCHKtugFHiaXgjrnI+pyfT6f3J5fGUQDJh0JfDsbH0kurhMMdVUkB3gIUCFLksvRm1Ca8o+LkqLH4/lEcVGOd1aldGNsAw5IyEPmeWReYDPLSJroqSPdecEk8bLYbRR/SDno7FWUMUYOovWi/3jAyo7lrNlf4rKJW+2FRgvlf8HzWwaZhk1dB5uynsRIrwnDjqjwAAAHSEMZIcRYIj+fsVov2nt40lhyumTCdK0rlqDjIs1MHAJqNoWhrxqIFp5w6iZfYTlzoAAAACIWxKnfGSrrDg26fcm01ky3Wr1hCJ8I9PuuQ7SBpbaYhNprKueXJeMlIMCa1ocLiaWwurNikj4sfhtp3FnihEjYMUnP6MpwrZNKWYEVWID8y06YSaQDvC1bc3wfmB4GB0t9aIjl9ubYrKxgL3d4gtVwAAAAdc8Zq55QJ5MRHapXd4g3eC1jaLBYWe+SBP19phXorOQSTu1qcWuiIEE6A8mwW9pMeTDOyFoaJwooD8HNLgh0hIFEHHx9ou0YHql7KCbtN0XrxMNJLhU/EABWp8XJJFxKkH2uYXy5/T6wbuO5TQSuDrl7foiuETyEAfDDKD+zgVPmt5MUIgzWASShvaNZ7cQ22Oct8/w4vyQJpA38/3oMvJN/tp72vz2z1D7Qu9f4K73peEY3OnhYo0EW2jqjhJER8ngeHozTH85yX29uDI6T0zi8dMJEq80ijBlgLwCf9TqgAAAAEAAAABVYYuxWfEuaxvBkivWA/SfIa+XSWTfQxphjVs8yhmpfY="
                }
            }
        ]
    }"###;
}
