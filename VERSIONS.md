# vade-evan-bbs

## Next Version

### Features

- add `vc_zkp_propose_proof` to add propose step, that can be done before requesting proofs
- add support to accept `BbsProofProposal` as input for `vc_zkp_request_proof`
- make proof in `ProofPresentation` optional and skip proof verification if not provided
- update `vc_zkp_create_revocation_registry_definition` and `vc_zkp_revoke_credential` to skip proof generation
  if `issuer_public_key_did` or `issuer_proving_key` are not provided
- update `signer_address` in `VerifyProofPayload` to be optional

### Fixes

- adjust `credentialStatus` to be optional property in TypeScript typings for `IssueCredentialPayload`

### Deprecations

- the field `id` is now using a struct to wrap (de)serialization (`PrefixedUuid`) and its value must now be prefixed with `uuid:` in `DraftBbsCredential` and therefore in:
  - `OfferCredentialPayload`
  - `RequestCredentialPayload`
  - `IssueCredentialPayload`
  - `BbsCredential`
  - `UnsignedBbsCredential`
  - `UnfinishedBbsCredential`
  - `BbsPresentation`

## v0.4.0

### Features

- add custom function to derive public key from private key (`get_public_key_from_private_key`)
- combine `sdk` and `develop` branches to support both builds on `develop`
- adjust `credential_status` to be optional property in Credential types
- adjust `revocation_list` param in `VerifyProofPayload` to be optional
- adjust types, tests and functions to remove `credential_subject.id` from credentials
- implement handling for `required_revealed_statements` in presentation creation and verification

### Fixes

- update dependencies for critical vulnerabilities
- fix credential size is increasing when revoking, because old proof was not removed before

## v0.3.0

### Features

- Refactor data structures and adjust test cases
- make credential subject id (and respective properties in credential flow) optional
- make the "verifierDid" optional for generating proof requests
- update signing to use `vade-signer` instead of `vade-evan-substrate`

### Fixes

- add validUntil to returned credential when its getting "finished"

## v0.2.0

### Features

- removed internal resolval of did documents, instead the complete did document for revocation registry needs to be passed

## v0.1.1

### Fixes

- added git urls as dependencies

## Initial Version

- add initial project setup
