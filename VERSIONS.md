# vade-evan-bbs

## Next Version

### Features

### Fixes

### Deprecations

## v0.4.0

### Features

- add custom function to derive public key from private key (`get_public_key_from_private_key`)
- combine `sdk` and `develop` branches to support both builds on `develop`
- adjust `credential_status` to be optional property in Credential types
- adjust `revocation_list` param in `VerifyProofPayload` to be optional
- adjust types, tests and functions to remove `credential_subject.id` from credentials

### Fixes

- update dependencies for critical vulnerabilities

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
