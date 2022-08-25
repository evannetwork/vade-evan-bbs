# vade-evan-bbs

## Next Version

### Features

### Fixes

### Deprecations

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
