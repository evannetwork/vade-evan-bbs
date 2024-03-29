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

/*
 * Message following a `BbsCredentialOffer`, sent by a potential credential prover.
 * Provides the values that need to be signed by the issuer in both encoded/cleartext, and blinded format.
 * Incorporates the nonce value sent in `BbsCredentialOffer`.
 */
export interface BbsCredentialRequest {
  credentialOffer: BbsCredentialOffer;
  blindSignatureContext: string;
}

/**
 * Message sent by a prover stating which attributes of which schema he is intending to reveal.
 *
 * All fields (except `createdAt`) will be included in a `BbsProofRequest` created from this proposal.
 */
export interface BbsProofProposal {
  verifier: string;
  createdAt: string;
  nonce: string;
  type: string;
  subProofRequests: BbsSubProofRequest[];
}


/**
 * Message sent by a verifier stating which attributes of which schema the prover is supposed to reveal.
 */
export interface BbsProofRequest {
  verifier: string;
  createdAt: string;
  nonce: string;
  type: string;
  subProofRequests: BbsSubProofRequest[];
}

/**
 * Part of a proof request that requests attributes of a specific schema
 */
export interface BbsSubProofRequest {
  schema: string;
  revealedAttributes: number[];
}

/**
 * Specifies the properties of a credential, as well as metadata.
 * Needs to be stored publicly available and temper-proof.
 */
export interface CredentialSchema {
  id: string;
  type: string;
  name: string;
  author: string;
  createdAt: string;
  description: string;
  properties: Record<string, SchemaProperty>;
  required: string[];
  additionalProperties: boolean;
  proof?: AssertionProof;
}

export interface CredentialDraftOptions {
  issuerDid: String,
  id?: string;
  issuanceDate?: string;
  subjectDid?: string;
  validUntil?: string;
}

export interface SchemaProperty {
  type: string;
  format?: string;
  items?: string[];
}

/**
 * AssertionProof, typically used to ensure authenticity and integrity of a VC document
 */
export interface AssertionProof {
  type: string;
  created: string;
  proofPurpose: string;
  verificationMethod: string;
  jws: string;
}

/**
 * Message sent by an issuer.
 * Defines how the credential to be issued will look like.
 */
export interface BbsCredentialOffer {
  ldProofVcDetail: LdProofVcDetail;
  nonce: string;
}

/**
 * Message to initiate credential issuance, sent by (potential) prover.
 * Specifies the schema to be used for the credential.
 */
export interface CredentialProposal {
  issuer: string;
  schema: string;
}

/**
 * A verifiable credential issued by an issuer upon receiving a `CredentialRequest`.
 * Specifies the signed values, the `CredentialSchema`, and the `CredentialSignature`
 * including revocation info.
 */
export interface BbsCredential {
  '@context': (string | { [key in string]?: { '@type': string } })[];
  id: string;
  type: string[];
  issuer: string;
  credentialSubject: CredentialSubject;
  credentialSchema: CredentialSchemaReference;
  credentialStatus?: CredentialStatus;
  validUntil?: string;
  issuanceDate: string;
  proof: BbsCredentialSignature;
}

/*
 * A VC without the proof part (input for vade to sign)
 */
export interface UnsignedCredential {
  '@context': (string | { [key in string]?: { '@type': string } })[];
  id: string;
  type: string[];
  issuer: string;
  credentialSubject: CredentialSubject;
  credentialSchema: CredentialSchemaReference;
  credentialStatus?: CredentialStatus;
  validUntil?: string;
  issuanceDate: string;
}

/**
 * A verifiable credential with a blind signature that still needs to be processed by the holder
 */
export interface UnfinishedBbsCredential {
  '@context': (string | { [key in string]?: { '@type': string } })[];
  id: string;
  type: string[];
  issuer: string;
  credentialSubject: CredentialSubject;
  credentialSchema: CredentialSchemaReference;
  credentialStatus?: CredentialStatus;
  validUntil?: string;
  issuanceDate: string;
  proof: BbsUnfinishedCredentialSignature;
}

export interface CredentialSubject {
  data: Record<string, string>;
}

export interface CredentialStatus {
  id: string;
  type: string;
  revocationListIndex: string;
  revocationListCredential: string;
}

export interface RevocationListCredentialSubject {
  id: string;
  type: string;
  encodedList: string;
}

export interface CredentialSchemaReference {
  id: string;
  type: string;
}

export interface BbsCredentialSignature {
  type: string;
  created: string;
  proofPurpose: string;
  verificationMethod: string;
  credentialMessageCount: number;
  requiredRevealStatements: number[];
  signature: string;
}

export interface BbsUnfinishedCredentialSignature {
  type: string;
  created: string;
  proofPurpose: string;
  verificationMethod: string;
  credentialMessageCount: number;
  requiredRevealStatements: number[];
  blindSignature: string;
}

/*
 * A collection of all proofs requested in a `ProofRequest`. Sent to a verifier as the response to
 * a `ProofRequest`.
 */
export interface ProofPresentation {
  '@context': (string | { [key in string]?: { '@type': string } })[];
  id: string;
  type: string[];
  verifiableCredential: BbsPresentation[];
  proof: AssertionProof;
}

/*
 * Proof presentation without a proof (just for internal use)
 */
export interface UnfinishedProofPresentation {
  '@context': (string | { [key in string]?: { '@type': string } })[];
  id: string;
  type: string[];
  verifiableCredential: BbsPresentation[];
}

/*
 * A verifiable credential exposing requested properties of a `BbsCredential` by providing a Bbs signature proof
 */
export interface BbsPresentation {
  '@context': (string | { [key in string]?: { '@type': string } })[];
  id: string;
  type: string[];
  issuer: string;
  issuanceDate: string;
  credentialSubject: CredentialSubject;
  credentialSchema: CredentialSchemaReference;
  credentialStatus?: CredentialStatus;
  proof: BbsPresentationProof;
}

/*
 * A proof object of a `BbsPresentation`
 */
export interface BbsPresentationProof {
  type: string;
  created: string;
  proofPurpose: string;
  credentialMessageCount: number;
  verificationMethod: string;
  requiredRevealStatements: number[];
  nonce: string;
  proof: string;
}

export interface BbsProofVerification {
  proof: string;
  status: string;
  reason?: string;
}

/*
 * `RevocationListCredential` without a proof (for internal use only).
 *
 * @deprecated will be removed, use `RevocationListCredential` instead (as `.proof` is optional)
 */
export interface UnproofedRevocationListCredential {
  '@context': (string | { [key in string]?: { '@type': string } })[];
  id: string;
  type: string[];
  issuer: string;
  issued: string;
  credentialSubject: RevocationListCredentialSubject;
}

/*
 * A revocation list credential associating VC revocation IDs to their revocation status as a bit list. See
 * <https://w3c-ccg.github.io/vc-status-rl-2020/#revocationlist2020credential>
 */
export interface RevocationListCredential {
  '@context': (string | { [key in string]?: { '@type': string } })[];
  id: string;
  type: string[];
  issuer: string;
  issued: string;
  credentialSubject: RevocationListCredentialSubject;
  proof?: AssertionProof;
}

export interface DraftBbsCredential {
  '@context': (string | { [key in string]?: { '@type': string } })[];
  id: string;
  type: string[];
  issuer: string;
  issuanceDate: string;
  validUntil?: string;
  credentialSubject: CredentialSubject;
  credentialSchema: CredentialSchemaReference;
}

export enum LdProofVcDetailOptionsType {
  Ed25519Signature2018 = 'Ed25519Signature2018',
}

export enum LdProofVcDetailOptionsCredentialStatusType {
  RevocationList2021Status = 'RevocationList2021Status',
  None = 'None',
}

export interface LdProofVcDetailOptionsCredentialStatus {
  type: LdProofVcDetailOptionsCredentialStatusType;
}

export interface LdProofVcDetailOptions {
    created: string;
    proofType: LdProofVcDetailOptionsType;
    credentialStatus: LdProofVcDetailOptionsCredentialStatus;
    requiredRevealStatements: number[];
}

export interface LdProofVcDetail {
    credential: DraftBbsCredential;
    options: LdProofVcDetailOptions;
}