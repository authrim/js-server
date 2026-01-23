/**
 * Verifiable Credentials Support
 */

export { CredentialIssuer, type CredentialIssuerConfig, type CredentialIssuerMetadata } from './issuer.js';
export { PresentationVerifier, type PresentationVerifierConfig, type PresentationVerificationResult } from './verifier.js';
export type {
  CredentialFormat,
  CredentialSubject,
  VerifiableCredential,
  CredentialRequest,
  CredentialResponse,
  CredentialOffer,
  PresentationDefinition,
  InputDescriptor,
  FieldConstraint,
  VerifiablePresentation,
  AuthorizationRequest,
  AuthorizationResponse,
  PresentationSubmission,
  DescriptorMap,
} from './types.js';
