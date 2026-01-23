/**
 * Verifiable Credentials Type Definitions
 *
 * OpenID for Verifiable Credential Issuance (OpenID4VCI)
 * OpenID for Verifiable Presentations (OpenID4VP)
 */

/**
 * Credential format
 */
export type CredentialFormat =
  | 'jwt_vc_json'
  | 'jwt_vc_json-ld'
  | 'ldp_vc'
  | 'vc+sd-jwt'
  | 'mso_mdoc';

/**
 * Credential subject
 */
export interface CredentialSubject {
  id?: string;
  [key: string]: unknown;
}

/**
 * Verifiable Credential (W3C Data Model)
 */
export interface VerifiableCredential {
  '@context': string[];
  id?: string;
  type: string[];
  issuer: string | { id: string; [key: string]: unknown };
  issuanceDate: string;
  expirationDate?: string;
  credentialSubject: CredentialSubject | CredentialSubject[];
  proof?: {
    type: string;
    created: string;
    verificationMethod: string;
    proofPurpose: string;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

/**
 * Credential request (OpenID4VCI)
 */
export interface CredentialRequest {
  format: CredentialFormat;
  credential_definition?: {
    type: string[];
    [key: string]: unknown;
  };
  proof?: {
    proof_type: 'jwt';
    jwt: string;
  };
}

/**
 * Credential response (OpenID4VCI)
 */
export interface CredentialResponse {
  format: CredentialFormat;
  credential?: string | object;
  c_nonce?: string;
  c_nonce_expires_in?: number;
}

/**
 * Credential offer (OpenID4VCI)
 */
export interface CredentialOffer {
  credential_issuer: string;
  credential_configuration_ids: string[];
  grants?: {
    authorization_code?: {
      issuer_state?: string;
    };
    'urn:ietf:params:oauth:grant-type:pre-authorized_code'?: {
      'pre-authorized_code': string;
      tx_code?: {
        input_mode?: 'numeric' | 'text';
        length?: number;
        description?: string;
      };
    };
  };
}

/**
 * Presentation definition (OpenID4VP)
 */
export interface PresentationDefinition {
  id: string;
  name?: string;
  purpose?: string;
  input_descriptors: InputDescriptor[];
}

/**
 * Input descriptor (OpenID4VP)
 */
export interface InputDescriptor {
  id: string;
  name?: string;
  purpose?: string;
  format?: Record<string, unknown>;
  constraints?: {
    fields?: FieldConstraint[];
    limit_disclosure?: 'required' | 'preferred';
  };
}

/**
 * Field constraint
 */
export interface FieldConstraint {
  path: string[];
  filter?: {
    type: string;
    [key: string]: unknown;
  };
}

/**
 * Verifiable Presentation (W3C Data Model)
 */
export interface VerifiablePresentation {
  '@context': string[];
  type: string[];
  verifiableCredential: (string | VerifiableCredential)[];
  holder?: string;
  proof?: {
    type: string;
    created: string;
    verificationMethod: string;
    proofPurpose: string;
    challenge?: string;
    domain?: string;
    [key: string]: unknown;
  };
}

/**
 * Authorization request (OpenID4VP)
 */
export interface AuthorizationRequest {
  response_type: 'vp_token';
  client_id: string;
  redirect_uri: string;
  presentation_definition: PresentationDefinition;
  nonce: string;
  state?: string;
}

/**
 * Authorization response (OpenID4VP)
 */
export interface AuthorizationResponse {
  vp_token: string;
  presentation_submission: PresentationSubmission;
  state?: string;
}

/**
 * Presentation submission
 */
export interface PresentationSubmission {
  id: string;
  definition_id: string;
  descriptor_map: DescriptorMap[];
}

/**
 * Descriptor map entry
 */
export interface DescriptorMap {
  id: string;
  format: string;
  path: string;
  path_nested?: DescriptorMap;
}
