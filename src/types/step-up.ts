import type {
  Phase1ErrorDetails,
  StepUpInputState,
  StepUpPreferredMethod,
  StepUpStatusObject,
} from './errors.js';

export interface StepUpDefaultPolicy {
  token_ttl_seconds: number;
  action_ttl_seconds: number;
  receipt_ttl_seconds: number;
  max_attempts: number;
  resend_cooldown_seconds: number;
  max_resends: number;
}

export const DEFAULT_STEP_UP_POLICY: StepUpDefaultPolicy = {
  token_ttl_seconds: 300,
  action_ttl_seconds: 600,
  receipt_ttl_seconds: 300,
  max_attempts: 5,
  resend_cooldown_seconds: 60,
  max_resends: 3,
};

export interface StepUpAcceptableMethods {
  methods: string[];
}

export interface StepUpRequirement {
  step_up_token: string;
  acceptable_methods: StepUpAcceptableMethods;
  expires_at: string;
  expires_at_unix: number;
}

export interface StepUpNextAction {
  type: string;
  method?: string;
  url?: string;
  expires_at?: string;
  expires_at_unix?: number;
  retry_after_seconds?: number;
  [key: string]: unknown;
}

export interface StepUpActionResponse {
  action_id: string;
  status: StepUpStatusObject['status'];
  preferred_method?: StepUpPreferredMethod;
  step_up_receipt?: string;
  next_action?: StepUpNextAction;
  input_state?: StepUpInputState;
  attempts_remaining?: number;
  max_attempts?: number;
  resend_available_at?: string;
  resend_available_at_unix?: number;
  resends_remaining?: number;
  expires_at?: string;
  expires_at_unix?: number;
  updated_at?: string;
  updated_at_unix?: number;
  [key: string]: unknown;
}

export interface StepUpStartRequest {
  step_up_token: string;
  preferred_method?: string;
  context?: Record<string, unknown>;
}

export interface StepUpCompleteRequest<Input = unknown> {
  input: Input;
}

export type StepUpResendResponse = StepUpActionResponse;

export interface StepUpFailureBody {
  error: string;
  error_description?: string;
  error_details?: Phase1ErrorDetails;
  step_up?: StepUpRequirement;
  status?: StepUpStatusObject;
  input_state?: StepUpInputState;
  next_action?: StepUpNextAction;
}
