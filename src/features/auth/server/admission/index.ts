// src/features/auth/server/admission/index.ts
// Barrel exports for shared auth admission controls.
export { issueCsrfToken, validateCsrf } from "./csrf";
export { createGenericAdmissionFailure, padAdmissionTiming } from "./enumerationParity";
export { AdmissionDeadlineExceeded, remainingDeadlineMs, withinDeadline } from "./deadline";
export { monotonicNow, type MonotonicClock } from "./monotonicClock";
export type { AdmissionDecision, CsrfValidationInput, GenericAdmissionFailure } from "./admission.types";
