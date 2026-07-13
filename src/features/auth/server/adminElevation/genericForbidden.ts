// Parity-safe generic forbidden outcome. The guard throws this on ANY failure so callers
// cannot branch on the reason; the HTTP body is the shared generic admission failure.
import { createGenericAdmissionFailure } from "@/features/auth/server/admission";
import type { GenericAdmissionFailure } from "@/features/auth/server/admission";

export class GenericForbiddenError extends Error {
  constructor() {
    super("ADMIN_ELEVATION_FORBIDDEN");
    this.name = "GenericForbiddenError";
  }
}

export function isGenericForbiddenError(error: unknown): error is GenericForbiddenError {
  return error instanceof GenericForbiddenError;
}

// Identical body/status for every denial (enumeration parity, generic 403).
export function genericForbiddenResponse(): GenericAdmissionFailure {
  return createGenericAdmissionFailure(403);
}
