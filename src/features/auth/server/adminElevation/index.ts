// Barrel exports for the admin elevation contract.
export { authorizeAdminElevationForDomainMutation, requireAdminElevation } from "./requireAdminElevation";
export { genericForbiddenResponse, GenericForbiddenError, isGenericForbiddenError } from "./genericForbidden";
export type { AdminCapability, AdminElevationContext, AdminSession, ElevationGrant } from "./adminElevation.types";
