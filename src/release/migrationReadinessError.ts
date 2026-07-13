// Defines the public error type for fail-closed migration readiness failures.
export class MigrationReadinessError extends Error {
  override readonly name = 'MigrationReadinessError';
}
