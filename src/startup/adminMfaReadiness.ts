// Defines the fail-closed Node production startup gate for stored admin MFA keys.
export type AdminMfaStartupReadinessInput = Readonly<{
  runtime: string | undefined;
  nodeEnv: string | undefined;
  validate: () => Promise<void>;
}>;

export async function runAdminMfaStartupReadiness(input: AdminMfaStartupReadinessInput): Promise<void> {
  if (input.runtime !== "nodejs" || input.nodeEnv !== "production") return;
  await input.validate();
}
