// Routes startup invariants to a runtime-specific instrumentation module.
export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    const { registerAdminMfaInstrumentation } = await import("./instrumentation-node");
    await registerAdminMfaInstrumentation(process.env.NEXT_RUNTIME, process.env.NODE_ENV);
  }
}
