export type ActionResult =
  | { ok: true }
  | { ok: false; errors: { formErrors?: string[]; fieldErrors?: Record<string, string[]> } };
