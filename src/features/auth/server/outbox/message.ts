// Outbox worker message parsing and QStash-safe body construction.
import { z } from "zod";

export const outboxEmailEventTypes = ["EMAIL_VERIFICATION", "INVITATION_DELIVERY"] as const;

export const OutboxWorkerMessageSchema = z
  .object({
    id: z.string().min(1),
  })
  .strict();

export type OutboxWorkerMessage = z.infer<typeof OutboxWorkerMessageSchema>;

export function buildOutboxWorkerMessage(message: OutboxWorkerMessage): OutboxWorkerMessage {
  return OutboxWorkerMessageSchema.parse(message);
}
