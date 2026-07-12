// QStash publish contract helpers for transactional email outbox messages.
import { createHash } from "node:crypto";
import { z } from "zod";
import { env } from "@/lib/env";
import { buildOutboxWorkerMessage, type OutboxWorkerMessage } from "./message";

export type OutboxDedupInput = {
  eventType: string;
  subjectId: string;
  keyVersion?: number | string | null;
  contentVersion: string;
};

export type QStashPublishRequest = {
  url: string;
  init: {
    method: "POST";
    headers: {
      Authorization: string;
      "Content-Type": "application/json";
      "Upstash-Deduplication-Id": string;
      "Upstash-Forward-Authorization": string;
    };
    body: string;
  };
};

export type QStashPublishRequestInput = {
  qstashBaseUrl: string;
  qstashToken: string;
  workerAuthorizationSecret: string;
  destinationUrl: string;
  dedupId: string;
  message: OutboxWorkerMessage;
};

const QStashPublishResponseSchema = z.object({ messageId: z.string().min(1) });

export function buildOutboxDedupId(input: OutboxDedupInput): string {
  const keyVersion = input.keyVersion === null || input.keyVersion === undefined
    ? "none"
    : String(input.keyVersion);
  const material = [input.eventType, input.subjectId, keyVersion, input.contentVersion].join("\u001f");
  return createHash("sha256").update(material, "utf8").digest("hex");
}

export async function publishOutboxEmailId(
  input: QStashPublishRequestInput,
  fetcher: typeof fetch = fetch,
  signal?: AbortSignal,
): Promise<string> {
  const request = buildQStashPublishRequest(input);
  let response: Response;
  try {
    response = await fetcher(request.url, { ...request.init, signal });
  } catch {
    signal?.throwIfAborted();
    throw new Error("QSTASH_PUBLISH_FAILED");
  }
  if (!response.ok) throw new Error("QSTASH_PUBLISH_FAILED");
  const parsed = QStashPublishResponseSchema.safeParse(await response.json().catch(() => null));
  if (!parsed.success) throw new Error("QSTASH_PUBLISH_FAILED");
  return parsed.data.messageId;
}

export async function publishConfiguredOutboxEmail(
  row: { id: string; dedupId: string },
  fetcher: typeof fetch = fetch,
  signal?: AbortSignal,
): Promise<string> {
  const baseUrl = env.QSTASH_URL;
  const token = env.QSTASH_TOKEN;
  const workerSecret = env.INTERNAL_WORKER_AUTH_SECRET;
  const appUrl = env.APP_URL ?? env.AUTH_URL ?? env.NEXTAUTH_URL;
  if (!baseUrl || !token || !workerSecret || !appUrl) throw new Error("QSTASH_CONFIG_MISSING");
  return publishOutboxEmailId({
    qstashBaseUrl: baseUrl,
    qstashToken: token,
    workerAuthorizationSecret: workerSecret,
    destinationUrl: new URL("/api/internal/outbox-email", appUrl).toString(),
    dedupId: row.dedupId,
    message: { id: row.id },
  }, fetcher, signal);
}

export function buildQStashPublishRequest(input: QStashPublishRequestInput): QStashPublishRequest {
  const message = buildOutboxWorkerMessage(input.message);
  return {
    url: `${input.qstashBaseUrl.replace(/\/$/, "")}/v2/publish/${input.destinationUrl}`,
    init: {
      method: "POST",
      headers: {
        Authorization: `Bearer ${input.qstashToken}`,
        "Content-Type": "application/json",
        "Upstash-Deduplication-Id": input.dedupId,
        "Upstash-Forward-Authorization": `Bearer ${input.workerAuthorizationSecret}`,
      },
      body: JSON.stringify(message),
    },
  };
}
