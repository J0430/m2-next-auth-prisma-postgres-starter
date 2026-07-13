---
id: INCIDENT-P040
date: 2026-07-13
severity: SEV-4
status: VERIFYING
packet: PACKET-02-gated-registration
branch: feat/secure-registration
environment: ci-pipeline
detected_by: user-report
related_incidents: [INCIDENT-P016, INCIDENT-P019, INCIDENT-P022, INCIDENT-P023]
fix_pr: null
---

# INCIDENT-P040 - CI Gated Registration DB Reuse Audit Failure

## Step 0 Incident Memory Check

- **Search terms:** `test:db:gated-registration`, `invite_reuse_audit_failed`, `each replay loser must append one reuse audit event`, `auditPersisted false`, `migration-readiness`
- **Recurrence:** related to `INCIDENT-P019` because both concern disposable PostgreSQL invariant verification.
- **Related but distinct:** related to `INCIDENT-P022` and `INCIDENT-P023` because the failure crosses invite reuse durability and outbox/runtime DB proof.
- **Decision:** raise this as a new child incident because the current symptom is a concrete CI behavioral failure in the real PostgreSQL integration runner.

## Problem

### Symptoms

- GitHub `CI / migration-readiness` fails while running `pnpm test:db:gated-registration`.
- The runner logs repeated `security.invite_reuse_audit_failed` events with `auditPersisted: false`.
- The script throws: `Error: each replay loser must append one reuse audit event`.

### Impact

- **Users affected:** none directly before merge.
- **Features broken:** CI migration-readiness and real PostgreSQL behavioral proof.
- **Data at risk:** potential audit-durability risk if the same condition can occur in production.
- **Workaround exists:** no safe workaround; the integration gate must pass before merge.

### Reproduction Steps

1. Run GitHub `CI / migration-readiness` on `feat/secure-registration`.
2. Execute `pnpm test:db:gated-registration` against disposable PostgreSQL.
3. Observe reuse audit writes fail while alerts fire.

### Evidence

Standalone local recurrence, reported from the pasted output:

```text
DATABASE_URL=postgresql://manumurillo@localhost:5432/auth_ci pnpm test:db:gated-registration

Error: ADMIN_MFA_SECRET_KEYRING_MISSING
    at keyForVersion (.../src/features/auth/server/adminMfa/secretCrypto.ts:27:23)
    at validateStoredAdminMfaKeyVersions (.../src/features/auth/server/adminMfa/secretCrypto.ts:81:42)
    at main (.../scripts/gated-registration-db-integration.ts:714:5)
```

This local recurrence is a test-fixture issue: pre-push exports the admin-MFA
test keyring, but the standalone package script previously did not.

```text
security.invite_reuse_audit_failed {
  inviteId: 'task016-a0a0bd18-9621-4224-9bd9-c77590e92f71-lifecycle-invite',
  auditPersisted: false
}

Error: each replay loser must append one reuse audit event
    at invariant (.../scripts/gated-registration-db-integration.ts:64:25)
    at verifyInviteLifecycleBehavior (.../scripts/gated-registration-db-integration.ts:270:5)
```

Latest CI recurrence, reported 2026-07-13:

```text
security.invite_reuse_audit_failed {
  inviteId: 'task016-af75669e-11c0-4d7c-9964-d76dbef44946-lifecycle-invite',
  auditPersisted: false
}

Error: each replay loser must append one reuse audit event
    at invariant (/home/runner/work/auth-manumu-studio/auth-manumu-studio/scripts/gated-registration-db-integration.ts:64:25)
    at verifyInviteLifecycleBehavior (/home/runner/work/auth-manumu-studio/auth-manumu-studio/scripts/gated-registration-db-integration.ts:272:5)
    at async main (/home/runner/work/auth-manumu-studio/auth-manumu-studio/scripts/gated-registration-db-integration.ts:704:5)
```

### Files Suspected

| File | Why suspected |
|------|--------------|
| `scripts/gated-registration-db-integration.ts` | Contains the failing real PostgreSQL lifecycle assertion. |
| `src/features/auth/server/invites/reuseEvidence.ts` | Persists invite reuse audit events outside the rolled-back transaction. |
| `src/features/auth/server/invites/redeemInvite.ts` | Signals reuse from the invite redemption CAS path. |
| `prisma/schema.prisma` | Defines `AuditEvent` persistence contract. |

### Root Cause Hypothesis

> The reuse-audit persistence path used a 50ms outer `withinDeadline` race around
> the Prisma transaction. Under CI concurrency, the function can mark the audit
> failed and alert with `auditPersisted: false` before the durable write has a
> fair chance to complete.

### What's Blocked

- PR merge readiness.
- `CI / migration-readiness`.
- Confidence that replay losers append durable reuse audit evidence.

## Resolution

### Contributing Factors

1. **Factor:** The integration gate runs concurrent invite replay attempts against real PostgreSQL.
   - **How it contributed:** Timing-sensitive audit persistence failures are visible only in the real DB runner.
   - **Why it was not caught earlier:** Unit tests mock the persistence path and do not exercise CI database timing.

### Was the Hypothesis Correct?

> Pending.

### Files Changed

| File | Change | Why |
|------|--------|-----|
| `src/features/auth/server/invites/reuseEvidence.ts` | Removed the 50ms outer deadline from the audit transaction and uses a larger Prisma transaction wait/timeout budget | Prevent CI from falsely classifying queued durable audit writes as failed. |
| `tests/gated-registration-invites.test.ts` | Asserts the reuse audit transaction uses the hardened budget | Prevent recurrence of the too-tight audit budget. |
| `package.json` | Supplies the local test-only admin-MFA keyring for `pnpm test:db:gated-registration` | Make the standalone DB command match the pre-push fixture environment. |

### Fix Approach

> Keep the audit write durable and awaited. The alert still uses a bounded
> evidence budget, but the database audit write is no longer wrapped in the
> 50ms `Promise.race` that produced CI false failures.

### Regression Risk

- Medium because invite replay audit behavior is a security evidence path.

### Testing Done

- [x] Unit tests pass
- [x] Integration tests pass
- [ ] Manual verification in target environment
- [x] Edge cases tested

### Timeline

| Time (UTC) | Event |
|------------|-------|
| 17:00 | User reported CI migration-readiness still breaking |
| 17:05 | Registry searched and new child incident raised |
| 17:16 | Local invite unit suite and real `auth_ci` DB integration passed after fix |
| 17:20 | Standalone local command reported missing admin-MFA keyring fixture |

### Lessons Learned

**What went well:**
- The real PostgreSQL runner caught a security-relevant durability condition.

**What could be better:**
- Pre-push should include the same DB integration before CI sees it.

### Action Items

| Action | Owner | Deadline | Status | Tracking |
|--------|-------|----------|--------|----------|
| Reproduce `pnpm test:db:gated-registration` locally on `auth_ci` | Codex | 2026-07-13 | DONE | This incident |
| Add the DB integration gate to pre-push | Codex | 2026-07-13 | DONE | `.husky/pre-push` |
| Rerun GitHub migration-readiness | Manu / Codex | 2026-07-13 | TODO | PR checks |

## Conclusion

The disposable PostgreSQL migration-readiness gate failed because replay-loser invite reuse attempts reported failed durable audit writes under a too-tight 50ms audit deadline. The local fix awaits the Prisma audit transaction with a larger budget and now needs GitHub migration-readiness confirmation.
