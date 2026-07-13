---
id: INCIDENT-P039
date: 2026-07-13
severity: SEV-4
status: VERIFYING
packet: PACKET-02-gated-registration
branch: feat/secure-registration
environment: ci-pipeline
detected_by: user-report
related_incidents: [INCIDENT-P009, INCIDENT-P034, INCIDENT-P036]
fix_pr: null
---

# INCIDENT-P039 - CI TASK-028 Evidence Docs Drift

## Step 0 Incident Memory Check

- **Search terms:** `test-coverage`, `TASK-028`, `gated-registration-security-verification`, `No test files found`, `docs/research`, `docs/cursor-tasks`, `clean runner`
- **Recurrence:** related to `INCIDENT-P036` because both block CI coverage, but distinct from the original creation-surface timeout and generated-Prisma-client failures.
- **Related but distinct:** related to `INCIDENT-P009` and `INCIDENT-P034` because the test enforces security evidence contracts.
- **Decision:** raise this as a new child incident because the current failure is clean-runner evidence-file drift.

## Problem

### Symptoms

- GitHub `CI / test-coverage` fails in a clean runner while local context still has the referenced planning/research files.
- The security verification test depends on files that are not guaranteed to be tracked in the repository checkout.

### Impact

- **Users affected:** none directly.
- **Features broken:** CI coverage gate and PR merge readiness.
- **Data at risk:** no.
- **Workaround exists:** yes; remove local-only evidence dependencies or commit the required evidence files.

### Reproduction Steps

1. Run `pnpm test:coverage` in GitHub Actions on `feat/secure-registration`.
2. Let `tests/gated-registration-security-verification.test.ts` read TASK-028 evidence docs.
3. Observe the clean runner fail when local-only files are absent.

### Evidence

```text
User reported CI test-coverage failure on 2026-07-13.
Prior failing paths included local-only TASK-028 evidence files under docs/research
and docs/cursor-tasks, while only docs/build-packets/PACKET-02-gated-registration.md
is confirmed tracked.
```

Follow-up screenshot on 2026-07-13 shows `CI / test-coverage (pull_request)`
and `CI / test-coverage (push)` both successful, so this incident is in
VERIFYING pending final PR green state.

### Files Suspected

| File | Why suspected |
|------|--------------|
| `tests/gated-registration-security-verification.test.ts` | Reads evidence files during coverage. |
| `docs/build-packets/PACKET-02-gated-registration.md` | Tracked source of truth for the locked decision evidence. |
| `docs/research/PACKET-02-STAGE-0-CONTEXT/source/*` | Local evidence paths may not exist in CI. |

### Root Cause Hypothesis

> The TASK-028 security evidence test drifted from committed repository artifacts to local planning/research files, so GitHub clean runners fail even though the developer workstation has those files.

### What's Blocked

- PR merge readiness.
- `CI / test-coverage`.

## Resolution

### Contributing Factors

1. **Factor:** Evidence files live in mixed tracked and local planning locations.
   - **How it contributed:** The test passed locally while clean CI lacked the same files.
   - **Why it was not caught earlier:** Local verification was not performed from a clean clone.

### Was the Hypothesis Correct?

> Pending CI confirmation.

### Files Changed

| File | Change | Why |
|------|--------|-----|
| `tests/gated-registration-security-verification.test.ts` | Pending | Restrict evidence reads to tracked files or commit required evidence. |

### Fix Approach

> Use committed packet evidence as the clean-runner source of truth, then rerun coverage locally and in CI.

### Regression Risk

- Low if the remaining evidence still asserts the same locked security decisions.

### Testing Done

- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual verification in target environment
- [ ] Edge cases tested

### Timeline

| Time (UTC) | Event |
|------------|-------|
| 17:00 | User reported CI still breaking |
| 17:05 | Registry searched and new child incident raised |

### Lessons Learned

**What went well:**
- The failure is isolated to a clean-runner evidence dependency.

**What could be better:**
- Security evidence tests should use only tracked files or explicit fixtures.

### Action Items

| Action | Owner | Deadline | Status | Tracking |
|--------|-------|----------|--------|----------|
| Restrict TASK-028 evidence reads to tracked files | Codex | 2026-07-13 | TODO | This incident |
| Rerun `pnpm test:coverage` in CI | Manu / Codex | 2026-07-13 | TODO | PR checks |

## Conclusion

CI coverage is blocked by a clean-runner evidence-file drift, not by the security decision itself. The fix is to make the TASK-028 verification depend only on committed repository artifacts and confirm the GitHub coverage job passes.
