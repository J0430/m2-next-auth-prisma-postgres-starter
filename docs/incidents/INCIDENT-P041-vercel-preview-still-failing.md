---
id: INCIDENT-P041
date: 2026-07-13
severity: SEV-3
status: OPEN
packet: PACKET-02-gated-registration
branch: feat/secure-registration
environment: staging
detected_by: user-report
related_incidents: [INCIDENT-P006, INCIDENT-P010, INCIDENT-P011]
fix_pr: null
---

# INCIDENT-P041 - Vercel Preview Deployment Still Failing

## Step 0 Incident Memory Check

- **Search terms:** `Vercel`, `Deployment failed`, `vercel.json`, `cron`, `Hobby`, `preview`, `feat/secure-registration`
- **Recurrence:** related to `INCIDENT-P006`, `INCIDENT-P010`, and `INCIDENT-P011`, but not confirmed to be the same root cause without current `vercel inspect` logs.
- **Related but distinct:** this incident tracks the current branch's preview deployment still failing after source-side CI repairs.
- **Decision:** raise a new incident because the deployment remains blocked and the current Vercel failure log has not yet been captured.

## Problem

### Symptoms

- GitHub PR status shows `Vercel - Deployment has failed`.
- The branch is not deployed even though some GitHub Actions checks are now passing or queued.
- The exact Vercel failure reason is not yet captured in this incident.

### Impact

- **Users affected:** no production users directly, but preview verification is blocked.
- **Features broken:** Vercel Preview deployment and deploy status gate.
- **Data at risk:** no.
- **Workaround exists:** partial; inspect the failed deployment and fix the source or Vercel project setting reported there.

### Reproduction Steps

1. Push `feat/secure-registration`.
2. Let Vercel create the PR Preview deployment.
3. Observe GitHub report `Vercel - Deployment has failed`.

### Evidence

```text
User screenshot on 2026-07-13:
Vercel — Deployment has failed.
This branch has not been deployed.
```

### Files Suspected

| File | Why suspected |
|------|--------------|
| `vercel.json` | Owns cron and Vercel deployment configuration. |
| `src/lib/env.ts` | Production/preview env validation can fail closed during build. |
| `.github/workflows/release-readiness.yml` | Reads Vercel project identity for release checks. |
| Vercel project settings | External env/build settings may drift from repository expectations. |

### Root Cause Hypothesis

> The current preview failure is either a remaining Vercel project setting/env mismatch or a source configuration issue still visible only in Vercel's build/deploy logs.

### What's Blocked

- Preview deployment.
- PR deploy verification.
- Merge confidence for production release.

## Resolution

### Contributing Factors

1. **Factor:** Vercel deployment state is external to GitHub Actions.
   - **How it contributed:** Local and CI checks can pass while Preview still fails on project settings or Vercel-specific validation.
   - **Why it was not caught earlier:** The current `vercel inspect` failure log has not been copied into the repo.

### Was the Hypothesis Correct?

> Pending Vercel inspect logs.

### Files Changed

| File | Change | Why |
|------|--------|-----|
| `vercel.json` | Pending | Confirm whether source config still blocks deployment. |

### Fix Approach

> Capture the latest Vercel inspect logs, classify whether the failure is source or project configuration, then update source/docs or Vercel settings accordingly.

### Regression Risk

- Medium until preview deployment is verified.

### Testing Done

- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual verification in target environment
- [ ] Edge cases tested

### Timeline

| Time (UTC) | Event |
|------------|-------|
| 17:00 | User reported Vercel still breaking |
| 17:05 | Registry searched and new incident raised |

### Lessons Learned

**What went well:**
- Vercel failure remains visible as a separate deployment gate.

**What could be better:**
- Vercel inspect logs should be attached to the incident before source fixes are attempted.

### Action Items

| Action | Owner | Deadline | Status | Tracking |
|--------|-------|----------|--------|----------|
| Capture latest `vercel inspect --logs` output | Manu / Codex | 2026-07-13 | TODO | This incident |
| Classify source vs Vercel project setting root cause | Codex | 2026-07-13 | TODO | This incident |
| Verify preview deployment reaches Ready | Manu / Codex | 2026-07-13 | TODO | Vercel |

## Conclusion

The Vercel Preview deployment is still failing and needs its current deployment logs captured before further fixes. This incident keeps the deployment gate separate from GitHub coverage and migration-readiness failures.
