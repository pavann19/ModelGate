# ModelGate: admission policy under load and failure

## Engineering problem

A platform team needs a deployment-time control for signed, immutable images and namespace
trust without allowing workload-supplied registry references to turn that control into an
unrestricted network deputy. A failed dependency must also have an explicit effect on admission.

ModelGate implements this boundary as a Go Kubernetes validating webhook. Kubernetes supplies
caller authorization and policy storage. The webhook reads namespace policy directly, verifies
the exact digest/repository identity using a controlled registry transport and pinned cosign,
and denies unsafe host access. This is an implemented platform-security control, not a complete
ML governance platform or a managed production service.

## Decisions that matter operationally

- **Fresh policy reads, no positive cache:** every admission reads the current namespace key.
  This costs API/verification work but avoids stale signature approvals after key rotation.
  In-flight admissions still use their request snapshot; already-running Pods are not revoked.
- **Bounded concurrency:** eight admission slots and explicit saturation denial bound active
  verification work. Excess traffic is rejected rather than queued without limit.
- **Connection-level destination trust:** reviewed host/CIDR endpoints and numeric IP dialing
  bind checks to actual sockets. Private TLS registries are supported explicitly; redirects are
  refused. This trades broad registry/CDN compatibility for a small auditable outbound boundary.
- **Fail-closed availability:** a webhook outage blocks protected admission. Replication and
  operator recovery are availability concerns; ignoring the webhook would remove enforcement.
- **Measure the deployed path:** the operational evaluation includes the API server, real policy
  reads, TLS registry traffic and cryptography, with raw samples and failures retained.

## Evidence

The frozen release completed six GitHub Actions jobs on commit `5e0d20a`: unit/race/scanner,
envtest, real cosign, Helm, fuzzing and live kind admission. That run establishes the published
release's checks; it does not certify changes added after that commit.
[Release CI run](https://github.com/pavann19/ModelGate/actions/runs/40179741472).

The additional platform evaluation is documented in [the experiment contract](PLATFORM_EVALUATION.md).
Its results must be read with the exact environment, sample counts and outcome classifications;
transport failures, deliberate denials and successful admissions are different outcomes.

## Measured local results — 2026-10-26

Three complete runs retained **1840 measured requests**, plus 25 checked warmups per run.
All required phase expectations passed. Any unsuccessful recovery probes are retained; no samples or failed cases were removed. Raw latency values,
outcome counts, timestamps and source hashes are in the
[public measurement record](evidence/platform-eval-20261026.json).

Environment: Windows client, Kubernetes 1.31.0 in single-node kind, Docker 29.9.2 with 4 CPUs
and 3.83 GiB memory shared with other local activity. The webhook was limited to **1 CPU / 512 MiB**;
the registry was limited to 0.5 CPU / 256 MiB. The original kind cluster also shared the engine.
These are short closed-loop local trials, not an isolated capacity certification or a production SLO.

| Concurrent workers | Allowed, by run | p95 of allowed requests, observed range | Allowed requests/s, observed range |
| --- | --- | --- | --- |
| 1 | 100/100, 100/100, 100/100 | 101.9–392.1 ms | 3.68–10.82 |
| 4 | 100/100, 100/100, 100/100 | 508.0–1115.9 ms | 5.41–10.02 |
| 8 | 100/100, 100/100, 100/100 | 1284.8–2241.4 ms | 5.90–8.45 |
| 16 | 8/100, 9/100, 8/100 | 972.3–1312.5 ms | 6.67–8.21 |

Each load row comprises 100 requests per run. The 16-worker row includes explicit capacity
rejections; its successful-request quantiles have a smaller sample and must not be confused with
the all-request latency. Increasing workers did not establish a throughput improvement in this
resource-limited environment. The eight-slot bound rejected overload rather than accumulating
unbounded verification work. No positive cache or relaxed signature check was introduced.

Across the three failure experiments:

- Unsigned images: **300/300 denied** by policy, not by an unavailable webhook.
- After changing the namespace signing key: **60/60 old signatures denied**, without restarting
  the webhook; all 60 requests after restoring that key were admitted.
- Intentional webhook outage: **60/60 requests rejected** through fail-closed admission transport.
- All 60 post-recovery requests were admitted. Observed recovery to the first successful dry-run,
  including scale-up and rollout, was **6.05–9.21 seconds**; this is a lab observation, not an SLO.
- Slow-registry saturation: no requests were admitted; each run observed explicit capacity
  rejections and bounded verification timeout denials.

The evaluation client, orchestration and source hashes were identical across all three runs.
One initial recovery probe was rejected while routing converged; its failed result remains in
the raw record. Docker container counts varied from two to four, and background activity was
not controlled, so the latency ranges include host contention rather than an isolated capacity test.
The baseline commit is `5e0d20a`, with the new evaluation files locally uncommitted; the old
release CI result is not claimed for these additions. Historical benchmark samples remain untouched.

## Limits

The experiment uses API-server dry-runs and minimal OCI fixtures. It does not measure kubelet
image pulls, model serving, multi-node scale, managed-cloud operation or runtime revocation.
The optional model-file check inspects webhook-local files, not workload volumes. Metrics remain
unauthenticated and require network restriction. Full Pod Security Standards are a separate
Kubernetes control. No percentage speedup or business-cost reduction is claimed without a
measured comparison.
