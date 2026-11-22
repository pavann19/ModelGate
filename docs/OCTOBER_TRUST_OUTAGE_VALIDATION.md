# Historical signature controls and webhook-outage validation

Three local trials on 26 October 2026; selected evidence published on 22 November 2026. This supplies the matching public record for **420/420 negative-signature controls**, **120/120 positive controls**, **60/60 webhook-outage requests blocked**, and **2.97–6.04 seconds observed recovery**. These are historical local observations, not a fresh benchmark of current main.

## Exact scope and counts

The three trials used API-server dry-runs in a disposable single-node kind Kubernetes 1.31.0 cluster, a real TLS OCI registry and real explicit-key Cosign verification. The webhook had a 1 CPU / 512 MiB limit on a shared local Docker engine. No kubelet execution, model serving, host HA or production SLO was established. The recorded checkout was based on `76c44afaa07f2e069283de5116e4c894ed26cf4f` with uncommitted changes; retained source hashes identify the historical candidate rather than an invented clean commit.

| Named phase | Per trial | Across 3 trials | Outcome |
|---|---:|---:|---|
| Unsigned image | 100 | 300 | Policy denied |
| Old signature after namespace signing-key rotation | 20 | 60 | Policy denied |
| Replacement-key signature in a different namespace retaining its original key | 20 | 60 | Policy denied |
| **Selected negative-signature controls** | **140** | **420** | **420/420 policy denied** |
| Newly trusted signature after key rotation | 20 | 60 | Allowed |
| Original-key signature in the unchanged namespace | 20 | 60 | Allowed |
| **Selected positive controls** | **40** | **120** | **120/120 allowed** |
| Signature after restoring the original key | 20 | 60 | Allowed; additional control, outside the selected 120 |
| Injected webhook outage | 20 | 60 | Webhook unavailable; API-server fail-closed rejection |
| Post-recovery requests | 20 | 60 | Allowed; separate from the selected 120 |

**420 is a repeated-request count across three negative-signature scenarios, not 420 distinct attacks or arbitrary invalid-request categories.** The 60 outage requests were rejected through admission transport failure, not signature-policy denial. The outage was injected by scaling the webhook to zero and waiting for its Pods to disappear, then restoring replicas. This count does not establish behavior during every registry, API, DNS, telemetry or other dependency outage.

## Recovery measurements from these exact trials

Recovery elapsed time starts immediately before restoring the original replica count and ends after rollout readiness and the first successful API-server dry-run. It includes scale-up/rollout/probe time; it is not registry recovery, RTO, monthly availability or a guaranteed bound.

| Trial | Observed recovery seconds | Outage requests blocked | Post-recovery allowed |
|---|---:|---:|---:|
| 1 | 5.944633 | 20/20 | 20/20 |
| 2 | 2.968314 | 20/20 | 20/20 |
| 3 | 6.043802 | 20/20 | 20/20 |

Observed range: **2.968314–6.043802 s**, or **2.97–6.04 s** rounded to two decimals. Median: **5.944633 s**. With only three trials, nearest-rank p95 equals the maximum, **6.043802 s**; it is not a robust production tail estimate. All trials recorded successful fixture restoration with no restoration errors.

The [earlier platform case study](CASE_STUDY.md) reports **6.05–9.21 s** from a different three-run dataset based on `5e0d20a`. Those historical values remain unchanged. Do not pair that dataset with the 420/120 counts or replace one run's numbers with another's. The [matched latency comparison](OCTOBER_LATENCY_COMPARISON.md) is a separate 800-request experiment; its 85.7% gain is not an outage improvement.

## Complete selected dataset and limitations

[Sanitized trials](evidence/october-trust-outage-20261026/trials.json) preserve **all 2,019 measured samples** from these three trials, including load, overload, signature controls, recovery probes and outage phases. Total classified outcomes: **1,167 allowed, 348 saturated, 444 policy-denied and 60 webhook-unavailable**. The selected 420 negative controls exclude 24 policy denials from the bounded-saturation phases; the selected 120 positives exclude load, restoration and recovery controls. No failures are converted into successful controls.

Five checked warmups preceded each of the four signed load phases and the unsigned phase: **75 recorded warmups** across the trials, excluded from measured counts/quantiles. Failure/control phases had no warmup. Every recorded recovery probe is retained; in this particular dataset the first probe succeeded in each trial. Phase and per-outcome p50/p95/p99, timing samples, aggregate counts, source hashes, resource settings and full-precision recovery observations remain available.

This export selects the security section from a preserved combined local record and includes its original file hash. It omits local paths, cluster/container names, namespace/registry addresses, image aliases, node identities and command/log text. Bulk logs, synthetic key material and fixture state remain private. Numerical samples and outcomes are unchanged. Saved values/hashes enable recomputation, not independent proof that an experiment ran or full reconstruction of the historical environment. No live trial or long soak was restarted for publication.

Recompute retained observations without accessing a cluster:

```sh
python3 -B hack/check-october-trust-outage.py
```

The checker validates all sample/outcome counts, phase/per-outcome quantiles and aggregate counts, the named 420/120/60 controls, recorded restoration status and recovery observations. The combined record hashes candidate handler sources separately from each trial's evaluator/orchestration inputs. It does not compare historical source hashes to current main or certify historical runtime identity from hashes alone. Current CI running this script verifies saved arithmetic, not re-execution of the historical workload. A new live run needs isolated fixture infrastructure and separately identified source/configuration.

Current implementation, CI and later measurements have their own identities. General production readiness, provenance/attestation support, host resilience and original endurance gates remain separate and incomplete. Publishing evidence does not expand the actual test coverage implied by a resume's shorthand.
