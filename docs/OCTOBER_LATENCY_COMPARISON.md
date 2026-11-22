# Historical matched admission latency comparison

Measured locally on 26 October 2026; selected evidence published on 22 November 2026. This documents the exact **4.203 s → 600.8 ms (85.7%)** result, not a new measurement or a benchmark of current main.

The optimization eliminated repeated verification of an identical image within each admission request. A later request still resolved policy and performed verification; no cross-request signature approval cache was used.

## Matched experiment

Disposable single-node kind Kubernetes 1.31.0; Windows client; real TLS OCI registry/signature verification; API-server admission dry-runs, not kubelet execution. Same registry, signed workload-image digest, webhook resources and request configurations across baseline/candidate. The webhook limit was 1 CPU / 512 MiB on a shared Docker engine with 4 CPUs and approximately 3.83 GiB RAM. Another local cluster shared the engine, so this is not isolated production-capacity evidence.

Preloaded baseline and candidate images were tested in **baseline/candidate/candidate/baseline** order. Each block checked exclusive ready-image identity before timing and ran four configurations: 1 or 8 same-image containers, with 1 or 4 concurrent request workers. Each phase recorded 3 checked warmups then 50 measured requests. Total: **800/800 measured requests admitted**, 48 recorded warmups, 100 observations per implementation/configuration. Quantiles use nearest rank; warmups are excluded from measured samples.

| Containers / concurrent workers | p50 before → after ms | p95 before → after ms | p99 before → after ms |
|---|---:|---:|---:|
| 1 / 1 | 102.777 → 104.823 | 135.491 → 130.895 | 162.258 → 146.786 |
| 8 / 1 | 821.223 → 109.439 | 934.597 → 145.998 | 1081.006 → 158.989 |
| 1 / 4 | 497.666 → 490.307 | 700.842 → 610.861 | 794.492 → 699.915 |
| **8 / 4** | 3697.641 → 424.359 | **4203.222 → 600.792** | 4397.285 → 607.241 |

For eight containers sharing one image at four concurrent workers:

```text
100 × (1 − 600.792 / 4203.222) = 85.70639380932057%
```

The resume rounding is therefore **4.203 s → 600.8 ms, 85.7% reduction**. This result requires the qualifier **matched local kind trials with eight same-image containers and four concurrent request workers**. It is not a uniform single-container gain or an independent-image speedup. The one-container/one-worker p50 worsened slightly; all controls are retained above. No statistical-significance, cold-start, production throughput, availability or SLO claim is made.

## Evidence and identity

[Sanitized comparison with every measured sample](evidence/october-latency-20261026/comparison.json) retains phase timestamps, Go versions, all 800 timing/outcome samples, phase quantiles, pooled results, source hashes, resource configuration and recorded running-image identities. The baseline commit was `76c44afaa07f2e069283de5116e4c894ed26cf4f`; the candidate had uncommitted changes, so its recorded source hashes and image digest identify it rather than an invented candidate commit.

- Baseline local image digest: `sha256:4363bca9df0e48ef893bae62f0387c25144f90c70182544c8b869ff4f2361c26`.
- Candidate local image digest: `sha256:21c6dbcf5a069934b656c3482b814b5dc04481edccc75ebd86a04b820772a337`.

These are recorded local image identities, not promises that images are publicly downloadable. The combined original private record's SHA-256 is included for provenance. Export selects only its comparison section and omits cluster/container names, namespace, registry address and image-tag aliases. Numerical samples, order, quantiles, source hashes and content-addressed identities are unchanged. Bulk logs/private fixture state remain preserved locally. Hashes and saved samples support recomputation; they do not independently prove execution or provide a complete historical environment reconstruction.

Recompute without accessing a cluster:

```sh
python3 -B hack/check-october-latency.py
```

The checker verifies sample/outcome counts, ABBA order, recorded exclusive-image checks and image identities, phase/pooled p50/p95/p99, and percentage reductions. It intentionally does not compare historical source hashes to current main. A fresh live reproduction needs the historical implementations, pinned images, synthetic registry and isolated kind resources; this documentation publication did not rerun the experiment. Current CI passing this checker means saved arithmetic was verified, not that the historical workload was rerun.

The [November resource comparison](RESOURCE_IMPROVEMENTS.md) uses a later verifier, concurrency 1 and a different baseline. Its one-container tail regressed. Keep those measurements separate; neither percentage is cumulative, and neither establishes production readiness. Original endurance and other release gates remain unchanged.
