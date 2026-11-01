# Threat model

Protected boundary: users authorized to create/update Pods in a protected namespace, but unable to
edit ModelGatePolicy or cluster enforcement configuration. Cluster administrators, policy writers,
trusted signing-key holders and webhook filesystem writers are trusted and can bypass this control.

| Abuse case | Current behavior / evidence boundary |
| --- | --- |
| Mutable tag changed after verification | Production verifier rejects tag references; digest regression tests |
| Digest switched or wrong-object signature | Exact digest passed to cosign; real signed/unsigned integration must run |
| Registry redirect or DNS rebinding | Numeric IP dial bound to operator CIDRs; redirects denied; adversarial transport and production-verifier tests |
| Wrong policy/cache identity | No positive cache; namespace consistency checked; direct policy reads |
| Malformed signature/unsupported algorithm | Offline cosign rejects invalid signatures/keys; real signed/unsigned/wrong-key/payload matrix |
| Missing provenance | Not enforced; no provenance claim |
| Policy reload/key rotation race | Request snapshot only; no cached positives, no runtime revocation |
| Concurrent requests | Per-call key files and maps; production handler caps concurrent checks at eight and denies saturation |
| Pod image mutation/ephemeral container | UPDATE and ephemeral-subresource rules; envtest adversarial suites |
| Timeout/outage | Fail rejects transport timeout; handler errors deny; Ignore explicitly downgrades enforcement |
| Unauthorized direct caller | No mTLS/userInfo authorization; caller cannot thereby create a Kubernetes Pod |
| Tenant/namespace bypass | Kubernetes RBAC and protected policy ownership required; excluded namespaces bypass |
| Oversized artifact | 64 MiB regular-file limit; regression coverage; aggregate admission pressure still matters |
| Pathological JSON/registry response | Input context/time limits partly bound work; network headers/body sizes and JSON depth are bounded; aggregate load remains deployment dependent |
| Retry amplification | No handler retries; registry fetch has one auth retry; numeric dial attempts only approved returned IPs; API-server retries external |
| Queue saturation | No queue; eight production slots; saturation denies, regression tested |
| Stale approval | No verification cache; already-admitted Pods remain running |
| Error information leakage | Retained verifier stderr bounded, content not redacted |

Admission does not bind a model file to a workload volume or prevent later file changes. Digest-pinned
images close the tag race; they do not close every runtime supply-chain problem.
