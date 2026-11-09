# Local lifecycle and recovery runbook

ModelGate admission is deterministic. The analysis worker has a separate
Deployment and no Kubernetes credential or policy-write tool. Never make an
admission decision depend on an LLM, queue, telemetry exporter or worker health.

## Preflight and install

Use a new, labelled disposable cluster and a separate kubeconfig for validation.
Record source/config hashes, runtime image IDs and effective policy first.
Current process-only verification is described in [the security demonstration](security/DEMONSTRATION.md).
The historical local cluster lab remains private retained evidence; no new cluster, shared daemon
or long soak is authorized by this document. A real deployment requires an independently isolated
and explicitly approved target; no paid/cloud operation is implied.

For an operator installation, install the CRD and list-only RBAC, explicitly
review the registry destination policy, provision serving TLS, and supply the
matching CA bundle. Install namespace policies before testing workloads; missing
or ambiguous policy fails closed. Helm requires a CA bundle. Never publish a
private key or registry password as evidence. Keep probe port 8081 internal.

## Health and termination

`/healthz` checks the process independently of remote dependencies. `/readyz`
requires a TLS handshake with the webhook listener and rejects draining state.
The startup probe gives initialization a separate budget. These checks do not
certify registry availability or workload acceptance; continue synthetic signed
and unsigned round trips. Registry failures deny admission without restarting
the process. HTTP probe port is not exposed by the Service.

Two replicas use node-spread preferences, maxUnavailable=0, maxSurge=1,
minReadySeconds=3 and PDB minAvailable=1. SIGTERM cancels readiness and the manager
drains for up to 25 seconds. A bounded 10-second preStop helper first keeps the
listener alive while Kubernetes withdraws terminating endpoints; distroless
uses the same executable's standalone `--prestop-delay` mode, which performs no
configuration loading or API calls. The pod grace period is 40 seconds. Admission has a
12-second handler deadline and bounded concurrency. A PDB covers voluntary
disruptions; two kind nodes on one machine do not establish host resilience.

## Upgrade and rollback

Pin the new image digest and keep the previous image/config/CA/public policy
snapshot. Verify the new image in synthetic controls before rollout. Observe
ready endpoints, admission outcome classes, p50/p95/p99 and recovery time during
rolling replacement. Halt on any unsigned/tampered positive, unexpected policy
change, or budget breach. Do not change failurePolicy to make a rollout pass.

Rollback the image/config to the recorded version and wait for exclusive ready
image identities. Repeat positive and negative controls. If trust material also
changed, restore its explicit compatible CA/key policy; `rollout undo` alone
does not undo Secrets, CRDs or policies. Record both the failed and recovery run.

## Certificate and signing-key rotation

For leaf rotation under the same CA, update the TLS Secret, restart the
Deployment to bound projected-Secret propagation time, wait for rollout and
verify admission. For CA rotation, first distribute an overlapping old+new CA
bundle, update the serving Secret, roll all replicas, verify the new certificates,
then remove the old CA. Retain old trust only for the declared transition.
Never install an empty bundle or an Ignore failure policy.

Rotate namespace signing keys independently of serving TLS. Test old-key denial,
new-key acceptance and unchanged-namespace isolation; restore the fixture policy
after destructive lab tests. Runtime agent output cannot authorize key rotation.

## Backup and restore

Retain operator-owned configuration/public trust and a separately secured copy
of private TLS material according to the hosting secret-management policy.
The worker runbook describes its isolated SQLite backup/restore. Restore into a
new fixture location first, run integrity and idempotency controls, then compare
pre/post records. A process restart time is neither RTO nor RPO; publish those
only after a measured full restore exercise on the intended topology.

## Cleanup and deployment review

Stop only fixture processes and delete only the cluster name and kubeconfig
recorded by the lab. Keep evidence and failed runs. Never delete a default-context
cluster or shared volume. A deployment review must separately approve hosting,
identity, network policy, secret rotation, backup retention, image provenance,
rollback and monitoring ownership. Local tests do not establish production
availability or monthly uptime.
