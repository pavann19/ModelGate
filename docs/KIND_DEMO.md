# kind integration

Use an isolated disposable cluster: the smoke changes the default namespace policy and registry Secret.
Prerequisites: Docker Linux engine, kind, kubectl, Python 3, bash, openssl and envsubst.
The Docker build obtains the digest-pinned production cosign 2.4.1 executable.

```sh
kind create cluster --name modelgate
CLUSTER=modelgate python3 deploy/kind/private-registry-smoke.py
```

This builds the actual hardened image and a test-only private TLS OCI registry, installs raw manifests
with generated webhook certificates and explicit Pod-IP /32 registry trust, then exercises server-side
Pod dry-runs. Real ECDSA payloads are verified by the production pinned cosign CLI. The positive and
negative cases cover anonymous/authenticated signatures, identity mismatch, tampering, redirects,
forbidden hosts, timeouts, partial/oversized responses, host access and concurrent admission saturation.
JSON results are written to artifacts/private-kind; any failed assertion makes the script fail.
The registry fixtures are minimal OCI manifests. These tests establish admission behavior, not image
pulling, scheduling, container execution, managed-cluster operation or public registry compatibility.
The fixture server exits after 15 minutes. Delete the disposable cluster after inspection.

The original `smoke.sh`, `sign-test-images.sh` and Pod YAML fixtures are retained for historical public
registry experiments. They need an explicitly reviewed REGISTRY_POLICY_FILE. ttl.sh currently redirects
signature requests and is unsupported by the no-redirect contract; that smoke fails closed and is not
the candidate's CI admission proof. No failed public result is counted as a private-registry pass.
