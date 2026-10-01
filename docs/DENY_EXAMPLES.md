# Exact Denial Examples

These examples show the denial surface ModelGate exposes to users. The unsigned-image example is
from the October 1, 2026 local kind smoke run summarized in [VALIDATION.md](VALIDATION.md). The
pickle example is the exact response string constructed by `internal/webhook.Handler` and covered by
`TestHandle_RejectsPickleModelArtifact`.

## Deny Unsigned Image

Fixture:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod-unsigned
spec:
  containers:
    - name: main
      image: ${UNSIGNED_IMAGE}
```

Command:

```bash
envsubst < deploy/kind/fixtures/bad-pod-unsigned.yaml | kubectl apply -f -
```

Observed denial:

```text
Error from server (Forbidden): error when creating "STDIN": admission webhook "validate-pods.modelgate.dev" denied the request: unsigned or invalid image "ttl.sh/modelgate-kind-unsigned-1790853828:1h": image "ttl.sh/modelgate-kind-unsigned-1790853828:1h" failed signature verification: exit status 10: WARNING: Skipping tlog verification is an insecure practice that lacks of transparency and auditability verification for the signature.
Error: no signatures found
main.go:69: error during command execution: no signatures found
SMOKE PASS: bad-pod-unsigned denied by the webhook
```

The key assertion is `no signatures found`, and the smoke script fails if that substring is missing.

## Deny Pickle Model

ModelGate treats the pod annotation value as the model artifact identifier, looks it up in the
namespace `ModelGatePolicy`, fetches the artifact bytes from the webhook container's filesystem,
and rejects the request if the file is a pickle even when the SHA-256 matches the allow-list.

Policy shape:

```yaml
apiVersion: modelgate.dev/v1alpha1
kind: ModelGatePolicy
metadata:
  name: default-policy
  namespace: default
spec:
  cosignPublicKeyPEM: |
    -----BEGIN PUBLIC KEY-----
    <public key that signs the pod image>
    -----END PUBLIC KEY-----
  artifactAllowList:
    - id: model-b
      sha256: <sha256 of the pickle bytes>
```

Pod shape:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pickle-model
  namespace: default
  annotations:
    modelgate.dev/model-artifact: model-b
spec:
  containers:
    - name: main
      image: <cosign-signed-image>
```

Exact denial message:

```text
admission webhook "validate-pods.modelgate.dev" denied the request: model artifact "model-b" failed validation: artifact: pickle-serialized data detected, refusing to admit
```

The regression test for this is:

```bash
go test ./internal/webhook -run TestHandle_RejectsPickleModelArtifact -count=1
```

The test fixture uses a real protocol-4 pickle byte stream and a matching SHA-256, so the denial is
about the serialization format, not a hash mismatch.

