# Admission examples

A protected workload needs a digest-pinned image signed by the namespace policy's key:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: model-server
  namespace: default
spec:
  containers:
    - name: server
      image: registry.example/model@sha256:<64-lowercase-hex-digest>
```

Replace the placeholder with a real signed image digest. Unsigned digests are rejected by cosign;
mutable tags fail with `image must use an immutable repository@sha256 digest reference`.
Use `modelgate.dev/model-artifact: /models/model.safetensors` only when that exact local path is
allow-listed by SHA-256 and mounted into the webhook. The built-in deployments do not mount models.
Matching hashes do not override recognized pickle rejection. Missing annotations skip model checks.

Focused regression: `go test ./internal/webhook -run 'TestHandle_RejectsPickleModelArtifact|TestHandleProductionVerifierRejectsMutableTag'`.
These are reproducible response expectations, not captured live-cluster release-candidate evidence.
