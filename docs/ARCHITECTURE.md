# Architecture

```text
Kubernetes API server (caller authentication + RBAC + admission)
  -> namespace selector (excludes kube-system and installation namespace)
  -> TLS /validate-pods (controller-runtime AdmissionReview decoding)
  -> Handler: eight concurrent slots (saturation denies) + namespace consistency + 12-second context
  -> direct Kubernetes API LIST of namespace ModelGatePolicy
     -> missing / multiple / API failure: reject
     -> explicit exemption with reason: allow
     -> enforcement config: immutable per-request map
  -> host-access checks
  -> exact image identity + operator registry/endpoint policy
     -> controlled Go HTTPS transport: resolve, approve IP, dial numeric IP; no proxy/redirect
     -> digest-verified manifest and cosign signature payload downloads
     -> exact repository/digest claims + offline cosign verify-blob on local files
     -> 10-second total verifier deadline; bounded downloads and retained stderr
  -> optional model annotation: allow-list lookup -> regular local file <= 64 MiB
     -> recognized pickle rejection + JSON-object framing + SHA-256 comparison
  -> AdmissionResponse allow/deny + bounded-label metrics + structured decision log
```

`cmd/webhook` wires the manager and TLS server. There is no HTTP management API,
reconciling controller, policy database, background queue, or positive verification cache.
Policy objects live in Kubernetes; status is unused. Every request reads policy afresh.
No subprocess shell is used: image and key path are separate executable arguments.

Validation cannot change Pod images. Workloads must supply digest references themselves.
Admission uses a snapshot; updating a key/policy does not revoke already-running Pods.
Artifact files are inspected in the webhook, not in the workload container.

Trust boundaries are the API server, operator-owned policy and serving TLS keys, cosign binary,
registry network path, operator destination policy and webhook filesystem. No code establishes provenance/SBOM trust.
The direct reader avoids informer staleness but does not make policy updates atomic with Pod admission.
