# Registry destination security

ModelGate requires an operator-owned JSON policy mounted from a Kubernetes Secret. Missing,
malformed or empty policy prevents startup. Namespace signing policies cannot broaden destination
trust. There is no implicit Docker Hub expansion, mutable-tag resolution or environment override.

```json
{
  "registries": [{
    "host": "registry.example:443",
    "endpoints": [{"host": "registry.example:443", "cidrs": ["192.168.10.20/32"]}],
    "caPEM": "<optional private CA PEM>"
  }]
}
```

Replace the example with your registry's real exact authority and reviewed IP ranges. Ports and
IPv6 authorities must be canonical; include IPv6 in brackets. Public and private IPs both require
explicit CIDRs. Loopback, link-local, unspecified, multicast and known metadata addresses are always
rejected, even if a CIDR would include them. Multiple DNS results must all be approved. DNS changes
outside the policy deny requests until an operator reviews and redeploys the policy. Policy is loaded
once at startup; rotate the Secret and restart the Deployment to reload atomically.

## Actual production path

1. Parse explicit `registry/repository@sha256:<64 lowercase hex>` without aliases or tags.
2. Match the registry authority exactly against the operator policy.
3. Create a per-verification HTTPS client with no proxy and no redirect following.
4. The transport's actual DialContext resolves the approved endpoint, checks every returned IP
   against its CIDRs and forbidden-address rules, and dials the checked **numeric IP**. No second
   DNS lookup occurs in the dialer. TLS still checks the original hostname/IP and trusted CA.
5. Fetch the exact image manifest and check its SHA-256; fetch `sha256-<digest>.sig` and its
   content-addressed payload layers, checking descriptor sizes and SHA-256.
6. Reject payloads that do not name the exact requested repository, digest and cosign signature type.
7. Write the payload, signature and policy public key to private temporary files, then run pinned
   cosign 2.4.1 `verify-blob --offline --insecure-ignore-tlog=true` with local file operands.
   Cosign does not resolve image tags or download registry content in this path.

The image reference passed to Kubernetes remains the same immutable reference being authorized.
No alternate online CosignVerifier path exists. The handler's eight slots and ten-second verifier
context bound work. Each manifest is capped at 1 MiB, each payload at 64 KiB, and each manifest at
16 signature layers. Headers, deadlines, nesting and duplicate JSON keys are bounded/rejected.

All redirects are denied, including redirects to otherwise trusted endpoints. Registries whose
blob downloads require redirects/CDNs are unsupported by this release. This is deliberate fail-closed
behavior; adding a hostname alone cannot bypass redirect refusal. No HTTP/insecure-TLS fallback exists.

## Authentication and private registries

Anonymous HTTPS and Bearer challenges are supported. A token realm must be HTTPS and an explicitly
configured endpoint in the same registry rule. Put any reviewed auth endpoint and its IP CIDRs in
`endpoints`. Optional `username` and `password` fields belong in the Secret, not a ConfigMap or Git.
Credentials are sent only to the reviewed token endpoint. Docker credential helpers, workload
imagePullSecrets and inherited proxy/COSIGN_REPOSITORY/DOCKER_CONFIG settings are not consumed.
Serving a private CA is supported with `caPEM`; disabling TLS validation is not supported.

Errors are generic and never return registry bodies, auth challenge text, tokens or cosign stderr.
Namespace policy errors and file/model validation retain their separately documented error surfaces.

## Installation

```sh
kubectl -n modelgate-system create secret generic modelgate-registry-policy \
  --from-file=registry-policy.json=/secure/reviewed-registry-policy.json
```

The raw manifest uses `modelgate-registry-policy`; Helm uses `registryPolicySecret` (same default).
`hack/registry-policy.go` snapshots DNS for an explicitly supplied operator registry during demo
bootstrap only. Review its output. It is never run against workload input and is not the runtime
security check: the runtime transport rechecks and pins its own actual connection.

Threat exclusions: compromised trusted registry/signing key/operator/kernel; DNS resolution itself
uses the platform resolver; no runtime Pod revocation or model-volume binding. No proxy is assumed
safe as the socket boundary. The original proxy design was rejected because loopback proxy bypass
would leave an alternate outbound path. The controlled transport and offline verifier are required.
