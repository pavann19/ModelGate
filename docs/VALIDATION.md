# Validation Notes

Last updated: October 1, 2026.

## Helm

Status: resolved through CI chart rendering.

The local Windows machine still does not have Helm installed or on `PATH`:

Command:

```powershell
helm version --short
```

Observed blocker:

```text
helm: The term 'helm' is not recognized as a name of a cmdlet, function, script file, or executable program.
```

Resolution: `.github/workflows/ci.yml` now has a `helm-chart` job that installs Helm in GitHub
Actions, runs `helm lint`, renders the chart with a dummy CA bundle, and verifies the negative path:
`helm template` must fail with `tls.caBundle is required` when the CA bundle is omitted.

Evidence boundary: the CI job definition is committed; the next pushed CI run is the durable
execution evidence. Local Helm remains unverified until Helm is installed on this machine.

## kind

Status: passed locally.

The first attempt used the default Windows `bash.exe` and failed before running the smoke test
because WSL has no default distro installed:

```text
Error code: Bash/Service/CreateInstance/GetDefaultDistro/WSL_E_DEFAULT_DISTRO_NOT_FOUND
```

The successful run used MSYS Bash:

```powershell
& 'C:\msys64\usr\bin\bash.exe' deploy/kind/smoke.sh 2>&1 | Tee-Object -FilePath kind-smoke-output.20261001-165153.txt
```

Evidence file:

- local raw log: `kind-smoke-output.20261001-165153.txt`

Key assertions from the run:

```text
SMOKE PASS: good-pod admitted
SMOKE PASS: bad-pod-unsigned denied by the webhook
SMOKE PASS: bad-pod-privileged denied by the webhook
SMOKE PASS: bad-pod-hostnetwork denied by the webhook
SMOKE PASS: bad-pod-hostpath denied by the webhook
SMOKE PASS: kube-system unaffected
SMOKE TEST COMPLETE: all assertions passed
```

## Evidence File Policy

Raw local evidence captures are machine-specific and noisy, so they are not committed:

- `kind-smoke-output*.txt`
- `.evidence-acr-run-*/`

The repository commits concise summaries and durable evidence pointers instead:

- `docs/VALIDATION.md` for the latest local validation summary.
- CI artifacts such as `kind-smoke-output` and `helm-chart-output` for full run logs.
- `bench/results/azure-acr-image-evidence.json` for the selected ACR publication evidence.

