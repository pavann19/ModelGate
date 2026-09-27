# Azure ACR Evidence

## Chosen Azure workflow

ModelGate uses Azure Container Registry only for Azure evidence. This is deliberate:

- Azure Container Apps does not exercise Kubernetes admission webhooks.
- A plain Azure VM would only reproduce a weaker local demo unless it also built a Kubernetes cluster.
- The existing GitHub Actions `kind-smoke` job is the behavioral proof: it builds the webhook image, deploys it into a real kind cluster, and asserts signed-image admission plus unsigned/privileged/hostNetwork/hostPath denials.
- ACR adds Azure-backed image publication and digest evidence without claiming managed production operation.

## Required GitHub settings

The manual workflow `.github/workflows/azure-acr.yml` uses Azure OIDC login and needs these repository secrets:

- `AZURE_CLIENT_ID`
- `AZURE_TENANT_ID`
- `AZURE_SUBSCRIPTION_ID`

It also needs one repository variable:

- `AZURE_ACR_NAME`

The Azure identity should have only the permissions needed to push to the selected ACR, such as `AcrPush` scoped to that registry.

## Manual run

Run **Azure ACR Image Evidence** from GitHub Actions. Leave `image_tag` blank to publish the current commit SHA, or pass an immutable tag.

The workflow builds `modelgate-webhook`, pushes it to ACR, and uploads `azure-acr-image-evidence.json` with:

- repository
- commit
- workflow run URL
- ACR name and login server
- pushed image reference
- tag
- digest

## Evidence boundary

A green ACR run proves image build and Azure registry publication for the named commit. It does not prove operation on AKS, Azure Container Apps, or any managed production cluster. Admission behavior remains proven by the normal CI `kind-smoke` artifact.

## Recorded run

The first successful ACR evidence run was completed on 2026-09-27:

- Workflow run: <https://github.com/pavann19/ModelGate/actions/runs/36338037260>
- Commit: `bf22be38d67e225f212be3681fe6ab63f7e23e95`
- Image: `pavancoderacr.azurecr.io/modelgate-webhook:bf22be38d67e225f212be3681fe6ab63f7e23e95`
- Digest: `sha256:542c4a37afd5d65c9b52f6ac7e6aaa29d0ad69d289add40ed8b74184f22c0859`
- Committed evidence: [`bench/results/azure-acr-image-evidence.json`](../bench/results/azure-acr-image-evidence.json)
