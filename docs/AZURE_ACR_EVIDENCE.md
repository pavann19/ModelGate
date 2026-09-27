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
