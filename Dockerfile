FROM golang:1.27.1-bookworm@sha256:8d48e12ec56735e9358640898b9d9b9fcca110612ed8a5567438c0a1baa24e66 AS build
ENV GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/webhook ./cmd/webhook

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
# CosignVerifier (internal/webhook/verifier.go) shells out to the real
# cosign CLI -- it must be present in this image, not just documented as a
# requirement. Copied from the official cosign image rather than fetched
# with curl, since distroless has no shell/package manager to fetch with.
COPY --from=ghcr.io/sigstore/cosign/cosign:v2.4.1@sha256:b03690aa52bfe94054187142fba24dc54137650682810633901767d8a3e15b31 /ko-app/cosign /usr/local/bin/cosign
COPY --from=build /out/webhook /webhook
ENTRYPOINT ["/webhook"]
