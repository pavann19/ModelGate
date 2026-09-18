FROM golang:1.24-bookworm AS build
ENV GOTOOLCHAIN=auto
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/webhook ./cmd/webhook

FROM gcr.io/distroless/static-debian12:nonroot
# CosignVerifier (internal/webhook/verifier.go) shells out to the real
# cosign CLI -- it must be present in this image, not just documented as a
# requirement. Copied from the official cosign image rather than fetched
# with curl, since distroless has no shell/package manager to fetch with.
COPY --from=ghcr.io/sigstore/cosign/cosign:v2.4.1 /ko-app/cosign /usr/local/bin/cosign
COPY --from=build /out/webhook /webhook
ENTRYPOINT ["/webhook"]
