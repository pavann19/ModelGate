FROM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go test -c -o /registry-fixture ./test/cosign
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /registry-fixture /registry-fixture
ENV MODELGATE_LIVE_REGISTRY_SERVER=1
ENTRYPOINT ["/registry-fixture", "-test.run=^TestLiveRegistryServer$", "-test.v"]
