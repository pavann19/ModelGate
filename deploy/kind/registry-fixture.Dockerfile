FROM golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go test -c -o /registry-fixture ./test/cosign
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /registry-fixture /registry-fixture
ENV MODELGATE_LIVE_REGISTRY_SERVER=1
ENTRYPOINT ["/registry-fixture", "-test.run=^TestLiveRegistryServer$", "-test.v"]
