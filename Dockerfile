FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /traefik-directory .

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /traefik-directory /traefik-directory
EXPOSE 8081
ENTRYPOINT ["/traefik-directory"]
