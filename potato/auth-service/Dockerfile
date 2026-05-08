# Multi-stage build. Final image is distroless static — ~10MB on aarch64.
FROM golang:1.22-alpine AS build
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum* ./
COPY . .
# Generate go.sum if absent (first build) and pin checksums.
RUN go mod tidy
# Pure Go (CGO_ENABLED=0) so we can land on distroless/static.
# modernc.org/sqlite is a pure-Go SQLite — important on aarch64.
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w" -o /out/auth-svc .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/auth-svc /auth-svc
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/auth-svc"]
