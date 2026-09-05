# ---------------------------------------------------------------------------
# Stage 1 — build
# ---------------------------------------------------------------------------
FROM golang:1.23-alpine AS builder

ARG VERSION=dev

WORKDIR /src

# The project has no external dependencies, so go.mod alone is enough and
# there is no go.sum to copy.
COPY go.mod ./
COPY cmd ./cmd
COPY pkg ./pkg

# CGO off produces a static binary, which runs on any base image.
RUN CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/sslscout ./cmd/sslscout

# ---------------------------------------------------------------------------
# Stage 2 — final image
# ---------------------------------------------------------------------------
FROM alpine:3.20

# ca-certificates: without the root certificates EVERY chain verification
#                  fails with "certificate signed by unknown authority" and
#                  SSLScout would report the whole world as untrusted.
# tzdata:          needed to format timestamps in a local zone (TZ=...).
RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -H -u 10001 sslscout

WORKDIR /app

COPY --from=builder /out/sslscout /usr/local/bin/sslscout
COPY public/index.html /app/public/index.html

# The report is written at run time; the directory has to be writable by the
# non-root user.
RUN chown -R sslscout:sslscout /app/public

USER sslscout

# Port used by -serve mode (see the README: do not expose it to the internet).
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/sslscout"]

# No CMD on purpose. Since WORKDIR is /app, the binary defaults already point
# at /app/domains.txt, /app/config.json and /app/public/report.json — the same
# paths the README tells you to mount. Passing "-config /app/config.json"
# explicitly would be worse: an explicit -config that does not exist is a fatal
# error, so the container would break for anyone who mounts only domains.txt
# and uses environment variables for the secrets. The default config.json, when
# absent, simply falls back to the built-in defaults.
#
# Extra arguments are passed straight to the binary:
#   docker run --rm -v $PWD/domains.txt:/app/domains.txt sslscout -serve :8080
#
# For a checker + nginx pair, see docker-compose.yml in the repository root.
