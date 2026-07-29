# Crypto backend selector for the IRMA server binary:
#   zkdilithium (default) — Rust native dep, fully-static binary on `scratch`
#   lazer                 — C stack (liblazer + Intel HEXL + GMP + MPFR),
#                           dynamically linked on a slim Debian runtime
# Switch with:  docker build --build-arg BACKEND=lazer ...
#   (or set BACKEND in the compose/.env — see irma_email_issuer docker-compose).
ARG BACKEND=zkdilithium

FROM golang:1 AS build
ARG BACKEND
ENV CGO_ENABLED=1

RUN apt-get update && apt-get install -y gcc musl-dev curl git make

# Backend-specific build toolchain.
RUN set -eux; \
    if [ "$BACKEND" = "lazer" ]; then \
        apt-get install -y --no-install-recommends \
            g++ cmake unzip patch libgmp-dev libmpfr-dev; \
    else \
        curl https://sh.rustup.rs -sSf | sh -s -- -y; \
    fi
ENV PATH="/root/.cargo/bin:${PATH}"

# Build irma CLI tool
COPY . /irmago
WORKDIR /irmago

# Build the selected backend's native dependency inside the module cache, then
# the irma binary. Module cache dirs are read-only, so chmod them first.
RUN set -eux; \
    go mod download; \
    if [ "$BACKEND" = "lazer" ]; then \
        LAZ="$(go list -m -f '{{.Dir}}' github.com/AVecsi/lazer)"; \
        chmod -R u+w "$LAZ"; \
        make -C "$LAZ"; \
        HEXL64="$LAZ/third_party/hexl-development/build/hexl/lib64/libhexl.a"; \
        [ -f "$HEXL64" ] || { mkdir -p "$(dirname "$HEXL64")"; \
            cp "$(find "$LAZ/third_party/hexl-development/build" -name libhexl.a | head -1)" "$HEXL64"; }; \
        go build -tags lazer -o /bin/irma ./irma; \
    else \
        PQG="$(go list -m -f '{{.Version}}' github.com/AVecsi/pq-gabi)"; \
        cd "/go/pkg/mod/github.com/!a!vecsi/pq-gabi@${PQG}"; \
        chmod -R u+w .; \
        make build; \
        cd /irmago; \
        go build -a -ldflags '-extldflags "-static -lm"' -o /bin/irma ./irma; \
    fi

# Create application user (used by the scratch runtime below)
RUN useradd -u 1000 -ms /bin/bash irma

# ── runtime images (one per backend; the final FROM selects one by ARG) ──────

# zkDilithium: fully-static binary -> minimal scratch image (unchanged).
FROM scratch AS runtime-zkdilithium
COPY --from=build /bin/irma /bin/irma
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /etc/group /etc/group
COPY --from=build --chown=irma:irma /home/irma/ /home/irma/
USER irma
RUN ["/bin/irma", "scheme", "download", "--use-schemes-assets-path"]
ENTRYPOINT ["/bin/irma"]

# lazer: the binary dynamically links libgmp/libmpfr/libstdc++, so reuse the
# build stage as the runtime — all those libs are already present and match the
# build's glibc (a separate slim base risks a glibc version mismatch). HEXL and
# Falcon are static inside liblazer.a. (Mirrors Dockerfile.verify's approach.)
FROM build AS runtime-lazer
USER irma
RUN ["/bin/irma", "scheme", "download", "--use-schemes-assets-path"]
ENTRYPOINT ["/bin/irma"]

# Select the runtime image for the chosen backend.
FROM runtime-${BACKEND} AS final
