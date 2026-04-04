FROM golang:1 as build

# Set build environment
ENV CGO_ENABLED=1

RUN apt-get update && apt-get install -y gcc musl-dev curl git make

# Install Rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Build irma CLI tool
COPY . /irmago
WORKDIR /irmago

# Build pq-gabi's Rust dependency before go build
RUN go mod download && \
    cd /go/pkg/mod/github.com/\!a\!vecsi/pq-gabi@$(go list -m -f '{{.Version}}' github.com/AVecsi/pq-gabi) && \
    chmod -R u+w . && \
    make build

RUN go build -a -ldflags '-extldflags "-static -lm"' -o "/bin/irma" ./irma

# Create application user
RUN useradd -u 1000 -ms /bin/bash irma

# Start building the final image
FROM scratch

# Copy binary from build stage
COPY --from=build /bin/irma /bin/irma

# Add TLS root certificates
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Ensure the application user and group is set
COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /etc/group /etc/group
COPY --from=build --chown=irma:irma /home/irma/ /home/irma/

# Switch to application user
USER irma

# Include schemes as assets in the Docker image to speed up the start-up time
RUN ["/bin/irma", "scheme", "download", "--use-schemes-assets-path"]

ENTRYPOINT ["/bin/irma"]
