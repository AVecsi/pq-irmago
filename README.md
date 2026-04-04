# pq-irmago &nbsp; [![GoDoc](https://godoc.org/github.com/AVecsi/pq-irmago?status.svg)](https://godoc.org/github.com/AVecsi/pq-irmago) [![Go Report Card](https://goreportcard.com/badge/github.com/AVecsi/pq-irmago)](https://goreportcard.com/report/github.com/AVecsi/pq-irmago)

> **⚠️ WARNING:** This is an academic proof-of-concept prototype and has not received careful code review. This implementation is **NOT ready for production use**.

`pq-irmago` is an IRMA implementation in Go based on post-quantum primitives. It contains multiple libraries and applications:

* The commandline tool [`irma`](https://irma.app/docs/irma-cli/), which contains an [IRMA server](https://irma.app/docs/irma-server/); subcommands for manipulating [IRMA schemes](https://irma.app/docs/schemes/), generating IRMA issuer public/private keypairs, performing test IRMA sessions on the command line; and more.
* The Go library [`irmaserver`](https://irma.app/docs/irma-server-lib/) providing a HTTP server that handles IRMA session with the [IRMA mobile app](https://github.com/privacybydesign/irma_mobile), and functions for starting and managing IRMA sessions.
* The root package `irma` contains generic IRMA functionality used by all other components below, such as parsing [IRMA schemes](https://irma.app/docs/schemes/), parsing [IRMA metadata attributes](https://irma.app/docs/overview#the-metadata-attribute), and structs representing messages of the IRMA protocol.
* The Go package `irmaclient` is a library that serves as the client in the IRMA protocol; it can receive and disclose IRMA attributes and store and read them from storage. The [IRMA mobile app](https://github.com/privacybydesign/irma_mobile) uses `irmaclient`.

## Documentation

Technical documentation of all components of `pq-irmago`.

## Running (development)

The easiest way to run the `irma` command line tool for development purposes is using Docker.

    docker-compose run irma

For example, to start a simple IRMA session:

    IP=192.168.1.2 # Replace with your local IP address.
    docker-compose run -p 48680:48680 irma session --disclose pbdf.sidn-pbdf.email.email --url "http://$IP:48680"

### Running without Docker

To run without Docker, you first need to build the pq-gabi Rust dependency:

    go mod download
    chmod -R u+w $(go env GOPATH)/pkg/mod/github.com/\!a\!vecsi/pq-gabi@$(go list -m -f '{{.Version}}' github.com/AVecsi/pq-gabi)
    make -C $(go env GOPATH)/pkg/mod/github.com/\!a\!vecsi/pq-gabi@$(go list -m -f '{{.Version}}' github.com/AVecsi/pq-gabi) build

Then move into the `irma` subfolder and run the server:

    cd irma
    go run main.go server

## Running the verification server

The verification server serves a frontend that allows users to verify their IRMA credentials by scanning a QR code with the Yivi app. It is built using `Dockerfile.verify` and run via the `verify` Docker Compose profile.

### Prerequisites

Create a `.env` file in the root of the repository (or export the variables in your shell):

    IP=192.168.1.2  # Replace with your local IP address

### Building and running

Build and start the verification server:

    IP=192.168.1.2 docker-compose --profile verify up irmaserver --build

The server will be available at `http://<IP>:8088`. Open this URL in a browser to see the verification frontend.

To force a full rebuild without using the Docker cache (e.g. after updating dependencies):

    IP=192.168.1.2 docker-compose --profile verify build --no-cache irmaserver
    IP=192.168.1.2 docker-compose --profile verify up irmaserver

### Notes

- The frontend is automatically cloned from the [yivi-frontend-packages](https://github.com/AVecsi/yivi-frontend-packages) repository during the Docker build, so no manual setup is required.
- TLS is disabled by default. This is fine for local development but should not be used in production.
- Authentication of incoming session requests is disabled (`--no-auth`), meaning anyone who can reach the server can use it. Do not expose this server publicly.

## Running the unit tests

> ⚠️ Tests will fail due to outdated test data.

Some of the unit tests connect to locally running external services, namely PostgreSQL, MySQL, Microsoft SQL Server and an SMTP server running at port 1025. These need to be up and running before these tests can be executed. This can be done using `docker-compose`.

### Running without Go

You can also run the tests fully in Docker using the command below. This is useful when you don't want to install the Go compiler locally. By default, all tests are run one-by-one without parallel execution.

    docker-compose run test

You can override the default command by specifying command line options for `go test` manually, for example:

    docker-compose run test ./internal/sessiontest -run TestDisclosureSession

We always enforce the `-p 1` option to be used (as explained [above](#running-the-tests)).

<!-- vim: set ts=4 sw=4: -->
