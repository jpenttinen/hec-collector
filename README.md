# Go and Python HEC receivers

Two independent, standard-library-only implementations of Splunk HEC JSON ingestion over HTTP and HTTPS. Both store events locally rather than indexing or forwarding them to Splunk.

| Implementation | Requirements | Documentation |
| --- | --- | --- |
| `go/` | Current patched Go 1.26.8+, Linux/macOS | [Go setup, configuration, and security limits](go/README.md) |
| `python/` | Current patched Python 3.12+, Linux/macOS | [Python setup, configuration, and security limits](python/README.md) |

Each directory contains its own source, tests, and security review. Go's module and local executables are in `go/`; Python does not require the Go implementation.

## Run Go

From the repository root:

```sh
cd go
go build -o bin/hec .
export HEC_TOKEN='replace-with-a-long-random-token'
./bin/hec
```

## Run Python

From the repository root:

```sh
cd python
export HEC_TOKEN='replace-with-a-long-random-token'
python3.14 hec.py
```

Both default to HTTP on `127.0.0.1:8088`. Run them on different ports if using both simultaneously, with separate events directories. Remote traffic requires HTTPS or a restricted TLS proxy; configuring HTTPS does not automatically disable HTTP.

## Test

From the repository root:

```sh
(cd go && go test -race ./... && go vet ./...)
(cd python && python3.14 -m unittest -v test_hec.py)
```

The [Go security workflow](.github/workflows/go-security.yml) runs from `go/` and also checks the public Go vulnerability database.

## Directory migration

Go source, `go.mod`, tests, binaries, and the Go security review moved into `go/`. Python source, tests, bytecode cache, and its security review moved into `python/`. Each implementation now has its own detailed README.

Existing Go executables are now `go/hec` and `go/bin/hec`. Existing `bin/events/` files were preserved under `go/bin/events/`; the previous root `events/` directory moved to `go/events/`. Event paths still resolve against the process working directory, so update launch scripts and service working directories, or set an absolute `-events-dir` to select existing data explicitly. Running Python from `python/` defaults to `python/events/`.
