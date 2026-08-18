# Isolated sandbox

All test execution and example analysis for this project runs inside this Docker sandbox. It has
**no network egress** (`network_mode: none`), runs as a non-root user, and drops all Linux
capabilities. This is deliberate: the vulnerable example loaders in `examples/` demonstrate real
file-read and template-injection sinks, and nothing in this repo should ever run against a live
network or with more privilege than it needs, even by accident.

## Usage

From the repo root:

```bash
docker compose -f docker/docker-compose.yml build
docker compose -f docker/docker-compose.yml run --rm sandbox
```

This builds the image and runs the test suite (`pytest`) with no network access. To run the CLI
against a specific file instead of the test suite:

```bash
docker compose -f docker/docker-compose.yml run --rm sandbox capaudit examples/vulnerable_loader_1.py
```

## Why `network_mode: none` instead of an allowlist

The motivating incident for this project involved an allowlist that only checked outbound network
fetches, missing local file reads and local code execution entirely. This sandbox avoids repeating
that pattern by denying network access outright rather than trying to allowlist it — there is no
legitimate reason for a static-analysis run over local files to need a network at all.
