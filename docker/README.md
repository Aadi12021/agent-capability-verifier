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
docker compose -f docker/docker-compose.yml run --rm sandbox capaudit examples/vulnerable_loader_1_path.py
```

## Verification

The isolation properties above were exercised end to end on 2026-09-08 (image built from this
`docker/` directory, `docker compose ... run --rm sandbox <cmd>` for each check):

| Property | Check | Result |
| --- | --- | --- |
| Image builds | `docker compose -f docker/docker-compose.yml build` | editable install of `capaudit` succeeds, image `docker-sandbox` created |
| Test suite runs inside the container | default `CMD` (`pytest -v`) | `47 passed` |
| No network egress | `urllib.request.urlopen("http://93.184.216.34", timeout=5)` (raw IP, no DNS) | `URLError: [Errno 101] Network is unreachable` |
| No DNS resolver | `socket.gethostbyname("example.com")` | `socket.gaierror: [Errno -3] Temporary failure in name resolution` |
| Non-root | `id` | `uid=1000(sandbox) gid=1000(sandbox)` |
| All capabilities dropped | `grep Cap /proc/self/status` | `CapInh/CapPrm/CapEff/CapBnd/CapAmb` all `0000000000000000` |
| No privilege escalation | `grep NoNewPrivs /proc/self/status` | `NoNewPrivs: 1` (seccomp filter also active: `Seccomp: 2`) |

`/workspace` is owned by root (populated by build-time `COPY`) and is not writable by the
`sandbox` user; `pytest` emits one harmless cache-write warning as a result. Re-run the checks
above after any change to the `Dockerfile` or `docker-compose.yml`.

## Why `network_mode: none` instead of an allowlist

The motivating incident for this project involved an allowlist that only checked outbound network
fetches, missing local file reads and local code execution entirely. This sandbox avoids repeating
that pattern by denying network access outright rather than trying to allowlist it — there is no
legitimate reason for a static-analysis run over local files to need a network at all.
