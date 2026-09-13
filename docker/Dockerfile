FROM python:3.12-slim

RUN useradd --create-home --uid 1000 sandbox
WORKDIR /workspace

COPY pyproject.toml /workspace/pyproject.toml
COPY src /workspace/src
COPY tests /workspace/tests
COPY examples /workspace/examples

RUN pip install --no-cache-dir -e ".[dev]"

# /workspace is root-owned (populated by the COPYs above), so the non-root
# sandbox user below can't write a cache there. Point ruff/mypy at a
# writable location instead of letting them fail on a permission error.
ENV RUFF_CACHE_DIR=/tmp/ruff-cache
ENV MYPY_CACHE_DIR=/tmp/mypy-cache
ENV COVERAGE_FILE=/tmp/.coverage

USER sandbox

CMD ["pytest", "-v"]
