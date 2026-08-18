FROM python:3.12-slim

RUN useradd --create-home --uid 1000 sandbox
WORKDIR /workspace

COPY pyproject.toml /workspace/pyproject.toml
COPY src /workspace/src
COPY tests /workspace/tests
COPY examples /workspace/examples

RUN pip install --no-cache-dir -e ".[dev]"

USER sandbox

CMD ["pytest", "-v"]
