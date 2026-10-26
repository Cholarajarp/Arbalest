# Multi-platform index for python:3.12-slim-bookworm, verified 2026-10-21.
FROM python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70 AS base

FROM base AS builder
ENV UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never
WORKDIR /build
RUN python -m pip install --no-cache-dir uv==0.11.21
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY arbalest_cli.py mcp_server.py ./
COPY engine/ ./engine/
RUN uv sync --locked --no-dev --no-editable --python /usr/local/bin/python

FROM base AS runtime
ENV PATH="/opt/venv/bin:$PATH" \
    HOME=/home/arbalest \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ARBALEST_SKIP_DOTENV=1
RUN groupadd --gid 10001 arbalest \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin arbalest \
    && mkdir /workspace \
    && chown 10001:10001 /workspace
COPY --from=builder /opt/venv /opt/venv
COPY LICENSE /usr/share/licenses/arbalest/LICENSE
USER 10001:10001
WORKDIR /workspace
ENTRYPOINT ["arbalest"]
CMD ["--help"]
