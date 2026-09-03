# Toolgate — capability control plane for AI agents.
# Build:  docker build -t toolgate .
# Run:    docker run -p 8484:8484 \
#           -e TOOLGATE_MASTER_KEY=... -e TOOLGATE_ADMIN_KEY=... \
#           -e TOOLGATE_PUBLIC_URL=https://gate.example.com \
#           -e TOOLGATE_HOST=0.0.0.0 \
#           -v toolgate-data:/data -e TOOLGATE_DB=/data/toolgate.db toolgate

FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS build
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev
COPY src ./src
COPY README.md LICENSE NOTICE ./
RUN --mount=type=cache,target=/root/.cache/uv uv sync --frozen --no-dev

FROM python:3.13-slim-bookworm
RUN groupadd -r toolgate && useradd -r -g toolgate toolgate \
    && mkdir /data && chown toolgate:toolgate /data
WORKDIR /app
COPY --from=build --chown=toolgate:toolgate /app /app
ENV PATH="/app/.venv/bin:$PATH" TOOLGATE_DB=/data/toolgate.db
USER toolgate
EXPOSE 8484
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s \
    CMD python -c "import urllib.request,os; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",8484)}/healthz')"
CMD ["toolgate-server"]
